//! The load-bearing invariant of the whole project: whatever the splitter
//! decides, the peer must rebuild the *exact* original bytes.
//!
//! Every test here is an identity test or a savings test. Nothing asserts on
//! internal representation choices.

use bytes::Bytes;
use muka_split::*;

/// Deterministic PRNG so a failure reproduces from its seed alone.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
    /// Exercise a few different block floors, including floors small enough
    /// that structure is found aggressively.
    fn block_floor(&mut self) -> usize {
        [64usize, 384, 2048][self.below(3) as usize]
    }
}

/// Both ends of the slow link, each with its own store.
struct Pair {
    local: MemStore,
    peer: MemStore,
    opt: Optimistic,
}

impl Pair {
    fn new() -> Self {
        Pair {
            local: MemStore::new(),
            peer: MemStore::new(),
            opt: Optimistic::new(Box::new(Never)),
        }
    }

    /// Split as the local side would, then rebuild as the peer would.
    /// Returns (bytes that would hit the wire, stats).
    fn round_trip(&self, policy: &Policy, body: &[u8]) -> (usize, SplitStats) {
        let ctx = Ctx {
            peer: &self.opt,
            local: &self.local,
            policy,
        };
        match split_body(body, &ctx) {
            Action::Split(out) => {
                assert!(check_identity(body, &out, &self.local), "sender identity check");
                let mut wire = 0usize;
                let mut pushed = Vec::new();
                for b in &out.to_push {
                    self.peer.put(b.clone());
                    wire += wire_cost(b);
                    pushed.push(b.digest);
                }
                wire += program_wire_cost(&out.instrs) as usize;
                // The stats model is what the split/passthrough decision uses, so
                // it has to track the real framing within framing slop, in both
                // directions.
                let modelled = out.stats.wire_bytes() as i64;
                let band = (8 * out.instrs.len() as i64 + 32 * out.to_push.len() as i64).max(64);
                assert!(
                    (modelled - wire as i64).abs() <= band,
                    "wire model {modelled} drifted from framed bytes {wire} (band {band})"
                );

                // The peer rebuilds from its own store only: that is the real
                // protocol requirement.
                let rebuilt = resolve(&self.peer, &out.instrs, policy.max_body_bytes, 32)
                    .expect("peer could not resolve program");
                assert_eq!(&rebuilt[..], body, "peer rebuild is not byte-identical");
                assert_eq!(rebuilt.len(), body.len());
                self.opt.note_pushed(pushed);
                (wire, out.stats)
            }
            Action::Passthrough(skip) => {
                let rebuilt = resolve(&self.peer, &[Instr::Lit(Bytes::from(body.to_vec()))], body.len() + 1, 1)
                    .expect("literal-only program must resolve");
                assert_eq!(&rebuilt[..], body);
                let _ = skip;
                (body.len(), SplitStats { body_len: body.len() as u64, lit_bytes: body.len() as u64, ..Default::default() })
            }
        }
    }
}

/// Cost of handing one block to the peer: digest, length, body.
fn wire_cost(b: &Block) -> usize {
    let mut n = b.digest.as_bytes().len() + 8;
    match &b.body {
        BlockBody::Bytes(x) => n += x.len(),
        BlockBody::Program(p) => n += program_wire_cost(p) as usize,
    }
    n
}

fn chat_body(turns: usize, with_image: bool) -> Vec<u8> {
    let mut msgs: Vec<serde_json::Value> = vec![serde_json::json!({
        "role": "system",
        "content": "You are a large agent system prompt. ".repeat(60),
    })];
    for t in 0..turns {
        let mut content: Vec<serde_json::Value> = vec![serde_json::json!({
            "type": "text",
            "text": format!("user turn {t}: {}", "hello world ".repeat(40)),
        })];
        if with_image && t % 3 == 0 {
            content.push(serde_json::json!({
                "type": "image_url",
                "image_url": { "url": format!("data:image/png;base64,{}", blob(t)) },
            }));
        }
        msgs.push(serde_json::json!({ "role": "user", "content": content }));
        msgs.push(serde_json::json!({
            "role": "assistant",
            "content": serde_json::Value::Null,
            "tool_calls": [{
                "id": format!("call_{t}"),
                "type": "function",
                "function": { "name": "read_file", "arguments": "{\"path\":\"src/main.rs\"}" },
            }],
        }));
        msgs.push(serde_json::json!({
            "role": "tool",
            "tool_call_id": format!("call_{t}"),
            "content": "fn main() { println!(\"ok\"); }\n".repeat(30),
        }));
    }
    let tools: Vec<serde_json::Value> = (0..12)
        .map(|i| {
            serde_json::json!({
                "type": "function",
                "function": {
                    "name": format!("tool_{i}"),
                    "description": "A tool with a long description. ".repeat(20),
                    "parameters": { "type": "object", "properties": {
                        "arg": { "type": "string", "description": "desc ".repeat(10) }
                    }}
                }
            })
        })
        .collect();
    let body = serde_json::json!({
        "model": "gpt-5-agent",
        "messages": msgs,
        "tools": tools,
        "stream": true,
        "temperature": 1,
    });
    serde_json::to_vec(&body).unwrap()
}

fn blob(seed: usize) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(60_000);
    let mut x = (seed as u64)
        .wrapping_mul(7919)
        .wrapping_add(13);
    for _ in 0..60_000 {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s.push(ALPHA[(x >> 33) as usize % 64] as char);
    }
    s
}

#[test]
fn steady_state_turns_cost_kilobytes_not_megabytes() {
    let p = Pair::new();
    let policy = Policy::default();
    let mut last = (0usize, 0usize);
    for turn in 1..=12usize {
        let body = chat_body(turn, true);
        let (wire, stats) = p.round_trip(&policy, &body);
        last = (wire, body.len());
        if std::env::var("MUKA_TRACE").is_ok() {
            eprintln!("turn {turn} body={} wire={wire} {stats:?}", body.len());
        }
        assert!(stats.refs > 0, "turn {turn} found no structure: {stats:?}");
        if turn >= 3 {
            assert!(
                stats.refs_hit > 0 && stats.saved_ratio() > 0.5,
                "turn {turn} should be serving history from cache: {stats:?}"
            );
        }
    }
    let (wire, body) = last;
    assert!(body > 200_000, "expected a large body, got {body}");
    assert!(
        wire < 6_000 && wire * 50 < body,
        "steady state wire {wire} vs body {body}"
    );
}

#[test]
fn a_compacted_history_still_hits_the_untouched_tail() {
    let p = Pair::new();
    let policy = Policy::default();
    p.round_trip(&policy, &chat_body(10, true));

    // Compaction: drop the early messages, insert one summary, keep the rest
    // byte-identical - exactly what an agent does when it runs out of context.
    let body = chat_body(10, true);
    let mut v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let msgs = v["messages"].as_array_mut().unwrap();
    let tail = msgs.split_off(6);
    msgs.clear();
    msgs.push(serde_json::json!({
        "role": "user",
        "content": "Summary of the conversation so far: ".to_string() + &"x".repeat(900),
    }));
    msgs.extend(tail);
    let rewritten = serde_json::to_vec(&v).unwrap();

    let (wire, stats) = p.round_trip(&policy, &rewritten);
    assert!(
        stats.refs_hit >= 4,
        "kept messages must still resolve by content: {stats:?}"
    );
    assert!(wire * 4 < rewritten.len(), "wire {wire} vs body {}", rewritten.len());
}

#[test]
fn a_reused_screenshot_costs_one_reference() {
    let p = Pair::new();
    let policy = Policy::default();
    let b0 = image_body(&blob(1), "caption one");
    p.round_trip(&policy, &b0);

    // Same image, different text around it: the message block misses but the
    // nested media block hits, so the 60 KB payload is not re-sent.
    let b1 = image_body(&blob(1), "caption two");
    let (wire, stats) = p.round_trip(&policy, &b1);
    assert!(stats.refs_hit >= 1, "{stats:?}");
    assert!(wire * 20 < b1.len(), "wire {wire} vs body {}", b1.len());
}

fn image_body(payload: &str, caption: &str) -> Vec<u8> {
    let b = serde_json::json!({
        "model": "m",
        "messages": [{ "role": "user", "content": [
            { "type": "text", "text": caption },
            { "type": "image_url", "image_url": { "url": format!("data:image/jpeg;base64,{payload}") } },
        ]}],
    });
    serde_json::to_vec(&b).unwrap()
}

#[test]
fn peer_restart_repushes_from_the_local_superset() {
    let p = Pair::new();
    let policy = Policy::default();
    let body = chat_body(4, false);
    p.round_trip(&policy, &body);
    let warm = p.round_trip(&policy, &body).0;

    // Peer loses everything (restart). The optimistic view must be dropped too,
    // otherwise we would keep referencing blocks it no longer has.
    p.peer.remove_all();
    p.opt.clear();
    let cold = p.round_trip(&policy, &body).0;
    assert!(cold > warm * 5, "cold {cold} vs warm {warm}");
    // ...and the next request is back to steady state, without any manual sync.
    let again = p.round_trip(&policy, &body).0;
    assert!(again < cold / 5, "second warm-up pass did not recover: {again}");
}

#[test]
fn tiny_bodies_are_not_worth_splitting() {
    let p = Pair::new();
    let policy = Policy::default();
    let body = br#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#;
    let (wire, stats) = p.round_trip(&policy, body);
    assert_eq!(wire, body.len());
    assert_eq!(stats.refs, 0);
}

#[test]
fn non_object_and_garbage_bodies_degrade_safely() {
    let p = Pair::new();
    let policy = Policy::default();
    for body in [
        b"not json at all, but long enough to matter: "
            .to_vec()
            .into_iter()
            .chain(std::iter::repeat(b'x'))
            .take(40 + 20_000)
            .collect::<Vec<u8>>(),
        b"[1,2,3]".to_vec(),
        b"{".to_vec(),
        b"".to_vec(),
        br#"{"messages":"not an array","pad":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.to_vec(),
        br#"{"messages":[[[[[[[[[[[["deep"]]]]]]]]]]]],"pad":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#.to_vec(),
    ] {
        let (wire, _) = p.round_trip(&policy, &body);
        // Identity is asserted inside round_trip; here we only require that a
        // decision was made and that wire bytes are never absurd.
        assert!(wire <= body.len() + 4096, "wire {wire} vs body {}", body.len());
    }
}

/// Random JSON: this is the test that would catch a span bug that could
/// otherwise corrupt a real user's prompt.
#[test]
fn fuzz_identity_over_random_json() {
    let mut valid = 0u32;
    let mut split_docs = 0u32;
    let mut total_refs = 0u64;
    for seed in 0..400u64 {
        let mut r = Rng::new(seed + 1);
        let mut policy = Policy::default();
        policy.min_block_bytes = r.block_floor();
        policy.min_payload_bytes = 1024;
        policy.cdc_bits = 6;
        policy.cdc_min = 512;
        policy.cdc_max = 4096;
        let body = gen_doc(&mut r, &mut valid);
        if body.len() < 4096 {
            continue;
        }
        let p = Pair::new();
        let (wire, stats) = p.round_trip(&policy, &body);
        assert!(
            wire <= body.len() + 4096,
            "seed {seed}: wire {wire} vs body {}",
            body.len()
        );
        if stats.refs > 0 {
            split_docs += 1;
            total_refs += u64::from(stats.refs);
        }
    }
    assert!(valid > 380, "generator produced too much invalid json: {valid}");
    // Most random documents are genuinely not worth splitting - the whole point
    // of the floors and the inflation guard is that they go out verbatim.
    assert!(split_docs > 30, "only {split_docs} documents got split");
    assert!(total_refs > 100, "only {total_refs} references created");
}

fn ws(r: &mut Rng, out: &mut String) {
    if r.chance(35) {
        out.push(' ');
    }
    if r.chance(10) {
        out.push_str("\n\t ");
    }
}

fn gen_string(r: &mut Rng, out: &mut String) {
    out.push('"');
    let n = r.below(40) as usize;
    for _ in 0..n {
        match r.below(12) {
            0 => out.push_str("\\\""),
            1 => out.push_str("\\\\"),
            2 => out.push_str("\\n"),
            3 => out.push_str("\\u00e9"),
            4 => out.push_str("\\ud83d\\ude00"),
            5 => out.push_str("/"),
            6 => out.push_str("é"),
            7 => out.push_str("\\t"),
            _ => out.push((b'a' + r.below(26) as u8) as char),
        }
    }
    out.push('"');
}

fn gen_value(r: &mut Rng, depth: usize, out: &mut String, pad_target: usize) {
    let simple = depth >= 3 || r.chance(35);
    if simple {
        match r.below(7) {
            0 => gen_string(r, out),
            1 => out.push_str(if r.chance(50) { "-0.0" } else { "1e10" }),
            2 => out.push_str("123456789012345678901234567890"),
            3 => out.push_str("true"),
            4 => out.push_str("null"),
            5 => {
                out.push_str("0.0000000001");
            }
            _ => {
                // Padding string so the document clears the min_body gate.
                out.push('"');
                let n = (r.below(pad_target as u64) as usize).min(4000);
                for _ in 0..n {
                    out.push('p');
                }
                out.push('"');
            }
        }
        return;
    }
    if r.chance(50) {
        out.push('{');
        let keys = r.below(4) + 1;
        for i in 0..keys {
            if i > 0 {
                out.push(',');
            }
            ws(r, out);
            gen_string(r, out);
            ws(r, out);
            out.push(':');
            ws(r, out);
            gen_value(r, depth + 1, out, pad_target);
        }
        ws(r, out);
        out.push('}');
    } else {
        out.push('[');
        let n = r.below(5);
        for i in 0..n {
            if i > 0 {
                out.push(',');
            }
            ws(r, out);
            gen_value(r, depth + 1, out, pad_target);
        }
        ws(r, out);
        out.push(']');
    }
}

/// A top-level object that sometimes looks like a chat request, so the
/// structural paths actually get exercised.
fn gen_doc(r: &mut Rng, accepted: &mut u32) -> Vec<u8> {
    for _ in 0..16 {
        let mut s = String::new();
        s.push('{');
        let n = r.below(6) + 2;
        for i in 0..n {
            if i > 0 {
                s.push(',');
            }
            ws(r, &mut s);
            let key = match r.below(8) {
                0 => "\"messages\"".to_string(),
                1 => "\"tools\"".to_string(),
                2 => "\"url\"".to_string(),
                3 => "\"file_data\"".to_string(),
                _ => {
                    let mut k = String::from("\"k");
                    for _ in 0..r.below(6) {
                        k.push((b'a' + r.below(26) as u8) as char);
                    }
                    k.push('"');
                    k
                }
            };
            s.push_str(&key);
            ws(r, &mut s);
            s.push(':');
            ws(r, &mut s);
            if key == "\"messages\"" {
                // an array of message-ish objects
                s.push('[');
                let m = r.below(6) + 1;
                for j in 0..m {
                    if j > 0 {
                        s.push(',');
                    }
                    ws(r, &mut s);
                    s.push_str("{\"role\":\"user\",\"content\":");
                    gen_value(r, 2, &mut s, 900);
                    ws(r, &mut s);
                    s.push('}');
                }
                ws(r, &mut s);
                s.push(']');
            } else {
                gen_value(r, 1, &mut s, 900);
            }
        }
        ws(r, &mut s);
        s.push('}');
        if serde_json::from_str::<serde_json::Value>(&s).is_ok() {
            *accepted += 1;
            return s.into_bytes();
        }
    }
    Vec::new()
}
