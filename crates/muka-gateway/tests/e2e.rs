//! End-to-end proof over real HTTP: turns through the local end, the link, the
//! peer end and a stand-in upstream.
//!
//! The assertion that matters most is not the byte count - it is that the
//! upstream received *exactly* the bytes the agent sent, every turn. Anything
//! else would make the whole tool unsafe to use.

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use muka_gateway::config::{Config, LocalConfig, RemoteConfig, Role};
use muka_gateway::local::{self, App};
use muka_gateway::remote::{MockUpstream, Peer};
use std::sync::Arc;

/// A chat request with a realistic amount of history: a long system prompt,
/// `turns` exchanges and, when asked, a base64 screenshot every other turn.
/// `with_image` has to stay constant within one conversation, otherwise the
/// "history" being reused is not the same history.
fn body(turns: usize, with_image: bool) -> Vec<u8> {
    let mut msgs: Vec<serde_json::Value> = vec![serde_json::json!({
        "role": "system",
        "content": "You are an agent system prompt. ".repeat(120),
    })];
    for t in 0..turns {
        let mut content: Vec<serde_json::Value> = vec![serde_json::json!({
            "type": "text",
            "text": format!("user turn {t}: {}", "some words from the user ".repeat(30)),
        })];
        if with_image && t % 2 == 0 {
            content.push(serde_json::json!({
                "type": "image_url",
                "image_url": { "url": format!("data:image/png;base64,{}", blob(t)) },
            }));
        }
        msgs.push(serde_json::json!({ "role": "user", "content": content }));
        msgs.push(serde_json::json!({
            "role": "tool",
            "tool_call_id": format!("call_{t}"),
            "content": "fn main() { println!(\"ok\"); }\n".repeat(30),
        }));
    }
    let tools: Vec<serde_json::Value> = (0..8)
        .map(|i| {
            serde_json::json!({
                "type": "function",
                "function": {
                    "name": format!("tool_{i}"),
                    "description": "A tool with a long description. ".repeat(15),
                }
            })
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "model": "gpt-5-agent",
        "messages": msgs,
        "tools": tools,
        "stream": true,
        "temperature": 1,
    }))
    .unwrap()
}

/// A `/v1/responses` body: the newer dialect nests `input` items instead of
/// `messages` and carries tool calls as items of their own. The splitter works
/// on structure, not on those key names, so this has to deduplicate too.
fn responses_body(turns: usize, with_image: bool) -> Vec<u8> {
    let mut input: Vec<serde_json::Value> = vec![serde_json::json!({
        "type": "message",
        "role": "developer",
        "content": [{ "type": "input_text", "text": "You are a coding agent. ".repeat(150) }],
    })];
    for t in 0..turns {
        input.push(serde_json::json!({
            "type": "message", "role": "user",
            "content": [{
                "type": "input_text",
                "text": format!("turn {t}: {}", "instructions from the user ".repeat(24)),
            }],
        }));
        if with_image && t % 2 == 0 {
            input.push(serde_json::json!({
                "type": "message", "role": "user",
                "content": [{
                    "type": "input_image",
                    "image_url": format!("data:image/png;base64,{}", blob(t)),
                }],
            }));
        }
        input.push(serde_json::json!({
            "type": "function_call",
            "call_id": format!("c{t}"),
            "name": "shell",
            "arguments": format!("{{\"cmd\":\"cargo build --turn {t}\"}}"),
        }));
        input.push(serde_json::json!({
            "type": "function_call_output",
            "call_id": format!("c{t}"),
            "output": "Compiling crate v0.1.0\n".repeat(40),
        }));
    }
    serde_json::to_vec(&serde_json::json!({
        "model": "gpt-5-agent",
        "input": input,
        "stream": true,
        "tools": [],
    }))
    .unwrap()
}

/// High-entropy base64, which is the shape real screenshots arrive in.
fn blob(seed: usize) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut x = (seed as u64).wrapping_mul(7919).wrapping_add(13);
    (0..40_000)
        .map(|_| {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ALPHA[(x >> 33) as usize % ALPHA.len()] as char
        })
        .collect()
}

async fn post(addr: std::net::SocketAddr, body: &[u8]) -> (u16, Vec<u8>) {
    post_at(addr, "/v1/chat/completions", body).await
}

async fn post_at(addr: std::net::SocketAddr, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    post_headers(addr, path, body, &[]).await
}

/// The same, with whatever extra headers a real client would send. A proxy may
/// rewrite framing but nothing the upstream counts: the query string and the
/// beta flags both change how a request is served.
async fn post_headers(
    addr: std::net::SocketAddr,
    path: &str,
    body: &[u8],
    extra: &[(&str, &str)],
) -> (u16, Vec<u8>) {
    let client: Client<hyper_util::client::legacy::connect::HttpConnector, muka_gateway::local::Body> =
        Client::builder(TokioExecutor::new()).build_http();
    let mut b = hyper::Request::builder()
        .method("POST")
        .uri(format!("http://{addr}{path}"))
        .header("content-type", "application/json")
        .header("authorization", "Bearer placeholder-not-the-real-key");
    for (k, v) in extra {
        b = b.header(*k, *v);
    }
    let resp = client
        .request(b.body(muka_gateway::local::full(Bytes::from(body.to_vec()))).unwrap())
        .await
        .expect("request through the local end");
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, bytes.to_vec())
}

/// `tls_tag` is the name of a throwaway directory holding the link key material.
async fn harness(token: Option<String>) -> (Arc<App>, Arc<MockUpstream>, std::net::SocketAddr) {
    harness_tls(token, None).await
}

async fn harness_tls(
    token: Option<String>,
    tls_tag: Option<&str>,
) -> (Arc<App>, Arc<MockUpstream>, std::net::SocketAddr) {
    harness_opts(token, tls_tag, true).await
}

async fn harness_opts(
    token: Option<String>,
    tls_tag: Option<&str>,
    compress: bool,
) -> (Arc<App>, Arc<MockUpstream>, std::net::SocketAddr) {
    let mock = MockUpstream::new();
    let (mock_addr, _mh) = mock.clone().bind().await.unwrap();

    let mut peer_cfg = Config::default();
    peer_cfg.role = Role::Remote;
    peer_cfg.pairing_token = token.clone();
    peer_cfg.remote = RemoteConfig {
        listen: "127.0.0.1:0".into(),
        upstream: format!("http://{mock_addr}"),
        api_key: Some("sk-real-key-never-leaves-the-peer".into()),
        ..Default::default()
    };
    let ca_file = tls_tag.map(|tag| {
        peer_cfg.remote.tls = true;
        let dir = std::env::temp_dir().join(format!("muka-tls-{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        peer_cfg.remote.tls_dir = Some(dir.clone());
        dir.join("ca.der")
    });
    let peer = Peer::new(Arc::new(peer_cfg)).unwrap();
    let (peer_addr, _ph) = peer.bind().await.unwrap();

    let local_cfg = Config {
        role: Role::Local,
        pairing_token: token,
        local: LocalConfig {
            listen: "127.0.0.1:0".into(),
            peer: peer_addr.to_string(),
            tls: ca_file.is_some(),
            tls_ca_file: ca_file,
            compress,
            ..Default::default()
        },
        ..Default::default()
    };
    let app = App::new(Arc::new(local_cfg)).unwrap();
    let (local_addr, _lh) = local::bind(app.clone()).await.unwrap();
    // Dropping the join handles detaches the servers: they live for the rest of
    // the test process, which is exactly what a harness wants.
    (app, mock, local_addr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_turn_rebuilds_byte_identically_and_later_turns_are_cheap() {
    let token = Some("0123456789abcdef0123456789".to_string());
    let (app, mock, addr) = harness(token).await;

    let mut prev_body = 0u64;
    let mut prev_wire = 0u64;
    for turn in 1..=6usize {
        let body = body(turn, true);
        let (status, resp) = post(addr, &body).await;
        assert_eq!(status, 200, "turn {turn} through the link");
        let text = String::from_utf8_lossy(&resp).to_string();
        assert!(text.starts_with("data: ") && text.contains("[DONE]"), "relay must be verbatim: {text:?}");

        let seen = mock.last_body().expect("the upstream was called");
        assert_eq!(
            seen.as_ref(),
            &body[..],
            "turn {turn}: the upstream must receive exactly the agent's bytes (sent {}, saw {})",
            body.len(),
            seen.len()
        );

        let snap = app.counters().snapshot();
        let d_body = snap.body_bytes - prev_body;
        let d_wire = snap.wire_bytes - prev_wire;
        prev_body = snap.body_bytes;
        prev_wire = snap.wire_bytes;
        assert_eq!(d_body, body.len() as u64, "body accounting");
        // A turn never re-sends history, so its cost is its own new content.
        // Odd turns from the third on add a fresh screenshot, which legitimately
        // has to cross the link once; even turns add only text.
        let adds_image = (turn - 1) % 2 == 0 && turn >= 3;
        if adds_image {
            assert!(d_wire * 2 < d_body, "turn {turn}: {d_wire} wire vs {d_body} body");
        } else if turn >= 3 {
            assert!(d_wire * 12 < d_body, "turn {turn}: {d_wire} wire vs {d_body} body");
        }
        assert!(d_wire <= d_body + 4096, "turn {turn} inflated the request");
    }
    // The peer's own store size rides back on every response: if that relay
    // ever breaks, the console would quietly show zeros.
    let last = app.turns().recent(1).pop().expect("a logged turn");
    assert!(last.store_blocks > 0, "peer store size never came back: {last:?}");
    let snap = app.counters().snapshot();
    assert!(snap.split_requests >= 3, "{snap:?}");
    assert_eq!(snap.rebuild_failures, 0, "no turn should have needed a whole-body retry");
    assert!(
        snap.wire_bytes * 3 < snap.body_bytes,
        "overall: {} wire vs {} body",
        snap.wire_bytes,
        snap.body_bytes
    );
    // Cumulative savings grow with the conversation: the body is quadratic in
    // turns, the link traffic is linear.
    let turns = 6u64;
    assert!(snap.refs_hit > 15, "history should be served by reference: {:?}", snap);
    let _ = turns;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_real_key_stays_on_the_peer_and_the_link_stays_short() {
    let (app, mock, addr) = harness(Some("a-fairly-long-pairing-token".into())).await;
    let body = body(2, false);
    let (status, _) = post(addr, &body).await;
    assert_eq!(status, 200);
    let seen = mock.last_body().unwrap();
    assert_eq!(seen.as_ref(), &body[..]);
    // Counters prove the history went as references, not as bytes.
    let snap = app.counters().snapshot();
    assert!(snap.refs > snap.refs_hit, "first turn pushes blocks");
    let (status2, _) = post(addr, &body).await;
    assert_eq!(status2, 200);
    let snap2 = app.counters().snapshot();
    assert!(
        snap2.refs_hit > snap.refs_hit,
        "an identical second turn must be served from the peer's cache"
    );
    let d_wire = snap2.wire_bytes - snap.wire_bytes;
    let d_body = snap2.body_bytes - snap.body_bytes;
    assert!(d_wire * 10 < d_body, "second identical turn: {d_wire} vs {d_body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_pairing_token_is_refused_before_anything_is_forwarded() {
    let mock = MockUpstream::new();
    let (mock_addr, _mh) = mock.clone().bind().await.unwrap();
    let mut peer_cfg = Config::default();
    peer_cfg.role = Role::Remote;
    peer_cfg.pairing_token = Some("the-peers-own-token-1234567890".into());
    peer_cfg.remote = RemoteConfig {
        listen: "127.0.0.1:0".into(),
        upstream: format!("http://{mock_addr}"),
        ..Default::default()
    };
    let peer = Peer::new(Arc::new(peer_cfg)).unwrap();
    let (peer_addr, _ph) = peer.bind().await.unwrap();

    let local_cfg = Config {
        role: Role::Local,
        pairing_token: Some("somebody-elses-token-1234567890".into()),
        local: LocalConfig { listen: "127.0.0.1:0".into(), peer: peer_addr.to_string(), ..Default::default() },
        ..Default::default()
    };
    let app = App::new(Arc::new(local_cfg)).unwrap();
    let (addr, _lh) = local::bind(app.clone()).await.unwrap();

    let body = body(1, false);
    let (status, resp) = post(addr, &body).await;
    assert_eq!(status, 502, "an unpaired peer must not serve: {}", String::from_utf8_lossy(&resp));
    assert!(mock.seen.lock().unwrap().is_empty(), "nothing may reach the upstream");
    assert!(app.counters().link_errors.load(std::sync::atomic::Ordering::Relaxed) >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dead_peer_answers_502_rather_than_hanging() {
    let local_cfg = Config {
        role: Role::Local,
        pairing_token: Some("0123456789abcdef0123456789".into()),
        local: LocalConfig { listen: "127.0.0.1:0".into(), peer: "127.0.0.1:1".into(), ..Default::default() },
        ..Default::default()
    };
    let app = App::new(Arc::new(local_cfg)).unwrap();
    let (addr, _lh) = local::bind(app.clone()).await.unwrap();
    let body = body(1, false);
    let (status, resp) = post(addr, &body).await;
    assert_eq!(status, 502);
    assert!(String::from_utf8_lossy(&resp).contains("muka_link"), "{resp:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_same_protocol_runs_over_tls_and_still_rebuilds_exactly() {
    let token = Some("0123456789abcdef0123456789abcdef".to_string());
    let (app, mock, addr) = harness_tls(token, Some("handshake")).await;
    let b1 = body(3, true);
    let (status, resp) = post(addr, &b1).await;
    assert_eq!(status, 200, "the TLS link must carry a real turn");
    assert!(String::from_utf8_lossy(&resp).contains("[DONE]"));
    assert_eq!(mock.last_body().unwrap().as_ref(), &b1[..], "TLS changed nothing about the rebuild");
    // The first turn legitimately carries the screenshots once; what must be
    // tiny is the *next* turn, which is what TLS must not make expensive.
    let before = app.counters().snapshot();
    // Same image policy as turn one, so the shared prefix really is shared:
    // changing `with_image` here would make it a different conversation.
    let b2 = body(4, true);
    let (status2, _) = post(addr, &b2).await;
    assert_eq!(status2, 200);
    let after = app.counters().snapshot();
    assert_eq!(after.rebuild_failures, before.rebuild_failures);
    assert_eq!(after.repairs, before.repairs, "TLS must not need extra repairs");
    let d_wire = after.wire_bytes - before.wire_bytes;
    let b1_len = body(3, true).len() as u64;
    let grew = b2.len() as u64 - b1_len;
    assert!(
        d_wire <= grew + 1_200,
        "over TLS, a follow-up turn should cost about what is new ({} B), got {d_wire} B for a {} B body",
        grew,
        b2.len()
    );
    assert!(
        d_wire * 20 < b2.len() as u64,
        "{d_wire} B on the link for a {} B body",
        b2.len()
    );
    assert_eq!(mock.last_body().unwrap().len(), b2.len(), "and the upstream still got it whole");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_pinned_to_the_wrong_ca_cannot_reach_the_upstream() {
    // Two independent key materials: the laptop has the wrong one. A
    // machine-in-the-middle with its own certificate is exactly this case.
    let (app, mock, addr) = {
        let (a, m, s) = harness_tls(
            Some("0123456789abcdef0123456789abcdef".into()),
            Some("wrong-ca"),
        )
        .await;
        // Swap the pinned CA for one from a different peer.
        let other = std::env::temp_dir().join("muka-tls-impostor");
        let _ = std::fs::remove_dir_all(&other);
        std::fs::create_dir_all(&other).unwrap();
        muka_gateway::tls::serve(&other).unwrap();
        let cfg = Arc::try_unwrap(a.cfg.clone()).ok();
        drop(cfg);
        // Rebuild an App that trusts the impostor CA.
        let mut c = Config::default();
        c.role = Role::Local;
        c.pairing_token = Some("0123456789abcdef0123456789abcdef".into());
        c.local = LocalConfig {
            listen: "127.0.0.1:0".into(),
            peer: s.to_string(),
            tls: true,
            tls_ca_file: Some(other.join("ca.der")),
            ..Default::default()
        };
        let app = App::new(Arc::new(c)).unwrap();
        let (addr, _h) = local::bind(app.clone()).await.unwrap();
        (app, m, addr)
    };
    let (status, resp) = post(addr, &body(1, false)).await;
    assert_eq!(status, 502, "an untrusted peer must fail closed: {}", String::from_utf8_lossy(&resp));
    assert!(String::from_utf8_lossy(&resp).contains("tls handshake"), "{}", String::from_utf8_lossy(&resp));
    assert!(mock.seen.lock().unwrap().is_empty(), "nothing may be forwarded");
    assert!(app.counters().link_errors.load(std::sync::atomic::Ordering::Relaxed) >= 1);
}

/// The claim compression has to keep honouring: it must actually pay, and must
/// not be what the deduplication relies on (both are measured here separately).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zstd_on_the_upload_shrinks_a_first_turn_without_changing_a_byte() {
    let text_only = body(6, false);
    let mut wires = Vec::new();
    for compress in [true, false] {
        let (app, mock, addr) = harness_opts(
            Some("0123456789abcdef0123456789abcdef".into()),
            None,
            compress,
        )
        .await;
        let (status, _) = post(addr, &text_only).await;
        assert_eq!(status, 200);
        assert_eq!(mock.last_body().unwrap().as_ref(), &text_only[..], "compress={compress} must still rebuild exactly");
        wires.push(app.counters().snapshot().wire_bytes);
    }
    let (with_z, without_z) = (wires[0], wires[1]);
    assert!(with_z > 0 && without_z > 0, "{with_z} / {without_z}");
    assert!(
        with_z * 2 < without_z,
        "zstd should more than halve a text first turn: {with_z} vs {without_z}"
    );
    // Dedup, not compression, is what makes turn two small: with compression off
    // the second turn is still two orders of magnitude below the body.
    let (app, _mock, addr) = harness_opts(Some("0123456789abcdef0123456789abcdef".into()), None, false).await;
    post(addr, &text_only).await;
    let before = app.counters().snapshot();
    post(addr, &body(7, false)).await;
    let after = app.counters().snapshot();
    let b7 = body(7, false).len() as u64;
    let delta = after.wire_bytes - before.wire_bytes;
    // Without compression a follow-up turn costs its own new content; the point
    // is that it does not cost the history, which would be ~6x this.
    assert!(delta * 3 < b7, "uncompressed follow-up turn should ride on cached blocks: {delta} of {b7}");
}

/// Several agents, one process, one cache. The second listener must not pay
/// again for blocks the peer already got through the first one - that is the
/// whole reason the store, the counters and the peer view live in a `Hub`
/// rather than inside a profile.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_profiles_on_one_peer_share_what_the_peer_already_has() {
    let token = Some("0123456789abcdef0123456789abcdef".to_string());
    let mock = MockUpstream::new();
    let (mock_addr, _mh) = mock.clone().bind().await.unwrap();

    let peer = Peer::new(Arc::new(Config {
        role: Role::Remote,
        pairing_token: token.clone(),
        remote: RemoteConfig {
            listen: "127.0.0.1:0".into(),
            upstream: format!("http://{mock_addr}"),
            ..Default::default()
        },
        ..Default::default()
    }))
    .unwrap();
    let (peer_addr, _ph) = peer.bind().await.unwrap();

    let hub = muka_gateway::Hub::new(Arc::new(Config {
        role: Role::Local,
        pairing_token: token,
        ..Default::default()
    }))
    .unwrap();
    let profile = |name: &str| LocalConfig {
        name: name.into(),
        listen: "127.0.0.1:0".into(),
        peer: peer_addr.to_string(),
        ..Default::default()
    };
    let a = App::for_profile(&hub, profile("agent-a")).unwrap();
    let b = App::for_profile(&hub, profile("agent-b")).unwrap();
    assert!(std::ptr::eq(&*a.store(), &*b.store()), "one store, two listeners");
    let (addr_a, _ha) = local::bind(a.clone()).await.unwrap();
    let (addr_b, _hb) = local::bind(b.clone()).await.unwrap();

    let big = body(3, true);
    let (status, _) = post(addr_a, &big).await;
    assert_eq!(status, 200);
    assert_eq!(mock.last_body().unwrap().as_ref(), &big[..], "agent A rebuilt exactly");
    let warmed = b.counters().snapshot();

    let (status, _) = post(addr_b, &big).await;
    assert_eq!(status, 200);
    assert_eq!(mock.last_body().unwrap().as_ref(), &big[..], "agent B rebuilt exactly");
    let after = b.counters().snapshot();
    let d_wire = after.wire_bytes - warmed.wire_bytes;
    let d_pushed = after.blocks_pushed - warmed.blocks_pushed;
    assert_eq!(d_pushed, 0, "agent B re-pushed {d_pushed} blocks it should have inherited");
    assert!(d_wire * 20 < big.len() as u64, "agent B put {d_wire} B on the link for a {} B body", big.len());

    let logged = b.turns().recent(4);
    assert_eq!(logged.len(), 2, "{logged:?}");
    assert_eq!(logged[0].profile, "agent-a");
    assert_eq!(logged[1].profile, "agent-b");
}

/// Local + peer + stand-in upstream, keeping the `Peer` handle so a test can
/// look at the peer's cache directly instead of inferring it from traffic.
async fn harness_peer() -> (Arc<App>, Arc<Peer>, Arc<MockUpstream>, std::net::SocketAddr) {
    let mock = MockUpstream::new();
    let (mock_addr, _mh) = mock.clone().bind().await.unwrap();
    let peer = Peer::new(Arc::new(Config {
        role: Role::Remote,
        remote: RemoteConfig {
            listen: "127.0.0.1:0".into(),
            upstream: format!("http://{mock_addr}"),
            ..Default::default()
        },
        ..Default::default()
    }))
    .unwrap();
    let (peer_addr, _ph) = peer.clone().bind().await.unwrap();
    let app = App::new(Arc::new(Config {
        role: Role::Local,
        local: LocalConfig {
            listen: "127.0.0.1:0".into(),
            peer: peer_addr.to_string(),
            ..Default::default()
        },
        ..Default::default()
    }))
    .unwrap();
    let (addr, _lh) = local::bind(app.clone()).await.unwrap();
    (app, peer, mock, addr)
}

/// The console's "clear both caches" is only worth clicking if the peer really
/// forgets: otherwise the next turn resolves from its store, nothing is
/// re-pushed, and the button was a lie about what it did.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clearing_both_caches_makes_the_next_turn_re_push() {
    let (app, peer, mock, addr) = harness_peer().await;

    let same = body(3, false);
    let (status, _) = post(addr, &same).await;
    assert_eq!(status, 200);
    let warmed = app.counters().snapshot();
    assert!(warmed.blocks_pushed > 0, "the first turn has to upload its blocks: {warmed:?}");
    assert!(peer.store.stats().blocks > 0, "and the peer has to keep them");

    // The identical request again: every block resolves on the peer, so the
    // link carries the program only and nothing is uploaded.
    let (status, _) = post(addr, &same).await;
    assert_eq!(status, 200);
    let steady = app.counters().snapshot();
    assert_eq!(
        steady.blocks_pushed, warmed.blocks_pushed,
        "a cached repeat must re-push nothing"
    );
    let cached_wire = steady.wire_bytes - warmed.wire_bytes;

    // The light reset: distrust what we think the peer holds, but leave both
    // stores alone. It has to cost an upload, or it does nothing at all.
    app.reset_cache(false).await;
    let (status, _) = post(addr, &same).await;
    assert_eq!(status, 200);
    let after_light = app.counters().snapshot();
    assert!(
        after_light.blocks_pushed > steady.blocks_pushed,
        "forgetting the peer's holdings must re-push: {:?}",
        steady.blocks_pushed
    );
    assert!(peer.store.stats().blocks > 0, "and the peer must still have them");
    let _ = post(addr, &same).await;
    let steady = app.counters().snapshot();
    assert_eq!(steady.blocks_pushed, after_light.blocks_pushed, "and the turn after must be cached again");

    app.reset_cache(true).await;
    assert_eq!(app.store().stats().blocks, 0, "the local cache is gone right away");
    // The peer clears on its own task. The frame is ordered ahead of any later
    // request on that connection, so this wait is only for the assertion.
    for _ in 0..200 {
        if peer.store.stats().blocks == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(peer.store.stats().blocks, 0, "the peer was never told to forget");

    let (status, _) = post(addr, &same).await;
    assert_eq!(status, 200);
    let after = app.counters().snapshot();
    let re_pushed = after.blocks_pushed - steady.blocks_pushed;
    assert!(
        re_pushed >= warmed.blocks_pushed,
        "the turn after a clear must upload what the very first turn uploaded: {re_pushed} vs {}",
        warmed.blocks_pushed
    );
    assert!(peer.store.stats().blocks > 0, "and the peer must hold them again");
    let post_wire = after.wire_bytes - steady.wire_bytes;
    // Counters start at zero, so the first turn's cost is its own total. The
    // turn after a clear has to pay that again - no more, because it is the
    // same body, and no less, because nothing is cached anywhere.
    let first_wire = warmed.wire_bytes;
    assert!(
        post_wire > cached_wire * 2,
        "clearing both caches has to cost bytes: {cached_wire} B cached vs {post_wire} B after"
    );
    assert!(
        post_wire <= first_wire + 700,
        "a re-push should cost about the original upload ({first_wire} B), got {post_wire} B"
    );
    assert_eq!(after.rebuild_failures, 0, "a cleared cache costs bytes, never a wrong prompt");
    assert_eq!(after.repairs, steady.repairs, "and must not need a repair round either");
    assert_eq!(
        mock.last_body().unwrap().as_ref(),
        &same[..],
        "still byte-for-byte the agent's body"
    );
    let turn = app.turns().recent(1).pop().expect("a logged turn");
    assert!(
        turn.pushed > 0 && turn.refs > turn.refs_hit,
        "the log must show the re-push, not hide it: {turn:?}"
    );
}

/// Both caches can lose a block behind the protocol's back - LRU eviction, a
/// crash, an operator wiping a directory - while the laptop still believes the
/// peer holds the history. The request must then go whole. That fallback is the
/// last safety net, so it has to work even though it is the rarest path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_body_nobody_can_rebuild_still_reaches_the_upstream_whole() {
    let (app, peer, mock, addr) = harness_peer().await;

    let (status, _) = post(addr, &body(3, false)).await;
    assert_eq!(status, 200);
    assert!(app.store().stats().blocks > 0 && peer.store.stats().blocks > 0, "both caches warm");

    // Evict on both sides, leaving the optimistic presence claiming the peer can
    // resolve the history.
    app.store().clear();
    peer.store.clear();

    let grew = body(4, false);
    let (status, _) = post(addr, &grew).await;
    assert_eq!(status, 200, "a lost cache may cost bytes, never a failed turn");
    assert_eq!(
        mock.last_body().unwrap().as_ref(),
        &grew[..],
        "the whole body must arrive byte-for-byte"
    );
    let c = app.counters().snapshot();
    assert!(c.rebuild_failures >= 1, "the fallback has to be counted: {c:?}");
    let t = app.turns().recent(1).pop().expect("a logged turn");
    assert!(!t.split, "the log must say the body went whole: {t:?}");
    assert_eq!(t.skip_reason.as_deref(), Some("rebuild failed"), "{t:?}");

    // Having been told the peer cannot resolve them, the next turn re-pushes.
    let pushed = c.blocks_pushed;
    let next = body(5, false);
    let (status, _) = post(addr, &next).await;
    assert_eq!(status, 200);
    assert!(
        app.counters().snapshot().blocks_pushed > pushed,
        "the next turn must rebuild by pushing, not by falling back again"
    );
    assert_eq!(mock.last_body().unwrap().as_ref(), &next[..]);
    assert_eq!(app.counters().snapshot().rebuild_failures, c.rebuild_failures, "only once");
}

/// Agents are moving to the Responses dialect, whose body nests `input` items
/// rather than `messages`. Nothing here is keyed to those names, so the same
/// savings - and the same byte-exactness - must hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_responses_dialect_deduplicates_without_being_parsed_by_name() {
    let (app, _peer, mock, addr) = harness_peer().await;
    let cold = responses_body(3, true);
    let (status, _) = post_at(addr, "/v1/responses", &cold).await;
    assert_eq!(status, 200);
    assert_eq!(mock.last_body().unwrap().as_ref(), &cold[..], "the new dialect rebuilds exactly");

    let warmed = app.counters().snapshot();
    let grew = responses_body(4, true);
    let (status, _) = post_at(addr, "/v1/responses", &grew).await;
    assert_eq!(status, 200);
    assert_eq!(mock.last_body().unwrap().as_ref(), &grew[..]);
    let after = app.counters().snapshot();
    let d_body = after.body_bytes - warmed.body_bytes;
    let d_wire = after.wire_bytes - warmed.wire_bytes;
    assert_eq!(d_body, grew.len() as u64, "body accounting for a /v1/responses turn");
    assert!(
        d_wire * 12 < d_body,
        "a text-only follow-up turn should ride on cached items: {d_wire} B of {d_body} B"
    );
    assert_eq!(after.rebuild_failures, 0);
    let t = app.turns().recent(1).pop().expect("a logged turn");
    // Not every reference can hit: the turn's own new items are genuinely new,
    // and those are the two blocks it pushes. The history must be the rest.
    assert!(
        t.split && t.refs > 8 && t.refs_hit as f64 > t.refs as f64 * 0.7,
        "the history should go as references, the new items as blocks: {t:?}"
    );
}

/// An Anthropic Messages body: `system` is a top-level block array, images ride
/// in `source.data`, tools carry `input_schema`. The splitter is structural, so
/// this has to deduplicate like the OpenAI shapes - and the peer has to
/// authenticate it the way *that* API expects.
fn anthropic_body(turns: usize, with_image: bool) -> Vec<u8> {
    let mut msgs: Vec<serde_json::Value> = Vec::new();
    for t in 0..turns {
        let mut content = vec![serde_json::json!({
            "type": "text",
            "text": format!("turn {t}: {}", "the user's request, repeated verbatim ".repeat(20)),
        })];
        if with_image && t % 2 == 0 {
            content.push(serde_json::json!({
                "type": "image",
                "source": { "type": "base64", "media_type": "image/png", "data": blob(t) },
            }));
        }
        msgs.push(serde_json::json!({ "role": "user", "content": content }));
        msgs.push(serde_json::json!({
            "role": "assistant",
            "content": [
                { "type": "text", "text": "Looking at that now. ".repeat(20) },
                { "type": "tool_use", "id": format!("toolu_{t}"), "name": "bash",
                  "input": { "command": format!("cargo build --turn {t}") } },
            ],
        }));
        msgs.push(serde_json::json!({
            "role": "user",
            "content": [{
                "type": "tool_result",
                "tool_use_id": format!("toolu_{t}"),
                "content": "Compiling crate v0.1.0\n".repeat(40),
            }],
        }));
    }
    serde_json::to_vec(&serde_json::json!({
        "model": "claude-sonnet-4-5",
        "max_tokens": 4096,
        "system": [{ "type": "text", "text": "You are a coding agent. ".repeat(200) }],
        "messages": msgs,
        "tools": [{
            "name": "bash",
            "description": "Run a shell command. ".repeat(20),
            "input_schema": { "type": "object", "properties": { "command": { "type": "string" } } },
        }],
        "stream": true,
    }))
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_messages_api_deduplicates_and_authenticates_its_own_way() {
    let (app, mock, addr) = harness_opts(Some("0123456789abcdef0123456789abcdef".into()), None, true).await;
    let cold = anthropic_body(3, true);
    // A real client sends beta flags and sometimes a query; both change how the
    // upstream serves the request, so neither may be lost on the way through.
    let (status, _) = post_headers(
        addr,
        "/v1/messages?beta=true",
        &cold,
        &[("anthropic-beta", "context-management-2025-06-27,token-efficient-tools-2025-02-19")],
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(mock.last_body().unwrap().as_ref(), &cold[..], "a Messages body must rebuild byte-exactly");
    assert_eq!(mock.last_path(), "/v1/messages?beta=true", "the query must survive");
    assert_eq!(
        mock.last_header("anthropic-beta").as_deref(),
        Some("context-management-2025-06-27,token-efficient-tools-2025-02-19"),
        "a beta flag the client needed for its context budget must not be dropped"
    );
    // That API authenticates with x-api-key. The placeholder the agent sent in
    // `Authorization` must not travel upstream next to the real credential.
    assert_eq!(
        mock.last_header("x-api-key").as_deref(),
        Some("sk-real-key-never-leaves-the-peer"),
        "the peer must inject the key the way this API expects: {:?}",
        mock.saw_headers.lock().unwrap()
    );
    assert_eq!(mock.last_header("authorization"), None, "no bogus bearer credential upstream");
    assert_eq!(mock.last_header("anthropic-version").as_deref(), Some("2023-06-01"), "a version is required");

    let warmed = app.counters().snapshot();
    let grew = anthropic_body(4, true);
    let (status, _) = post_at(addr, "/v1/messages", &grew).await;
    assert_eq!(status, 200);
    assert_eq!(mock.last_body().unwrap().as_ref(), &grew[..]);
    let after = app.counters().snapshot();
    let d_body = after.body_bytes - warmed.body_bytes;
    let d_wire = after.wire_bytes - warmed.wire_bytes;
    assert_eq!(d_body, grew.len() as u64, "body accounting for a Messages turn");
    assert!(
        d_wire * 8 < d_body,
        "a follow-up Messages turn should ride on the cached history: {d_wire} B of {d_body} B"
    );
    assert_eq!(after.rebuild_failures, 0);
    let t = app.turns().recent(1).pop().expect("a logged turn");
    assert!(t.split && t.refs_hit > 0, "the history went as references: {t:?}");
}
