//! The structural splitter: turns a request body into a block program.
//!
//! Layer order (see design): `A1` per-element caching of `messages` / `input`,
//! `A3`/`A2` payload lift-out inside blocks, `B` CDC fallback for anything we
//! cannot recognise. Anything questionable degrades to a smaller number of
//! references, never to a wrong reconstruction.

use crate::digest::{digest_of, BlockKind, Digest};
use crate::json::{elements_of_array, members_of_object, scan_document, Span, ValueKind, ValueSpan};
use bytes::Bytes;
use std::collections::HashSet;

use crate::cdc::cdc_candidates;
use crate::policy::{
    Action, Cand, Group, Skip, SplitStats, ARRAY_MEMBER_KEYS, DATA_URI_PREFIX, MAX_PAYLOAD_CANDS,
    MEDIA_KEYS, WHOLE_VALUE_KEYS,
};
use crate::program::{normalize, Block, BlockStore, Instr, Presence, SplitOutput};

/// Everything the splitter needs from the outside world.
pub struct Ctx<'a> {
    /// Which digests the *peer* can already resolve (its bloom filter, plus the
    /// local optimistic view of blocks we pushed but have not been confirmed
    /// for).
    pub peer: &'a dyn Presence,
    /// Local durable store: newly created blocks are written through here so a
    /// later request or a peer restart can re-push them.
    pub local: &'a dyn BlockStore,
    pub policy: &'a crate::policy::Policy,
}

/// Split one request body.
pub fn split_body(body: &[u8], ctx: &Ctx) -> Action {
    let p = ctx.policy;
    if !p.enabled {
        return Action::Passthrough(Skip::Disabled);
    }
    if body.len() < p.min_body_bytes {
        return Action::Passthrough(Skip::TooSmall(body.len() as u64));
    }
    if body.len() > p.max_body_bytes {
        return Action::Passthrough(Skip::TooLarge(body.len() as u64));
    }

    let mut b = Builder::new(body, ctx);
    let doc = scan_document(body).ok();
    let groups = match doc {
        Some(d) => structural_groups(body, d.span, ctx).unwrap_or_default(),
        None => Vec::new(),
    };

    if groups.is_empty() {
        if !p.cdc_fallback {
            return Action::Passthrough(Skip::Unrecognised);
        }
        b.stats.cdc_used = true;
        let floor = p.cdc_min.max(p.min_block_bytes);
        for c in cdc_candidates(body, Span::new(0, body.len()), floor, p.cdc_max, p.cdc_bits) {
            b.reference(&c, &[]);
        }
    } else {
        b.stats.structural = true;
        for g in &groups {
            b.reference(&g.cand, &g.children);
        }
    }

    b.lit(body.len());
    b.finish()
}

/// Candidate spans for one body: top-level structure, with payloads assigned as
/// children of the block that contains them.
fn structural_groups(body: &[u8], doc: Span, ctx: &Ctx) -> Result<Vec<Group>, Skip> {
    let p = ctx.policy;
    let members = members_of_object(body, doc).map_err(|_| Skip::Unrecognised)?;
    let mut cands: Vec<Cand> = Vec::new();
    let mut scratch = Vec::new();

    for m in &members {
        let Ok(key) = std::str::from_utf8(&m.key) else {
            continue;
        };
        let is_history = ARRAY_MEMBER_KEYS.iter().any(|k| *k == key);
        let floor = if is_history {
            p.min_history_block_bytes
        } else {
            p.min_block_bytes
        };
        if is_history && m.value.kind != ValueKind::Array {
            // `messages` present but not an array: nothing per-element to cache.
            continue;
        }
        if is_history {
            let els = elements_of_array(body, m.value.span).map_err(|_| Skip::Unrecognised)?;
            scratch.extend(
                els.iter()
                    .filter(|e| e.span.len() >= floor)
                    .map(|e| Cand::new(e.span, BlockKind::JsonMember, floor)),
            );
        } else if WHOLE_VALUE_KEYS.iter().any(|k| *k == key) && m.value.span.len() >= floor {
            cands.push(Cand::new(m.value.span, BlockKind::JsonMember, floor));
        }
    }
    cands.append(&mut scratch);
    cands.sort_by_key(|c| (c.span.start, c.span.end));

    let mut payloads: Vec<Cand> = Vec::new();
    let root = ValueSpan {
        span: doc,
        kind: ValueKind::Object,
    };
    collect_payloads(body, root, 0, ctx, &mut payloads);

    let mut groups: Vec<Group> = cands
        .iter()
        .map(|c| Group {
            cand: *c,
            children: Vec::new(),
        })
        .collect();

    let mut promoted: Vec<Cand> = Vec::new();
    let mut gi = 0usize;
    for pl in payloads {
        while gi < groups.len() && groups[gi].cand.span.end <= pl.span.start {
            gi += 1;
        }
        let parent_hit = gi < groups.len()
            && groups[gi].cand.span.start <= pl.span.start
            && groups[gi].cand.span.end >= pl.span.end;
        if parent_hit {
            groups[gi].children.push(pl);
        } else {
            promoted.push(pl);
        }
    }

    if promoted.is_empty() {
        return Ok(groups);
    }
    let mut out: Vec<Group> = Vec::with_capacity(groups.len() + promoted.len());
    let mut g = groups.into_iter().peekable();
    let mut pr = promoted.into_iter().peekable();
    loop {
        match (g.peek(), pr.peek()) {
            (Some(x), Some(y)) => {
                if x.cand.span.start <= y.span.start {
                    out.push(g.next().unwrap());
                } else {
                    out.push(Group {
                        cand: pr.next().unwrap(),
                        children: Vec::new(),
                    });
                }
            }
            (Some(_), None) => out.push(g.next().unwrap()),
            (None, Some(_)) => out.push(Group {
                cand: pr.next().unwrap(),
                children: Vec::new(),
            }),
            (None, None) => break,
        }
    }
    Ok(out)
}

/// Walk the JSON tree collecting long string values (base64 payloads and big
/// tool output) that deserve their own block.
fn collect_payloads(body: &[u8], v: ValueSpan, depth: usize, ctx: &Ctx, out: &mut Vec<Cand>) {
    if depth > ctx.policy.max_depth || out.len() >= MAX_PAYLOAD_CANDS {
        return;
    }
    let min = ctx.policy.min_payload_bytes;
    match v.kind {
        ValueKind::String => {
            if v.span.len() >= min && looks_like_payload(body, v.span) {
                let kind = if starts_with_data_uri(body, v.span) {
                    BlockKind::Media
                } else {
                    BlockKind::Text
                };
                out.push(Cand::new(v.span, kind, min));
            }
        }
        ValueKind::Object => {
            let Ok(ms) = members_of_object(body, v.span) else {
                return;
            };
            for m in ms {
                if is_media_key(&m.key) && m.value.kind == ValueKind::String && m.value.span.len() >= min
                {
                    // Media keys get a block even without a `data:` prefix: an
                    // inline base64 blob under `file_data`/`b64_json` is the
                    // single largest thing an agent re-sends every turn.
                    out.push(Cand::new(m.value.span, BlockKind::Media, min));
                    continue;
                }
                collect_payloads(body, m.value, depth + 1, ctx, out);
            }
        }
        ValueKind::Array => {
            let Ok(els) = elements_of_array(body, v.span) else {
                return;
            };
            for e in els {
                collect_payloads(body, e, depth + 1, ctx, out);
            }
        }
        _ => {}
    }
}

fn is_media_key(key: &[u8]) -> bool {
    MEDIA_KEYS.iter().any(|k| k.as_bytes() == key)
}

/// A bare `"data:image/png;base64,..."` style value, or anything long enough
/// that repeating it every turn is the whole problem we are solving.
fn looks_like_payload(body: &[u8], s: Span) -> bool {
    starts_with_data_uri(body, s) || s.len() >= 4 * 1024
}

fn starts_with_data_uri(body: &[u8], s: Span) -> bool {
    let inner = s.slice(body);
    inner.len() > DATA_URI_PREFIX.len() + 2 && inner[0] == b'"' && inner[1..].starts_with(DATA_URI_PREFIX)
}

struct Builder<'a, 'c> {
    body: &'a [u8],
    ctx: &'c Ctx<'c>,
    instrs: Vec<Instr>,
    push: Vec<Block>,
    /// Blocks already queued for push in this request (identical messages).
    queued: HashSet<Digest>,
    pos: usize,
    stats: SplitStats,
    limits: bool,
}

impl<'a, 'c> Builder<'a, 'c> {
    fn new(body: &'a [u8], ctx: &'c Ctx<'c>) -> Self {
        Builder {
            body,
            ctx,
            instrs: Vec::new(),
            push: Vec::new(),
            queued: HashSet::new(),
            pos: 0,
            stats: SplitStats {
                body_len: body.len() as u64,
                ..Default::default()
            },
            limits: false,
        }
    }

    /// Flush the literal run up to `end`.
    fn lit(&mut self, end: usize) {
        let end = end.min(self.body.len());
        if end > self.pos {
            let n = end - self.pos;
            self.instrs
                .push(Instr::Lit(Bytes::copy_from_slice(&self.body[self.pos..end])));
            self.stats.lit_bytes += n as u64;
            self.pos = end;
        }
    }

    /// Enqueue a block for the peer unless an identical one is already queued
    /// (two byte-identical messages in one history cost one push).
    fn queue(&mut self, block: Block) {
        if !self.queued.insert(block.digest) {
            return;
        }
        self.stats.blocks_created += 1;
        self.stats.push_bytes += block.wire_cost();
        self.stats.push_blocks += 1;
        if !self.ctx.local.has(&block.digest) {
            self.ctx.local.put(block.clone());
        }
        self.push.push(block);
    }

    fn reference(&mut self, c: &Cand, inner: &[Cand]) -> bool {
        let p = self.ctx.policy;
        let data = c.span.slice(self.body);
        if data.len() < c.floor || self.pos > c.span.start {
            return false;
        }
        let d = digest_of(c.kind, data);
        self.lit(c.span.start);
        self.stats.refs += 1;
        self.stats.ref_covered += data.len() as u64;
        if self.ctx.peer.has(&d) {
            self.stats.refs_hit += 1;
        } else {
            self.stats.refs_new += 1;
            let block = self.make_block(d, c, inner);
            self.queue(block);
        }
        self.instrs.push(Instr::Ref {
            digest: d,
            len: data.len() as u64,
        });
        self.pos = c.span.end;
        if self.instrs.len() > p.max_instrs {
            self.limits = true;
        }
        true
    }

    fn make_block(&mut self, d: Digest, c: &Cand, inner: &[Cand]) -> Block {
        let data = c.span.slice(self.body);
        if inner.is_empty() {
            return Block::raw(d, c.kind, Bytes::copy_from_slice(data));
        }
        let mut instrs: Vec<Instr> = Vec::new();
        let mut pos = c.span.start;
        for ch in inner {
            if ch.span.start < pos || ch.span.end > c.span.end || ch.span.len() < ch.floor {
                continue;
            }
            let cd = digest_of(ch.kind, ch.span.slice(self.body));
            if pos < ch.span.start {
                instrs.push(Instr::Lit(Bytes::copy_from_slice(
                    &self.body[pos..ch.span.start],
                )));
            }
            instrs.push(Instr::Ref {
                digest: cd,
                len: ch.span.len() as u64,
            });
            // Nested references count like top-level ones: reusing an old
            // screenshot in a new message is a real cache hit.
            self.stats.refs += 1;
            let child = Bytes::copy_from_slice(ch.span.slice(self.body));
            if self.ctx.peer.has(&cd) {
                self.stats.refs_hit += 1;
            } else {
                self.queue(Block::raw(cd, ch.kind, child));
            }
            pos = ch.span.end;
        }
        if pos < c.span.end {
            instrs.push(Instr::Lit(Bytes::copy_from_slice(
                &self.body[pos..c.span.end],
            )));
        }
        let instrs = normalize(instrs);
        if instrs.len() == 1 {
            if let Instr::Lit(b) = &instrs[0] {
                if b.len() == data.len() {
                    return Block::raw(d, c.kind, Bytes::copy_from_slice(data));
                }
            }
        }
        Block::program(d, c.kind, data.len() as u64, instrs)
    }

    fn finish(mut self) -> Action {
        if self.limits {
            return Action::Passthrough(Skip::Limits);
        }
        self.lit(self.body.len());
        if self.stats.refs == 0 {
            return Action::Passthrough(Skip::Unrecognised);
        }
        self.stats.instrs = self.instrs.len() as u32;
        let instrs = normalize(self.instrs);
        self.stats.instr_overhead = crate::program::program_wire_cost(&instrs)
            .saturating_sub(self.stats.lit_bytes);
        if self.stats.inflates() {
            // Aggressive block floors (or a body of thousands of tiny values)
            // can make the split bigger than the body. Never do that.
            return Action::Passthrough(Skip::Limits);
        }
        Action::Split(SplitOutput {
            instrs,
            to_push: self.push,
            stats: self.stats,
        })
    }
}

/// Verify a program reproduces `body` exactly. Used on both ends: the sender
/// before it commits a split, the peer after it rebuilds.
pub fn check_identity(body: &[u8], out: &SplitOutput, store: &dyn BlockStore) -> bool {
    match crate::program::resolve(store, &out.instrs, body.len() + 1, 32) {
        Ok(rebuilt) => rebuilt.as_ref() == body,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemStore;
    use crate::policy::Policy;
    use crate::presence::Never;

    fn ctx<'a>(p: &'a Policy, l: &'a dyn BlockStore, pe: &'a dyn Presence) -> Ctx<'a> {
        Ctx {
            peer: pe,
            local: l,
            policy: p,
        }
    }

    #[test]
    fn small_and_huge_bodies_short_circuit() {
        let pol = Policy::default();
        let st = MemStore::default();
        let a = split_body(b"{\"a\":1}", &ctx(&pol, &st, &Never));
        assert!(matches!(a, Action::Passthrough(Skip::TooSmall(_))));
        let mut pol2 = Policy::default();
        pol2.enabled = false;
        assert!(matches!(
            split_body(&vec![b' '; 9000], &ctx(&pol2, &st, &Never)),
            Action::Passthrough(Skip::Disabled)
        ));
        pol2.enabled = true;
        pol2.max_body_bytes = 100;
        assert!(matches!(
            split_body(&vec![b' '; 9000], &ctx(&pol2, &st, &Never)),
            Action::Passthrough(Skip::TooLarge(_))
        ));
    }

    #[test]
    fn non_json_falls_back_to_cdc() {
        let pol = Policy::default();
        let st = MemStore::default();
        let body = vec![b'k'; 40_000];
        match split_body(&body, &ctx(&pol, &st, &Never)) {
            Action::Split(o) => {
                assert!(o.stats.cdc_used);
                assert!(o.stats.refs >= 1);
                assert!(check_identity(&body, &o, &st));
            }
            other => panic!("expected cdc split, got {other:?}"),
        }
    }
}
