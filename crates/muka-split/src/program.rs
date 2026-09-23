//! The block-program model: a request body is encoded as a flat instruction
//! list of literal byte runs and references to content-addressed blocks.
//!
//! Blocks form a DAG (a message block may reference a media block nested
//! inside it), which is what lets a *new* message that reuses an *old*
//! screenshot cost 16 bytes instead of 1.3 MB.
//!
//! Reconstruction is pure concatenation, so it is byte-exact by construction;
//! `resolve` additionally re-checks the declared body digest and length.

use crate::digest::{BlockKind, Digest};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Instr {
    /// Inline bytes.
    Lit(Bytes),
    /// Pull `len` bytes of block `digest` from the store.
    Ref { digest: Digest, len: u64 },
}

impl Instr {
    pub const fn out_len(&self) -> u64 {
        match self {
            Instr::Lit(b) => b.len() as u64,
            Instr::Ref { len, .. } => *len,
        }
    }
}

/// A stored block: either opaque bytes, or a nested program.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockBody {
    Bytes(Bytes),
    Program(Vec<Instr>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub digest: Digest,
    pub kind: BlockKind,
    /// Exact length of the byte range this block stands for.
    pub len: u64,
    pub body: BlockBody,
}

impl Block {
    pub fn raw(digest: Digest, kind: BlockKind, data: Bytes) -> Self {
        let len = data.len() as u64;
        Block {
            digest,
            kind,
            len,
            body: BlockBody::Bytes(data),
        }
    }

    pub fn program(digest: Digest, kind: BlockKind, len: u64, instrs: Vec<Instr>) -> Self {
        Block {
            digest,
            kind,
            len,
            body: BlockBody::Program(instrs),
        }
    }

    /// Bytes this block costs to transmit *now* if the peer lacks it: its
    /// literal content plus the framing cost of its program.
    pub fn wire_cost(&self) -> u64 {
        match &self.body {
            BlockBody::Bytes(b) => b.len() as u64,
            BlockBody::Program(p) => program_wire_cost(p),
        }
    }
}

/// Serialized size of an instruction list under the wire framing
/// (tag + payload), used for split-vs-passthrough decisions and metrics.
pub fn program_wire_cost(instrs: &[Instr]) -> u64 {
    use crate::policy::{LIT_HDR, REF_WIRE};
    instrs
        .iter()
        .map(|i| match i {
            Instr::Lit(b) => b.len() as u64 + LIT_HDR,
            Instr::Ref { .. } => REF_WIRE,
        })
        .sum()
}

/// Something that can hand back blocks by digest (the local store).
pub trait BlockSource: Send + Sync {
    fn get(&self, digest: &Digest) -> Option<Block>;
    fn has(&self, digest: &Digest) -> bool {
        self.get(digest).is_some()
    }
}

/// A store the splitter writes newly created blocks through.
pub trait BlockStore: BlockSource {
    /// Returns false when the store refused the block (full / disabled), which
    /// only costs a future cache hit, never correctness.
    fn put(&self, block: Block) -> bool;
}

/// The result of splitting one request body.
#[derive(Clone, Debug)]
pub struct SplitOutput {
    /// Program the peer uses to rebuild the body.
    pub instrs: Vec<Instr>,
    /// Blocks the peer must be given before it can resolve `instrs`.
    pub to_push: Vec<Block>,
    pub stats: crate::policy::SplitStats,
}

/// Something that reports whether the *peer* can resolve a digest (its bloom
/// filter, refreshed from every downstream response).
pub trait Presence: Send + Sync {
    fn has(&self, digest: &Digest) -> bool;
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResolveError {
    #[error("block {0} missing on peer")]
    Missing(Digest),
    #[error("block nesting deeper than {0}")]
    TooDeep(usize),
    #[error("reconstruction would exceed {0} bytes")]
    TooLarge(usize),
    #[error("stored block body is inconsistent")]
    Corrupt,
}

/// Resolve an instruction list, pulling blocks through `store`.
///
/// Pure concatenation: no JSON is re-parsed or re-serialised here, which is
/// what makes the rebuilt body byte-identical to the sender's original.
pub fn resolve(
    store: &dyn BlockSource,
    instrs: &[Instr],
    max_out: usize,
    max_depth: usize,
) -> Result<Bytes, ResolveError> {
    let mut out: Vec<u8> = Vec::new();
    // Depth-first expansion of nested programs, kept iterative so a hostile or
    // accidental reference cycle cannot blow the stack.
    let mut stack: Vec<(Instr, usize)> =
        instrs.iter().rev().map(|i| (i.clone(), 1usize)).collect();
    while let Some((instr, depth)) = stack.pop() {
        match instr {
            Instr::Lit(b) => {
                if out.len() + b.len() > max_out {
                    return Err(ResolveError::TooLarge(max_out));
                }
                out.extend_from_slice(&b);
            }
            Instr::Ref { digest, len } => {
                if depth > max_depth {
                    return Err(ResolveError::TooDeep(max_depth));
                }
                if out.len() as u64 + len > max_out as u64 {
                    return Err(ResolveError::TooLarge(max_out));
                }
                let block = store.get(&digest).ok_or(ResolveError::Missing(digest))?;
                if block.len != len {
                    return Err(ResolveError::Corrupt);
                }
                match block.body {
                    BlockBody::Bytes(b) => {
                        if b.len() as u64 != len {
                            return Err(ResolveError::Corrupt);
                        }
                        out.extend_from_slice(&b);
                    }
                    BlockBody::Program(p) => {
                        if p.is_empty() {
                            return Err(ResolveError::Corrupt);
                        }
                        for i in p.iter().rev() {
                            stack.push((i.clone(), depth + 1));
                        }
                    }
                }
            }
        }
    }
    Ok(Bytes::from(out))
}

/// Digests the peer must be given before it can resolve `instrs`.
///
/// A block we already have on the peer is never walked into, so its children
/// do not have to be present: the peer resolves the whole subtree locally.
pub fn missing_blocks(
    store: &dyn BlockSource,
    peer: &dyn Presence,
    instrs: &[Instr],
    limit: usize,
) -> Vec<Digest> {
    let mut out = Vec::new();
    let mut seen: Vec<Digest> = Vec::new();
    let mut stack: Vec<Digest> = instrs
        .iter()
        .filter_map(|i| match i {
            Instr::Ref { digest, .. } => Some(*digest),
            Instr::Lit(_) => None,
        })
        .collect();
    while let Some(d) = stack.pop() {
        if seen.contains(&d) || peer.has(&d) {
            continue;
        }
        seen.push(d);
        if out.len() >= limit {
            break;
        }
        out.push(d);
        if let Some(b) = store.get(&d) {
            if let BlockBody::Program(p) = &b.body {
                for i in p.iter() {
                    if let Instr::Ref { digest, .. } = i {
                        stack.push(*digest);
                    }
                }
            }
        }
    }
    out
}

/// Merge adjacent literals so the wire form stays small.
pub fn normalize(mut instrs: Vec<Instr>) -> Vec<Instr> {
    let mut out: Vec<Instr> = Vec::with_capacity(instrs.len());
    for i in instrs.drain(..) {
        match (out.last_mut(), i) {
            (Some(Instr::Lit(prev)), Instr::Lit(next)) => {
                let mut merged = Vec::with_capacity(prev.len() + next.len());
                merged.extend_from_slice(prev);
                merged.extend_from_slice(&next);
                *prev = Bytes::from(merged);
            }
            (_, Instr::Lit(b)) => {
                if !b.is_empty() {
                    out.push(Instr::Lit(b));
                }
            }
            (_, other) => out.push(other),
        }
    }
    out
}

pub fn total_len(instrs: &[Instr]) -> u64 {
    instrs.iter().map(|i| i.out_len()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::digest_of;
    use std::collections::HashMap;
    use std::sync::RwLock;

    #[derive(Default)]
    struct MemStore(RwLock<HashMap<Digest, Block>>);
    impl MemStore {
        fn put(&self, b: Block) {
            self.0.write().unwrap().insert(b.digest, b);
        }
    }
    impl BlockSource for MemStore {
        fn get(&self, d: &Digest) -> Option<Block> {
            self.0.read().unwrap().get(d).cloned()
        }
    }

    struct Always(bool);
    impl Presence for Always {
        fn has(&self, _d: &Digest) -> bool {
            self.0
        }
    }

    const MEDIA: &[u8] = b"BASE64BASE64";
    const MSG_HEAD: &[u8] = br#"{"u":"data:,"#;
    const MSG_TAIL: &[u8] = br#""}"#;
    const ROOT_HEAD: &[u8] = b"{\"m\":[";
    const ROOT_TAIL: &[u8] = b"]}";

    fn msg_bytes() -> Vec<u8> {
        [MSG_HEAD, MEDIA, MSG_TAIL].concat()
    }

    fn root_bytes() -> Vec<u8> {
        [ROOT_HEAD, &msg_bytes(), ROOT_TAIL].concat()
    }

    fn seed() -> (MemStore, Digest, Digest) {
        let store = MemStore::default();
        let media = digest_of(BlockKind::Media, MEDIA);
        store.put(Block::raw(media, BlockKind::Media, Bytes::from_static(MEDIA)));
        let msg = digest_of(BlockKind::JsonMember, &msg_bytes());
        store.put(Block::program(
            msg,
            BlockKind::JsonMember,
            msg_bytes().len() as u64,
            vec![
                Instr::Lit(Bytes::from_static(MSG_HEAD)),
                Instr::Ref {
                    digest: media,
                    len: MEDIA.len() as u64,
                },
                Instr::Lit(Bytes::from_static(MSG_TAIL)),
            ],
        ));
        (store, msg, media)
    }

    fn ref_of(d: Digest, len: usize) -> Instr {
        Instr::Ref {
            digest: d,
            len: len as u64,
        }
    }

    #[test]
    fn nested_programs_resolve_to_exact_bytes() {
        let (store, msg, _media) = seed();
        let root = vec![
            Instr::Lit(Bytes::from_static(ROOT_HEAD)),
            ref_of(msg, msg_bytes().len()),
            Instr::Lit(Bytes::from_static(ROOT_TAIL)),
        ];
        assert_eq!(resolve(&store, &root, 1 << 20, 8).unwrap().as_ref(), root_bytes());
    }

    #[test]
    fn resolve_preserves_instr_order() {
        let store = MemStore::default();
        let root = vec![
            Instr::Lit(Bytes::from_static(b"1")),
            Instr::Lit(Bytes::from_static(b"2")),
            Instr::Lit(Bytes::from_static(b"3")),
            Instr::Lit(Bytes::from_static(b"4")),
            Instr::Lit(Bytes::from_static(b"5")),
        ];
        assert_eq!(resolve(&store, &root, 1 << 20, 4).unwrap().as_ref(), b"12345");
    }

    #[test]
    fn missing_walk_expands_absent_parents_and_stops_at_present_ones() {
        let (store, msg, media) = seed();
        let root = vec![ref_of(msg, msg_bytes().len())];
        // Peer has nothing: the parent program is useless without the media it
        // references, so both must be pushed.
        assert_eq!(
            missing_blocks(&store, &Always(false), &root, 10),
            vec![msg, media]
        );
        // Peer has the parent: no need to look inside it at all.
        assert_eq!(
            missing_blocks(&store, &Always(true), &root, 10),
            Vec::<Digest>::new()
        );
        // A media block referenced directly is reported on its own.
        let only_media = vec![ref_of(media, MEDIA.len())];
        assert_eq!(
            missing_blocks(&store, &Always(false), &only_media, 10),
            vec![media]
        );
        // The push budget must be honoured even when the store is empty.
        assert_eq!(missing_blocks(&store, &Always(false), &root, 1).len(), 1);
    }

    #[test]
    fn depth_and_size_limits_are_enforced() {
        let (store, msg, _) = seed();
        let root = vec![ref_of(msg, msg_bytes().len())];
        assert_eq!(
            resolve(&store, &root, 1 << 20, 1).unwrap_err(),
            ResolveError::TooDeep(1)
        );
        assert_eq!(
            resolve(&store, &root, 8, 8).unwrap_err(),
            ResolveError::TooLarge(8)
        );
    }

    #[test]
    fn length_mismatch_is_rejected() {
        let store = MemStore::default();
        let d = digest_of(BlockKind::Raw, b"abc");
        store.put(Block::raw(d, BlockKind::Raw, Bytes::from_static(b"abc")));
        let e = resolve(&store, &[ref_of(d, 2)], 1 << 20, 8);
        assert_eq!(e.unwrap_err(), ResolveError::Corrupt);
    }

    #[test]
    fn normalize_merges_and_drops_empty() {
        let n = normalize(vec![
            Instr::Lit(Bytes::from_static(b"ab")),
            Instr::Lit(Bytes::from_static(b"")),
            Instr::Lit(Bytes::from_static(b"cd")),
            Instr::Ref {
                digest: Digest([9; 16]),
                len: 3,
            },
            Instr::Lit(Bytes::from_static(b"e")),
        ]);
        assert_eq!(n.len(), 3);
        assert_eq!(total_len(&n), 8);
        assert_eq!(n[0], Instr::Lit(Bytes::from_static(b"abcd")));
    }
}
