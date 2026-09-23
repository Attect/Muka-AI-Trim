//! `muka-store` - the content-addressed block store both ends of the link run.
//!
//! Memory only, deliberately: what gets cached here is prompts and screenshots,
//! and none of it is worth a disk copy that outlives the process. A restarted end
//! re-learns the conversation, which costs one expensive turn the console shows;
//! it can never produce a wrong request, because every rebuild is still checked
//! against the digest the sender declared.
//!
//! Two ceilings bound the footprint: total bytes (LRU evicts the least recently
//! used blocks) and a TTL on untouched blocks. The local side is given the larger
//! budget on purpose - it is the superset a restarted peer re-learns from.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use muka_split::{digest_of, Block, BlockBody, BlockKind, BlockSource, BlockStore, Digest};
use serde::{Deserialize, Serialize};

/// What one process may hold, and the ceiling the console reports.
pub const MEMORY_LIMIT_BYTES: u64 = 200 << 20;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Ceiling on total block bytes; the least recently used blocks go first.
    pub max_bytes: u64,
    pub max_blocks: usize,
    /// Drop blocks untouched for this many seconds. Zero disables TTL.
    pub ttl_secs: u64,
    /// Refuse a single block larger than this.
    pub max_block_bytes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            max_bytes: MEMORY_LIMIT_BYTES,
            max_blocks: 2_000_000,
            ttl_secs: 14 * 24 * 3600,
            // A single block cannot be larger than the whole cache.
            max_block_bytes: MEMORY_LIMIT_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Stats {
    pub blocks: u64,
    pub bytes: u64,
    pub hits: u64,
    pub misses: u64,
    pub stored: u64,
    pub stored_bytes: u64,
    pub evictions: u64,
    pub rejected: u64,
}

struct Entry {
    len: u64,
    kind: BlockKind,
    /// Strictly increasing recency, so LRU order is deterministic.
    seq: u64,
    /// Wall-clock seconds of last use, for TTL.
    at: u64,
    body: BlockBody,
}

#[derive(Default)]
struct Inner {
    map: HashMap<Digest, Entry>,
    seq: u64,
    total: u64,
    stats: Stats,
}

pub struct Store {
    cfg: Config,
    inner: Mutex<Inner>,
}

/// Bytes blocks must hash to their own digest; a program block can only be
/// size-checked here, and is fully verified later by the request body digest.
fn verifies(body: &BlockBody, kind: BlockKind, digest: Digest, len: u64) -> bool {
    match body {
        BlockBody::Bytes(x) => digest_of(kind, x) == digest && x.len() as u64 == len,
        BlockBody::Program(p) => muka_split::total_len(p) == len,
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Store {
    pub fn new(cfg: Config) -> Self {
        Store {
            cfg,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// The configured ceiling, so the console can say how full the cache is.
    pub fn limit_bytes(&self) -> u64 {
        self.cfg.max_bytes
    }

    pub fn stats(&self) -> Stats {
        let g = self.inner.lock().expect("store lock poisoned");
        let mut s = g.stats;
        s.blocks = g.map.len() as u64;
        s.bytes = g.total;
        s
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("store lock poisoned").map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn has(&self, d: &Digest) -> bool {
        self.inner.lock().expect("store lock poisoned").map.contains_key(d)
    }

    /// Touch metadata only, for the presence fast path in the gateway.
    pub fn touch(&self, d: &Digest) {
        let mut g = self.inner.lock().expect("store lock poisoned");
        if !g.map.contains_key(d) {
            return;
        }
        g.seq += 1;
        let (seq, at) = (g.seq, now_secs());
        if let Some(e) = g.map.get_mut(d) {
            e.seq = seq;
            e.at = at;
        }
    }

    pub fn get(&self, d: &Digest) -> Option<Block> {
        let mut g = self.inner.lock().expect("store lock poisoned");
        if !g.map.contains_key(d) {
            g.stats.misses += 1;
            return None;
        }
        g.seq += 1;
        let (seq, at) = (g.seq, now_secs());
        let e = g.map.get_mut(d)?;
        e.seq = seq;
        e.at = at;
        let found = Some(Block {
            digest: *d,
            kind: e.kind,
            len: e.len,
            body: e.body.clone(),
        });
        g.stats.hits += 1;
        found
    }

    /// Insert a block. Returns false when it was refused: oversized, already
    /// present, or - the one that matters - not matching its own digest.
    pub fn insert(&self, b: Block) -> bool {
        // The digest is the only thing standing between a buggy or hostile peer
        // and a poisoned cache, so it is always re-checked here.
        if !verifies(&b.body, b.kind, b.digest, b.len) {
            let mut g = self.inner.lock().expect("store lock poisoned");
            g.stats.rejected += 1;
            tracing::warn!(digest = %b.digest, "rejecting a block that does not match its digest");
            return false;
        }
        if b.len > self.cfg.max_block_bytes {
            let mut g = self.inner.lock().expect("store lock poisoned");
            g.stats.rejected += 1;
            return false;
        }
        let mut g = self.inner.lock().expect("store lock poisoned");
        if g.map.contains_key(&b.digest) {
            return false;
        }
        g.seq += 1;
        let (seq, at) = (g.seq, now_secs());
        g.total += b.len;
        g.stats.stored += 1;
        g.stats.stored_bytes += b.len;
        g.map.insert(
            b.digest,
            Entry {
                len: b.len,
                kind: b.kind,
                seq,
                at,
                body: b.body,
            },
        );
        let over = g.total > self.cfg.max_bytes || g.map.len() > self.cfg.max_blocks;
        drop(g);
        if over {
            self.prune();
        }
        true
    }

    /// Enforce the byte and count ceilings by evicting the least recently used
    /// blocks, and drop anything past its TTL. Called by the peer side only: it
    /// is the authority on what it can resolve.
    pub fn prune(&self) {
        let ttl_secs = self.cfg.ttl_secs;
        let now = now_secs();
        let mut g = self.inner.lock().expect("store lock poisoned");
        let mut victims: Vec<Digest> = Vec::new();
        if ttl_secs > 0 {
            victims.extend(
                g.map
                    .iter()
                    .filter(|(_, e)| now.saturating_sub(e.at) > ttl_secs)
                    .map(|(d, _)| *d),
            );
        }
        let mut over_bytes = g.total.saturating_sub(self.cfg.max_bytes);
        let mut over_count = g.map.len().saturating_sub(self.cfg.max_blocks);
        if over_bytes > 0 || over_count > 0 {
            let mut by_seq: Vec<(u64, Digest)> = g.map.iter().map(|(d, e)| (e.seq, *d)).collect();
            by_seq.sort_unstable();
            for (_, d) in by_seq {
                if over_bytes == 0 && over_count == 0 {
                    break;
                }
                if victims.contains(&d) {
                    continue;
                }
                let Some(len) = g.map.get(&d).map(|e| e.len) else {
                    continue;
                };
                victims.push(d);
                over_bytes = over_bytes.saturating_sub(len);
                over_count = over_count.saturating_sub(1);
            }
        }
        for d in &victims {
            if g.map.remove(d).is_some() {
                g.stats.evictions += 1;
            }
        }
        // Cheaper and less error-prone than tracking every removal.
        g.total = g.map.values().map(|e| e.len).sum();
    }

    pub fn digests(&self) -> Vec<Digest> {
        self.inner.lock().expect("store lock poisoned").map.keys().copied().collect()
    }

    /// Forget every block. Returns how many went.
    ///
    /// Used by the console's "clear and re-push" action: after this the next
    /// requests re-upload their blocks, which is how you recover from a suspect
    /// cache without restarting either machine.
    pub fn clear(&self) -> u64 {
        let mut g = self.inner.lock().expect("store lock poisoned");
        let n = g.map.len() as u64;
        g.map.clear();
        g.total = 0;
        g.stats.evictions += n;
        n
    }

    /// Membership snapshot to hand to the other end, so it can reference blocks
    /// without a round trip per lookup.
    pub fn bloom(&self) -> Bloom {
        let g = self.inner.lock().expect("store lock poisoned");
        let mut b = Bloom::new(g.map.len().max(1024), 6);
        for d in g.map.keys() {
            b.add(d);
        }
        b
    }

    /// Bytes currently held.
    pub fn total_bytes(&self) -> u64 {
        self.inner.lock().expect("store lock poisoned").total
    }
}

impl BlockSource for Store {
    fn get(&self, d: &Digest) -> Option<Block> {
        Store::get(self, d)
    }
    fn has(&self, d: &Digest) -> bool {
        Store::has(self, d)
    }
}

impl BlockStore for Store {
    fn put(&self, block: Block) -> bool {
        Store::insert(self, block)
    }
}

/// Classic double-hashing bloom filter over BLAKE3.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bloom {
    pub m_bits: usize,
    pub k: usize,
    pub words: Vec<u64>,
}

impl Default for Bloom {
    fn default() -> Self {
        Bloom::new(1024, 6)
    }
}

impl Bloom {
    pub fn new(capacity: usize, k: usize) -> Self {
        let bits = (capacity.max(64) * 10).next_power_of_two();
        Bloom {
            m_bits: bits,
            k: k.clamp(1, 12),
            words: vec![0u64; bits / 64],
        }
    }

    pub fn empty() -> Self {
        Bloom::new(64, 6)
    }

    pub fn add(&mut self, d: &Digest) {
        for i in self.indices(d) {
            self.words[i >> 6] |= 1 << (i & 63);
        }
    }

    pub fn has(&self, d: &Digest) -> bool {
        self.indices(d)
            .into_iter()
            .all(|i| self.words[i >> 6] & (1 << (i & 63)) != 0)
    }

    fn indices(&self, d: &Digest) -> Vec<usize> {
        let mut h = blake3::Hasher::new();
        h.update(b"MUKA-BLOOM-1");
        h.update(d.as_bytes());
        let out = h.finalize();
        let b = out.as_bytes();
        let a = u64::from_le_bytes(b[0..8].try_into().unwrap());
        let c = u64::from_le_bytes(b[8..16].try_into().unwrap());
        (0..self.k)
            .map(|i| (a.wrapping_add(c.wrapping_mul(i as u64 + 1)) as usize) % self.m_bits)
            .collect()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.words.len() * 8);
        out.extend_from_slice(&(self.m_bits as u64).to_le_bytes());
        out.extend_from_slice(&(self.k as u64).to_le_bytes());
        for w in &self.words {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }

    pub fn from_bytes(raw: &[u8]) -> Option<Bloom> {
        if raw.len() < 16 {
            return None;
        }
        let m_bits = u64::from_le_bytes(raw[0..8].try_into().ok()?) as usize;
        let k = u64::from_le_bytes(raw[8..16].try_into().ok()?) as usize;
        let words: Vec<u64> = raw[16..]
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect();
        if m_bits % 64 != 0 || m_bits / 64 != words.len() || m_bits > 1 << 26 || k == 0 {
            return None;
        }
        Some(Bloom { m_bits, k, words })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use muka_split::{digest_of, normalize, Instr};

    fn cfg() -> Config {
        Config {
            max_bytes: 10_000,
            max_blocks: 1000,
            ttl_secs: 0,
            max_block_bytes: 5_000,
        }
    }

    fn blk(tag: u8, fill: usize) -> Block {
        let mut data = vec![tag];
        data.extend(std::iter::repeat_n(b'z', fill));
        let d = digest_of(BlockKind::JsonMember, &data);
        Block::raw(d, BlockKind::JsonMember, Bytes::from(data))
    }

    #[test]
    fn the_cache_is_bounded_to_200_mib_by_default() {
        assert_eq!(MEMORY_LIMIT_BYTES, 200 << 20);
        assert_eq!(Config::default().max_bytes, MEMORY_LIMIT_BYTES);
        assert_eq!(Config::default().max_block_bytes, MEMORY_LIMIT_BYTES);
        assert_eq!(Store::new(Config::default()).limit_bytes(), MEMORY_LIMIT_BYTES);
    }

    #[test]
    fn lru_eviction_keeps_the_recently_used() {
        let s = Store::new(cfg());
        let a = blk(1, 3_999);
        let b = blk(2, 3_498);
        let c = blk(3, 3_999);
        let (da, db, dc) = (a.digest, b.digest, c.digest);
        assert!(s.insert(a));
        assert!(s.insert(b));
        assert!(s.get(&da).is_some(), "touch a");
        assert!(s.insert(c));
        assert!(s.has(&da), "recently used block must survive");
        assert!(s.has(&dc));
        assert!(!s.has(&db), "least recently used should be evicted");
        assert!(s.total_bytes() <= 10_000, "{} bytes held", s.total_bytes());
        assert!(s.stats().evictions >= 1);
    }

    #[test]
    fn oversized_and_mismatched_blocks_are_refused() {
        let s = Store::new(cfg());
        assert!(!s.insert(blk(9, 5_001)), "over max_block_bytes");
        // Bytes that do not hash to the digest claimed would poison every later
        // request that references this block.
        let lie = blk(4, 100);
        let bytes = match lie.body {
            BlockBody::Bytes(b) => b,
            other => unreachable!("blk builds byte bodies, got {other:?}"),
        };
        assert!(!s.insert(Block::raw(digest_of(BlockKind::JsonMember, b"other"), BlockKind::JsonMember, bytes)), "digest mismatch must be rejected");
        assert_eq!(s.len(), 0, "nothing landed");
        assert_eq!(s.stats().rejected, 2, "and both refusals are counted");
    }

    #[test]
    fn program_blocks_are_kept_and_returned_whole() {
        let p = Block::program(
            digest_of(BlockKind::Media, b"AB"),
            BlockKind::Media,
            2,
            vec![Instr::Lit(Bytes::from_static(b"A")), Instr::Lit(Bytes::from_static(b"B"))],
        );
        let d = p.digest;
        let s = Store::new(cfg());
        assert!(s.insert(p));
        let back = s.get(&d).expect("the program block");
        let instrs = match back.body {
            BlockBody::Program(p) => p,
            ref other => panic!("expected a program block, got {other:?}"),
        };
        assert_eq!(normalize(instrs).len(), 1, "the nested literals were kept");
        assert_eq!(back.len, 2);
        assert_eq!(s.stats().blocks, 1);
    }

    #[test]
    fn clear_forgets_everything_and_the_store_keeps_working() {
        let s = Store::new(cfg());
        for tag in [1u8, 2, 3] {
            assert!(s.insert(blk(tag, 500)));
        }
        assert_eq!(s.len(), 3);
        assert_eq!(s.stats().bytes, 1_503);
        assert_eq!(s.clear(), 3);
        assert_eq!(s.len(), 0);
        assert_eq!(s.stats().bytes, 0);
        assert_eq!(s.total_bytes(), 0);
        assert!(s.insert(blk(9, 500)), "and it still takes blocks afterwards");
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn bloom_reports_membership_with_a_low_false_positive_rate() {
        let mut b = Bloom::new(10_000, 6);
        let keep: Vec<Block> = (0..500).map(|i| blk(b'x', 64 + i)).collect();
        for k in &keep {
            b.add(&k.digest);
        }
        assert!(keep.iter().all(|k| b.has(&k.digest)), "no false negatives");
        let fp = (0..5000)
            .filter(|i| b.has(&digest_of(BlockKind::JsonMember, &vec![b'q'; 900 + i])))
            .count();
        assert!(fp * 100 < 5000, "false positive rate too high: {fp}");
        let back = Bloom::from_bytes(&b.to_bytes()).expect("bloom roundtrip");
        assert!(keep.iter().all(|k| back.has(&k.digest)));
        assert!(Bloom::from_bytes(b"short").is_none());
    }
}
