//! A tiny in-memory block store: used by tests, benchmarks and `--shadow`.

use crate::digest::Digest;
use crate::program::{Block, BlockSource, BlockStore};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Default)]
pub struct MemStore {
    map: Mutex<HashMap<Digest, Block>>,
}

impl MemStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&self, block: Block) -> bool {
        self.map
            .lock()
            .expect("store lock poisoned")
            .insert(block.digest, block)
            .is_none()
    }

    pub fn len(&self) -> usize {
        self.map.lock().expect("store lock poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn bytes(&self) -> u64 {
        self.map
            .lock()
            .expect("store lock poisoned")
            .values()
            .map(|b| b.len)
            .sum()
    }

    pub fn remove(&self, d: &Digest) -> Option<Block> {
        self.map.lock().expect("store lock poisoned").remove(d)
    }

    /// Simulate a peer restart / full eviction.
    pub fn remove_all(&self) {
        self.map.lock().expect("store lock poisoned").clear();
    }
}

impl BlockSource for MemStore {
    fn get(&self, d: &Digest) -> Option<Block> {
        self.map
            .lock()
            .expect("store lock poisoned")
            .get(d)
            .cloned()
    }

    fn has(&self, d: &Digest) -> bool {
        self.map
            .lock()
            .expect("store lock poisoned")
            .contains_key(d)
    }
}

impl BlockStore for MemStore {
    fn put(&self, block: Block) -> bool {
        MemStore::put(self, block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::{digest_of, BlockKind};
    use bytes::Bytes;

    #[test]
    fn roundtrip() {
        let s = MemStore::new();
        let data = Bytes::from_static(b"abcd");
        let d = digest_of(BlockKind::Raw, &data);
        assert!(s.put(Block::raw(d, BlockKind::Raw, data)));
        assert!(!s.put(Block::raw(d, BlockKind::Raw, Bytes::from_static(b"abcd"))));
        assert_eq!(s.get(&d).unwrap().len, 4);
        assert_eq!(s.bytes(), 4);
        assert_eq!(s.remove(&d).unwrap().digest, d);
        assert!(!s.has(&d));
    }
}
