//! Views of "can the peer resolve this digest?".

use crate::digest::Digest;
use crate::program::Presence;
use std::collections::HashSet;
use std::sync::RwLock;

/// Peer has nothing (first request, or after a peer restart).
pub struct Never;

impl Presence for Never {
    fn has(&self, _digest: &Digest) -> bool {
        false
    }
}

/// Test helper.
pub struct Always(pub bool);

impl Presence for Always {
    fn has(&self, _digest: &Digest) -> bool {
        self.0
    }
}

/// The peer's reported cache state, widened by the blocks *this* process has
/// already pushed and not yet seen confirmed.
///
/// Without the optimistic half, every block would be pushed twice: bloom
/// filters only refresh on the next downstream response, so a block pushed for
/// request N still reads as absent while request N+1 is being split. The
/// repair path (`Need` frames) makes guessing "present" safe: a wrong guess
/// costs one round trip and a re-push, never a corrupt request.
pub struct Optimistic {
    base: Box<dyn Presence>,
    sent: RwLock<HashSet<Digest>>,
}

impl Optimistic {
    pub fn new(base: Box<dyn Presence>) -> Self {
        Optimistic {
            base,
            sent: RwLock::new(HashSet::new()),
        }
    }

    pub fn note_pushed(&self, digests: impl IntoIterator<Item = Digest>) {
        let mut g = self.sent.write().expect("presence lock poisoned");
        for d in digests {
            g.insert(d);
        }
    }

    /// Peer restarted or evicted: forget the optimistic view.
    pub fn clear(&self) {
        self.sent.write().expect("presence lock poisoned").clear();
    }

    pub fn len(&self) -> usize {
        self.sent.read().expect("presence lock poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Presence for Optimistic {
    fn has(&self, digest: &Digest) -> bool {
        if self.sent.read().expect("presence lock poisoned").contains(digest) {
            return true;
        }
        self.base.has(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::{digest_of, BlockKind};

    #[test]
    fn optimistic_wins_over_base() {
        let d = digest_of(BlockKind::Raw, b"x");
        let o = Optimistic::new(Box::new(Never));
        assert!(!o.has(&d));
        o.note_pushed([d]);
        assert!(o.has(&d));
        o.clear();
        assert!(!o.has(&d));
    }
}
