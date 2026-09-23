//! Content-defined chunking: the shape-agnostic fallback.
//!
//! Used when the body is not a recognisable JSON object (or is one we found no
//! cacheable structure in), so a `/v1/completions` prompt or a multipart body
//! still deduplicates. Chunk boundaries are content defined, so an insertion in
//! the middle only changes the chunk containing it.

use crate::digest::{gear_table, BlockKind};
use crate::json::Span;
use crate::policy::Cand;
use std::sync::OnceLock;

fn gear() -> &'static [u64; 256] {
    static T: OnceLock<[u64; 256]> = OnceLock::new();
    T.get_or_init(gear_table)
}

/// Split `range` into content-defined chunks. The final chunk always ends at
/// `range.end` so the whole range is covered.
pub fn cdc_candidates(body: &[u8], range: Span, min: usize, max: usize, bits: u32) -> Vec<Cand> {
    let t = gear();
    let mask = (1u64 << bits.min(40)) - 1;
    let mut out = Vec::new();
    let mut start = range.start;
    let mut h = 0u64;
    let mut i = start;
    while i < range.end {
        let b = body[i];
        // Gear shift: the hash keeps only the last 64 bytes, so a boundary at
        // offset p depends on body[p-64..p] alone. That is what makes an
        // insertion early in the body shift exactly one boundary instead of
        // cascading - do not reset `h` at a boundary or that property is lost.
        h = (h << 1).wrapping_add(t[b as usize]);
        i += 1;
        let len = i - start;
        if len >= min && ((h & mask) == 0 || len >= max) {
            out.push(Cand::new(Span::new(start, i), BlockKind::Chunk, min));
            start = i;
        }
    }
    if start < range.end {
        // Tail: emitted to cover the range; the caller applies its own floor.
        out.push(Cand::new(Span::new(start, range.end), BlockKind::Chunk, min));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiles(range: Span, cs: &[Cand]) -> bool {
        let mut pos = range.start;
        for c in cs {
            if c.span.start != pos {
                return false;
            }
            pos = c.span.end;
        }
        pos == range.end
    }

    #[test]
    fn chunks_tile_the_range_and_are_deterministic() {
        let body: Vec<u8> = (0..200_000u32).map(|i| (i * 7 + (i / 1000) as u32) as u8).collect();
        let range = Span::new(0, body.len());
        let a = cdc_candidates(&body, range, 4096, 65536, 13);
        let b = cdc_candidates(&body, range, 4096, 65536, 13);
        assert_eq!(
            a.iter().map(|c| c.span).collect::<Vec<_>>(),
            b.iter().map(|c| c.span).collect::<Vec<_>>()
        );
        assert!(tiles(range, &a));
        assert!(a.len() > 3);
        for c in &a[..a.len().saturating_sub(1)] {
            assert!(c.span.len() >= 4096);
            assert!(c.span.len() <= 65536);
        }
    }

    #[test]
    fn a_late_insertion_only_moves_one_boundary() {
        let base: Vec<u8> = (0..120_000u32).map(|i| (i * 31) as u8).collect();
        let mut patched = base[..40_000].to_vec();
        patched.extend_from_slice(b"INSERTED-PAYLOAD-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
        patched.extend_from_slice(&base[40_000..]);
        let r = Span::new(0, base.len());
        let before = cdc_candidates(&base, r, 2048, 32768, 12);
        let rp = Span::new(0, patched.len());
        let after = cdc_candidates(&patched, rp, 2048, 32768, 12);
        let sb: std::collections::HashSet<Vec<u8>> =
            before.iter().map(|c| c.span.slice(&base).to_vec()).collect();
        let kept = after
            .iter()
            .filter(|c| sb.contains(&c.span.slice(&patched).to_vec()))
            .count();
        assert!(
            kept >= after.len() - 3,
            "only a few chunks should change: {kept}/{}",
            after.len()
        );
    }
}
