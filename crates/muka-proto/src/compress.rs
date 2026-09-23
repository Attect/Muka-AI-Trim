//! Optional zstd on the upload side of the link.
//!
//! Only request-direction payloads are compressed. The download is a token
//! stream where a compressed block is bytes the agent cannot see until it is
//! complete, while the upload is a burst that has to finish before the model
//! even starts - and after deduplication the burst that remains is the first
//! turn of a conversation and any verbatim passthrough, i.e. exactly the
//! payloads worth paying CPU for.

use thiserror::Error;

/// Below this a zstd frame's own overhead is not worth a round trip.
pub const MIN_COMPRESS_BYTES: usize = 512;
/// Ratio a payload must beat, otherwise send it raw (base64 screenshots do).
pub const MIN_SAVING: f64 = 0.10;
/// Level 3 is roughly the point where more CPU stops buying more bytes.
pub const LEVEL: i32 = 3;
/// Hard ceiling on a decompressed frame, so a hostile or corrupt frame cannot
/// turn a few kilobytes into gigabytes.
pub const MAX_DECOMPRESSED: usize = 64 << 20;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CompressError {
    #[error("zstd encode failed for a {0} byte payload")]
    Encode(usize),
    #[error("zstd decode failed: {0}")]
    Decode(String),
    #[error("decompressed frame would exceed {0} bytes")]
    TooLarge(usize),
}

/// Compress, returning `None` when it is not worth it.
pub fn compress(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < MIN_COMPRESS_BYTES {
        return None;
    }
    let out = zstd::bulk::compress(data, LEVEL).ok()?;
    if out.is_empty() {
        return None;
    }
    let saving = 1.0 - (out.len() as f64 / data.len() as f64);
    if saving < MIN_SAVING {
        return None;
    }
    Some(out)
}

pub fn decompress(data: &[u8]) -> Result<Vec<u8>, CompressError> {
    let mut d = zstd::stream::Decoder::new(data).map_err(|e| CompressError::Decode(e.to_string()))?;
    use std::io::Read;
    // `take` bounds the output even against a valid but enormous frame.
    let mut buf = Vec::new();
    let limit = (&mut d).take(MAX_DECOMPRESSED as u64 + 1);
    let mut limit = limit;
    limit.read_to_end(&mut buf).map_err(|e| CompressError::Decode(e.to_string()))?;
    if buf.len() > MAX_DECOMPRESSED {
        return Err(CompressError::TooLarge(MAX_DECOMPRESSED));
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_compresses_and_entropy_does_not() {
        let json = format!("{{\"messages\":[{}]}}", (0..400).map(|i| format!("{{\"role\":\"user\",\"content\":\"line {i} of a tool result\"}}")).collect::<Vec<_>>().join(","));
        let c = compress(json.as_bytes()).expect("text should compress");
        assert!(c.len() * 3 < json.len(), "{} vs {}", c.len(), json.len());
        assert_eq!(decompress(&c).unwrap(), json.as_bytes());

        // Screenshot payloads are base64 of already-compressed image data, i.e.
        // high entropy: burning CPU there buys nothing, so it must stay raw.
        let mut x = 7u64;
        let raw: Vec<u8> = (0..20_000)
            .map(|_| {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (x >> 33) as u8
            })
            .collect();
        // Raw random bytes have nothing to gain.
        assert!(compress(&raw).is_none(), "high-entropy bytes must stay raw");
        // base64 wastes a quarter of every byte, so there is a modest win -
        // worth taking, but it must stay modest or the CPU is not justified.
        let enc = base64_of(&raw);
        let c = compress(&enc).expect("base64 has recoverable slack");
        assert!(c.len() * 4 > enc.len(), "expected under 25% saving, got {} of {}", c.len(), enc.len());
    }

    /// A stand-in for base64 image data: 6 useful bits per byte, no structure.
    fn base64_of(raw: &[u8]) -> Vec<u8> {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::with_capacity(raw.len() * 4 / 3 + 4);
        for chunk in raw.chunks(3) {
            let b = [chunk[0], chunk.get(1).copied().unwrap_or(0), chunk.get(2).copied().unwrap_or(0)];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(T[(n >> 18) as usize & 63]);
            out.push(T[(n >> 12) as usize & 63]);
            out.push(T[(n >> 6) as usize & 63]);
            out.push(T[n as usize & 63]);
        }
        out
    }

    #[test]
    fn small_payloads_are_not_wrapped() {
        assert!(compress(&[b'a'; 100]).is_none(), "below MIN_COMPRESS_BYTES");
        assert!(compress(&[b'a'; 4096]).is_some(), "a compressible burst is worth it");
    }

    #[test]
    fn a_bomb_is_refused() {
        let huge = vec![b'x'; 100_000];
        let frame = zstd::bulk::compress(&huge, LEVEL).unwrap();
        assert_eq!(decompress(&frame).unwrap().len(), 100_000);
        // A frame declaring more than the ceiling still fails closed.
        let bigger = zstd::bulk::compress(&vec![b'y'; MAX_DECOMPRESSED + 10], LEVEL).unwrap();
        assert_eq!(decompress(&bigger), Err(CompressError::TooLarge(MAX_DECOMPRESSED)));
    }

    #[test]
    fn garbage_is_reported_not_panicked() {
        assert!(matches!(decompress(b"not a zstd frame"), Err(CompressError::Decode(_))));
    }
}
