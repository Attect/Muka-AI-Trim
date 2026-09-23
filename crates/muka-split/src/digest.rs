//! Content digests.
//!
//! A digest covers the *exact raw bytes* of a block together with a domain tag
//! and the length, so a collision can never silently substitute different bytes
//! into a reconstructed request body.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Wire/internal digest width. 128 bit truncated BLAKE3.
pub const DIGEST_LEN: usize = 16;

/// Domain separation so identical bytes under different roles never collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum BlockKind {
    /// Opaque whole request body (pass-through / non structural fallback).
    Raw = 0,
    /// A JSON value that is a member of a cached array/object (e.g. one message).
    JsonMember = 1,
    /// A base64 media payload lifted out of a string value.
    Media = 2,
    /// Content defined chunk (CDC fallback).
    Chunk = 3,
    /// A large string value kept inside a block program.
    Text = 4,
}

impl BlockKind {
    pub const fn from_u8(v: u8) -> Option<BlockKind> {
        match v {
            0 => Some(BlockKind::Raw),
            1 => Some(BlockKind::JsonMember),
            2 => Some(BlockKind::Media),
            3 => Some(BlockKind::Chunk),
            4 => Some(BlockKind::Text),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Digest(#[serde(with = "hexbytes")] pub [u8; DIGEST_LEN]);

impl Digest {
    pub const fn as_bytes(&self) -> &[u8; DIGEST_LEN] {
        &self.0
    }

    pub fn hex(&self) -> String {
        let mut s = String::with_capacity(DIGEST_LEN * 2);
        for b in self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    pub fn short(&self) -> String {
        let mut s = String::with_capacity(12);
        for b in self.0.iter().take(6) {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", self.short())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

mod hexbytes {
    use super::DIGEST_LEN;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; DIGEST_LEN], s: S) -> Result<S::Ok, S::Error> {
        let mut buf = [0u8; DIGEST_LEN * 2];
        for (i, b) in v.iter().enumerate() {
            buf[i * 2] = hex_b(*b >> 4);
            buf[i * 2 + 1] = hex_b(*b & 0x0f);
        }
        s.serialize_str(std::str::from_utf8(&buf).expect("hex is ascii"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; DIGEST_LEN], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = s.as_bytes();
        if bytes.len() != DIGEST_LEN * 2 {
            return Err(serde::de::Error::custom("bad digest length"));
        }
        let mut out = [0u8; DIGEST_LEN];
        for (i, o) in out.iter_mut().enumerate() {
            let hi = hex_v(bytes[i * 2]).map_err(serde::de::Error::custom)?;
            let lo = hex_v(bytes[i * 2 + 1]).map_err(serde::de::Error::custom)?;
            *o = (hi << 4) | lo;
        }
        Ok(out)
    }

    const fn hex_b(n: u8) -> u8 {
        if n < 10 {
            b'0' + n
        } else {
            b'a' + (n - 10)
        }
    }

    const fn hex_v(c: u8) -> Result<u8, &'static str> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err("bad hex digit"),
        }
    }
}

const DOMAIN: &[u8] = b"MUKA-SPLIT-1";

/// Digest of `data` in role `kind`.
pub fn digest_of(kind: BlockKind, data: &[u8]) -> Digest {
    let mut h = blake3::Hasher::new();
    h.update(DOMAIN);
    h.update(&[kind as u8]);
    h.update(&(data.len() as u64).to_le_bytes());
    h.update(data);
    let full = h.finalize();
    let mut out = [0u8; DIGEST_LEN];
    out.copy_from_slice(&full.as_bytes()[..DIGEST_LEN]);
    Digest(out)
}

/// Deterministic pseudo random table for the gear rolling hash.
pub(crate) fn gear_table() -> [u64; 256] {
    let mut t = [0u64; 256];
    for (i, slot) in t.iter_mut().enumerate() {
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN);
        h.update(&(i as u32).to_le_bytes());
        let out = h.finalize();
        *slot = u64::from_le_bytes(out.as_bytes()[..8].try_into().unwrap());
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_stable_and_role_separated() {
        let a = digest_of(BlockKind::Media, b"hello");
        let b = digest_of(BlockKind::Media, b"hello");
        let c = digest_of(BlockKind::JsonMember, b"hello");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.hex().len(), DIGEST_LEN * 2);
        let json = serde_json::to_string(&a).unwrap();
        let back: Digest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);
    }
}
