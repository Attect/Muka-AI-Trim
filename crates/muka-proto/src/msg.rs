//! Control-plane messages.
//!
//! These are JSON: they are small, they evolve with `#[serde(default)]`, and
//! being readable matters when a user pastes a `--tee` capture to explain a
//! bug. Bulk data (programs, blocks, blooms, digest lists) is binary and lives
//! in `codec`.

use muka_split::{Digest, SplitStats};
use serde::{Deserialize, Serialize};

/// Protocol version. Peers must agree exactly: a mismatch degrades to
/// pass-through rather than reconstructing a wrong request.
/// Bumped whenever a peer must not be allowed to half-understand the other:
/// version 2 added compressed upload frames.
pub const VERSION: u32 = 2;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hello {
    pub version: u32,
    /// Human label for the console.
    pub peer_name: String,
    /// `hex(random)` echo of the pairing challenge, proving the shared secret
    /// without sending it.
    pub proof: String,
    /// Store size at open, so the peer can size its bloom.
    pub blocks: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HelloAck {
    pub version: u32,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub blocks: u64,
    /// Bumped on every peer start; a change means "my store is empty".
    pub epoch: u64,
}

/// One agent request. `split=false` means the body follows verbatim.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestHead {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body_len: u64,
    /// Digest of the *exact* body bytes; the peer must reproduce this.
    pub body_digest: Digest,
    pub kind: Kind,
    pub split: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Kind {
    #[default]
    Other,
    ChatCompletions,
    Completions,
    Responses,
    /// Anthropic Messages API: `/v1/messages` and its `count_tokens` sibling.
    /// The repeating history looks the same to the splitter; only the auth
    /// header differs, which is why the family is remembered here.
    Messages,
    Embeddings,
    Models,
}

impl Kind {
    pub const fn dedupable(self) -> bool {
        matches!(
            self,
            Kind::ChatCompletions
                | Kind::Completions
                | Kind::Responses
                | Kind::Messages
                | Kind::Embeddings
        )
    }
}

/// Classify a request path. Unknown paths pass through untouched.
pub fn classify(path: &str) -> Kind {
    let p = path.split('?').next().unwrap_or(path).trim_end_matches('/');
    if p.ends_with("/chat/completions") {
        Kind::ChatCompletions
    } else if p.ends_with("/completions") {
        Kind::Completions
    } else if p.ends_with("/responses") {
        Kind::Responses
    } else if p.ends_with("/messages") || p.ends_with("/count_tokens") {
        Kind::Messages
    } else if p.ends_with("/embeddings") {
        Kind::Embeddings
    } else if p.ends_with("/models") {
        Kind::Models
    } else {
        Kind::Other
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_length: Option<u64>,
    /// Time the peer spent rebuilding the body, so the console can separate it
    /// from link and model latency.
    pub rebuild_us: u64,
}

/// End of one request's response, carrying the accounting for the turn.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponseEnd {
    pub wire_bytes: u64,
    pub body_bytes: u64,
    pub upstream_us: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<SplitStats>,
    /// Set when the peer had to ask for blocks we believed it already had.
    pub repairs: u32,
    pub store_blocks: u64,
    pub store_bytes: u64,
}

impl ResponseEnd {
    /// Fraction of this turn's body that the peer already had.
    pub fn saved_ratio(&self) -> f64 {
        if self.body_bytes == 0 {
            return 0.0;
        }
        1.0 - (self.wire_bytes as f64 / self.body_bytes as f64)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerStats {
    pub requests: u64,
    pub rebuilt: u64,
    pub passthrough: u64,
    pub repairs: u64,
    pub store_blocks: u64,
    pub store_bytes: u64,
    pub stored: u64,
    pub evictions: u64,
    pub io_errors: u64,
}

/// Digests the receiver is missing. Binary: `count | digest*`.
pub fn encode_needs(digests: &[Digest]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + digests.len() * 16);
    crate::varint::write_uvarint(&mut out, digests.len() as u64);
    for d in digests {
        out.extend_from_slice(d.as_bytes());
    }
    out
}

pub fn decode_needs(raw: &[u8], max: usize) -> Result<Vec<Digest>, crate::codec::Error> {
    let mut r = crate::varint::Reader::new(raw);
    let n = r.u64_as("need count")?;
    if n > max {
        return Err(crate::codec::Error::TooLarge(n));
    }
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let b = r.take(muka_split::DIGEST_LEN)?;
        let mut a = [0u8; muka_split::DIGEST_LEN];
        a.copy_from_slice(b);
        out.push(Digest(a));
    }
    Ok(out)
}

/// `epoch | blocks | bloom bytes`.
pub fn encode_bloom(epoch: u64, blocks: u64, bloom: &muka_store::Bloom) -> Vec<u8> {
    let mut out = Vec::new();
    crate::varint::write_uvarint(&mut out, epoch);
    crate::varint::write_uvarint(&mut out, blocks);
    out.extend_from_slice(&bloom.to_bytes());
    out
}

pub fn decode_bloom(raw: &[u8]) -> Result<(u64, u64, muka_store::Bloom), crate::codec::Error> {
    let mut r = crate::varint::Reader::new(raw);
    let epoch = r.uvarint()?;
    let blocks = r.uvarint()?;
    let bloom = muka_store::Bloom::from_bytes(r.rest())
        .ok_or(crate::codec::Error::Codec(crate::varint::CodecError::Bad("bad bloom")))?;
    Ok((epoch, blocks, bloom))
}

/// Which block body shape a frame tag implies.
pub const fn block_is_program(tag: crate::codec::Tag) -> bool {
    matches!(tag, crate::codec::Tag::BlockProgram)
}
