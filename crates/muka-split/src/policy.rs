//! Tunables and the endpoint-shape vocabulary.

use crate::digest::DIGEST_LEN;
use crate::json::Span;
use serde::{Deserialize, Serialize};

/// Top-level array keys whose *elements* are cached individually. This is what
/// makes agent history compaction cheap: deleting or inserting a message in
/// the middle does not invalidate the other elements' digests.
pub const ARRAY_MEMBER_KEYS: &[&str] = &["messages", "input"];

/// Top-level keys cached as one whole value (large, rarely changing).
pub const WHOLE_VALUE_KEYS: &[&str] = &[
    "tools",
    "functions",
    "response_format",
    "prompt",
    "audio",
    "file",
    "file_ids",
    "tool_choice",
];

/// Keys whose string values are expected to hold base64 payloads.
pub const MEDIA_KEYS: &[&str] = &["url", "file_data", "data", "b64_json", "image_base64", "input_audio"];

/// A string value is treated as a lift-out payload when it starts with this.
pub const DATA_URI_PREFIX: &[u8] = b"data:";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    pub enabled: bool,
    /// Bodies smaller than this are sent whole: splitting would cost more than it saves.
    pub min_body_bytes: usize,
    /// Smallest JSON value we will create a block for.
    pub min_block_bytes: usize,
    /// Floor for elements of a cached history array. Lower than
    /// `min_block_bytes` on purpose: history is re-sent on *every* turn, so a
    /// 160-byte assistant message pays for its block within two turns, while a
    /// one-off value never would.
    pub min_history_block_bytes: usize,
    /// Smallest base64 / long-text payload worth lifting out of its message.
    pub min_payload_bytes: usize,
    /// Cap on reconstructed body size (defence against a hostile program).
    pub max_body_bytes: usize,
    pub max_instrs: usize,
    pub max_depth: usize,
    pub cdc_min: usize,
    pub cdc_max: usize,
    /// Log2 of the CDC average chunk size mask.
    pub cdc_bits: u32,
    /// Use content-defined chunking when the body is not recognisable JSON.
    pub cdc_fallback: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            enabled: true,
            min_body_bytes: 4096,
            min_block_bytes: 384,
            min_history_block_bytes: 128,
            min_payload_bytes: 4096,
            max_body_bytes: 512 << 20,
            max_instrs: 200_000,
            max_depth: 6,
            cdc_min: 8 << 10,
            cdc_max: 128 << 10,
            cdc_bits: 15,
            cdc_fallback: true,
        }
    }
}

impl Policy {
    pub fn cdc_mask(&self) -> u64 {
        (1u64 << self.cdc_bits.min(40)) - 1
    }
}

/// How much of a body the splitter found worth referencing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitStats {
    pub body_len: u64,
    pub lit_bytes: u64,
    pub instrs: u32,
    pub refs: u32,
    /// References the peer could already resolve, at any nesting level.
    pub refs_hit: u32,
    /// References that required us to push the block.
    pub refs_new: u32,
    /// Body bytes covered by top-level references.
    pub ref_covered: u64,
    pub blocks_created: u32,
    pub push_blocks: u32,
    pub push_bytes: u64,
    /// Framing cost of the root program's instruction list.
    pub instr_overhead: u64,
    pub structural: bool,
    pub cdc_used: bool,
}

/// Wire cost of one reference: tag + 16-byte digest + varint length.
pub const REF_WIRE: u64 = 1 + DIGEST_LEN as u64 + 3;
/// Wire cost of one literal run: tag + varint length (payload excluded).
pub const LIT_HDR: u64 = 1 + 3;

impl SplitStats {
    /// Bytes the local side puts on the wire before compression.
    pub fn wire_bytes(&self) -> u64 {
        self.lit_bytes + self.push_bytes + self.instr_overhead
    }

    /// Fraction of the body that did not have to be sent again.
    ///
    /// Note this is intentionally *not* `ref_covered / body_len`: on the first
    /// turn of a conversation every block is new, so the honest number is zero
    /// even though the split is what makes later turns cheap.
    pub fn saved_ratio(&self) -> f64 {
        if self.body_len == 0 {
            return 0.0;
        }
        let wire = self.wire_bytes();
        1.0 - (wire as f64 / self.body_len as f64)
    }

    /// Splitting may not make a request bigger: the top-up a peer needs after a
    /// restart, or a pathological body with thousands of tiny blocks, must
    /// degrade to sending the body verbatim.
    pub fn inflates(&self) -> bool {
        let slack = (self.body_len / 16).max(1024);
        self.wire_bytes() > self.body_len + slack
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Skip {
    /// Splitting disabled by config.
    Disabled,
    /// Body below `min_body_bytes`.
    TooSmall(u64),
    /// Body larger than `max_body_bytes`.
    TooLarge(u64),
    /// Not a single JSON object; CDC found nothing above the block floor.
    Unrecognised,
    /// Splitter guard tripped (too many instructions / nesting).
    Limits,
}

impl Skip {
    pub const fn reason(&self) -> &'static str {
        match self {
            Skip::Disabled => "disabled",
            Skip::TooSmall(_) => "too_small",
            Skip::TooLarge(_) => "too_large",
            Skip::Unrecognised => "unknown_shape",
            Skip::Limits => "limits",
        }
    }
}

/// A candidate byte range, in body coordinates.
#[derive(Clone, Copy, Debug)]
pub struct Cand {
    pub span: Span,
    pub kind: crate::digest::BlockKind,
    /// Minimum size worth a block, decided by whoever found the candidate: a
    /// history element, a one-off value and a base64 payload break even on
    /// different time scales.
    pub floor: usize,
}

impl Cand {
    pub const fn new(span: Span, kind: crate::digest::BlockKind, floor: usize) -> Self {
        Cand { span, kind, floor }
    }
}

/// A top-level candidate plus the payload candidates nested inside it.
#[derive(Clone, Debug)]
pub struct Group {
    pub cand: Cand,
    pub children: Vec<Cand>,
}

/// Cap on payload candidates per body, so a pathological body cannot make the
/// splitter spend longer than the transfer it is trying to save.
pub const MAX_PAYLOAD_CANDS: usize = 4096;

/// What the splitter produced for one body.
#[derive(Clone, Debug)]
pub enum Action {
    /// Send `program` + push `to_push` blocks; peer can rebuild the body.
    Split(crate::program::SplitOutput),
    /// Send the body verbatim.
    Passthrough(Skip),
}
