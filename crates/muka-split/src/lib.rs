//! `muka-split` - byte-exact structural deduplication of LLM request bodies.
//!
//! The whole crate exists to answer one question: *can the peer rebuild this
//! body byte-for-byte from what it already has?* It never parses-and-reserialises
//! JSON, because that would silently rewrite key order, number formats and
//! escapes, which changes what the upstream model tokenises and busts its
//! prefix cache. A body is instead described as a program of literal byte runs
//! and references to content-addressed blocks, and reconstruction is
//! concatenation.
//!
//! ```text
//! {"messages":[{m0},{m1}],"tools":[...]}
//!   -> Lit(`{"messages":[`) Ref(m0) Lit(`,`) Ref(m1) Lit(`],"tools":`) Ref(tools) Lit(`}`)
//! ```
//!
//! Blocks nest (a message block can reference the screenshot inside it), so a
//! new turn that reuses an old image costs 24 bytes rather than 1.3 MB.

mod cdc;
mod digest;
mod json;
mod memory;
mod policy;
mod presence;
mod program;
mod splitter;

pub use cdc::cdc_candidates;
pub use digest::{digest_of, BlockKind, Digest, DIGEST_LEN};
pub use json::{
    decode_string, elements_of_array, members_of_object, scan_document, scan_string, scan_value,
    skip_ws, strict_document, validate, Member, ScanError, Span, ValueKind, ValueSpan, MAX_DEPTH,
};
pub use memory::MemStore;
pub use policy::{
    Action, Cand, Group, Policy, Skip, SplitStats, ARRAY_MEMBER_KEYS, DATA_URI_PREFIX,
    MAX_PAYLOAD_CANDS, MEDIA_KEYS, WHOLE_VALUE_KEYS,
};
pub use presence::{Always, Never, Optimistic};
pub use program::{
    missing_blocks, normalize, program_wire_cost, resolve, total_len, Block, BlockBody,
    BlockSource, BlockStore, Instr, Presence, ResolveError, SplitOutput,
};
pub use splitter::{check_identity, split_body, Ctx};
