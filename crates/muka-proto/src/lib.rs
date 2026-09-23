//! `muka-proto` - the wire between the two ends: frames, block and program
//! encoding, and the control-plane messages.
//!
//! Frame layout: `tag:u8 | stream:uvarint | len:uvarint | payload`.
//! Stream 0 is control; every in-flight request owns one stream id, so a big
//! block push cannot sit in front of a response byte beyond a single frame.

pub mod codec;
pub mod compress;
pub mod io;
pub mod msg;
pub mod varint;

pub use codec::{
    block_digest, decode_block_bytes, decode_block_program, decode_program, encode_block_body,
    encode_block_frame, decode_block_frame, encode_block_head, encode_program, varint_len, Error, Frame, Tag,
    CONTROL_STREAM, MAX_BODY_BYTES,
    MAX_FRAME_PAYLOAD,
};
pub use io::{read_frame, write_frame};
pub use msg::{
    classify, decode_bloom, decode_needs, encode_bloom, encode_needs, block_is_program, Hello,
    HelloAck, Kind, PeerStats, RequestHead, ResponseEnd, ResponseHead, VERSION,
};
pub use varint::{write_uvarint, CodecError, Reader};
pub use compress::{
    compress as zstd_compress, decompress as zstd_decompress, CompressError, LEVEL as ZSTD_LEVEL,
    MAX_DECOMPRESSED, MIN_COMPRESS_BYTES, MIN_SAVING,
};
