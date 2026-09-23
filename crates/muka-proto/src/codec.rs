//! Frame framing and binary encoding of block programs.

use bytes::Bytes;
use muka_split::{Block, BlockBody, BlockKind, Digest, Instr, DIGEST_LEN};
use thiserror::Error;

use crate::varint::{write_uvarint, CodecError, Reader};

/// Largest frame payload we will read. Blocks (screenshots) are the biggest
/// thing that moves, and 64 MB is far above any real request body.
pub const MAX_FRAME_PAYLOAD: usize = 64 << 20;
/// Largest body we are willing to reconstruct, matched with the split policy.
pub const MAX_BODY_BYTES: usize = 512 << 20;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error("frame payload of {0} bytes exceeds the {MAX_FRAME_PAYLOAD} limit")]
    TooLarge(usize),
    #[error("unknown frame tag {0}")]
    UnknownTag(u8),
    #[error("unknown block kind {0}")]
    UnknownKind(u8),
    #[error("protocol version {0} is not supported (we speak {1})")]
    Version(u32, u32),
    #[error("io: {0}")]
    Io(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Tag {
    /// Session open: role, version, pairing proof.
    Hello = 1,
    /// Accept or reject a `Hello`.
    HelloAck = 2,
    /// One agent request's metadata (method, path, headers, body digest).
    RequestHead = 3,
    /// The program the peer uses to rebuild the body.
    Program = 4,
    /// A block whose body is opaque bytes.
    BlockBytes = 5,
    /// A block whose body is a nested program.
    BlockProgram = 6,
    /// Peer is missing these digests.
    Need = 7,
    /// Snapshot of the sender's store membership.
    Bloom = 8,
    /// Upstream response status and headers.
    ResponseHead = 9,
    /// A chunk of the upstream response body.
    ResponseBody = 10,
    /// End of one request's response, with per-turn accounting.
    ResponseEnd = 11,
    /// Peer-side counters, for the console.
    PeerStats = 12,
    Ping = 13,
    Pong = 14,
    /// Peer restarted: its store is empty.
    Reset = 15,
    /// Abort one stream (client went away).
    Cancel = 16,
    /// The sender finished the body for this stream.
    EndOfBody = 17,
    /// A chunk of a request body sent verbatim.
    RequestBody = 18,
    /// The peer could not rebuild: re-send the body whole.
    Fail = 19,
    /// Upload-side payloads, zstd frame. Kept separate from the raw tags so a
    /// receiver never has to guess whether to decompress.
    ProgramZ = 20,
    BlockBytesZ = 21,
    BlockProgramZ = 22,
    RequestBodyZ = 23,
}

impl Tag {
    pub const fn from_u8(v: u8) -> Result<Tag, Error> {
        Ok(match v {
            1 => Tag::Hello,
            2 => Tag::HelloAck,
            3 => Tag::RequestHead,
            4 => Tag::Program,
            5 => Tag::BlockBytes,
            6 => Tag::BlockProgram,
            7 => Tag::Need,
            8 => Tag::Bloom,
            9 => Tag::ResponseHead,
            10 => Tag::ResponseBody,
            11 => Tag::ResponseEnd,
            12 => Tag::PeerStats,
            13 => Tag::Ping,
            14 => Tag::Pong,
            15 => Tag::Reset,
            16 => Tag::Cancel,
            17 => Tag::EndOfBody,
            18 => Tag::RequestBody,
            19 => Tag::Fail,
            20 => Tag::ProgramZ,
            21 => Tag::BlockBytesZ,
            22 => Tag::BlockProgramZ,
            23 => Tag::RequestBodyZ,
            other => return Err(Error::UnknownTag(other)),
        })
    }
}

/// Control frames share stream 0; everything else is per-request.
pub const CONTROL_STREAM: u64 = 0;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub tag: Tag,
    pub stream: u64,
    pub payload: Bytes,
}

impl Frame {
    pub fn new(tag: Tag, stream: u64, payload: impl Into<Bytes>) -> Self {
        Frame { tag, stream, payload: payload.into() }
    }

    pub fn control(tag: Tag, payload: impl Into<Bytes>) -> Self {
        Frame::new(tag, CONTROL_STREAM, payload)
    }

    /// `tag | stream | len | payload`, all integers uvarint.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.payload.len() + 18);
        out.push(self.tag as u8);
        write_uvarint(&mut out, self.stream);
        write_uvarint(&mut out, self.payload.len() as u64);
        out.extend_from_slice(&self.payload);
        out
    }

    /// On-wire size of a frame with this stream and payload length.
    pub const fn frame_len(stream: u64, payload_len: usize) -> usize {
        1 + varint_len(stream) + varint_len(payload_len as u64) + payload_len
    }

    pub fn decode(raw: &[u8]) -> Result<Frame, Error> {
        let mut r = Reader::new(raw);
        let tag_byte = r.take(1).map_err(|_| Error::Codec(CodecError::Eof(0)))?[0];
        let tag = Tag::from_u8(tag_byte)?;
        let stream = r.uvarint()?;
        let len = r.u64_as("frame length")?;
        if len > MAX_FRAME_PAYLOAD {
            return Err(Error::TooLarge(len));
        }
        let payload = Bytes::copy_from_slice(r.take(len)?);
        if r.remaining() != 0 {
            return Err(Error::Codec(CodecError::Bad("trailing frame bytes")));
        }
        Ok(Frame { tag, stream, payload })
    }
}

pub const fn varint_len(v: u64) -> usize {
    let mut n = 1;
    let mut x = v >> 7;
    while x != 0 {
        n += 1;
        x >>= 7;
    }
    n
}

/// Encode an instruction list.
///
/// `0x00 varint len bytes` for a literal run, `0x01 digest varint len` for a
/// reference - which is the cost model `muka_split` uses to decide whether a
/// split is worth anything at all.
pub fn encode_program(instrs: &[Instr]) -> Vec<u8> {
    let mut out = Vec::new();
    write_uvarint(&mut out, instrs.len() as u64);
    for i in instrs {
        match i {
            Instr::Lit(b) => {
                out.push(0u8);
                write_uvarint(&mut out, b.len() as u64);
                out.extend_from_slice(b);
            }
            Instr::Ref { digest, len } => {
                out.push(1u8);
                out.extend_from_slice(digest.as_bytes());
                write_uvarint(&mut out, *len);
            }
        }
    }
    out
}

pub fn decode_program(raw: &[u8], max_instrs: usize) -> Result<Vec<Instr>, Error> {
    let mut r = Reader::new(raw);
    let n = r.u64_as("instruction count")?;
    if n > max_instrs {
        return Err(Error::TooLarge(n));
    }
    let mut out = Vec::with_capacity(n.min(max_instrs));
    for _ in 0..n {
        let kind = r.take(1)?[0];
        match kind {
            0 => {
                let len = r.u64_as("literal length")?;
                if len > MAX_FRAME_PAYLOAD {
                    return Err(Error::TooLarge(len));
                }
                out.push(Instr::Lit(Bytes::copy_from_slice(r.take(len)?)));
            }
            1 => {
                let d = r.take(DIGEST_LEN)?;
                let mut arr = [0u8; DIGEST_LEN];
                arr.copy_from_slice(d);
                let len = r.uvarint()?;
                out.push(Instr::Ref { digest: Digest(arr), len });
            }
            _ => return Err(Error::Codec(CodecError::Bad("unknown instr tag"))),
        }
    }
    if r.remaining() != 0 {
        return Err(Error::Codec(CodecError::Bad("trailing program bytes")));
    }
    Ok(out)
}
pub fn encode_block_head(b: &Block) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.push(b.kind as u8);
    write_uvarint(&mut out, b.len);
    out
}

/// The frame tag carries the body shape, so only the header is shared.
pub fn decode_block_bytes(digest: Digest, raw: &[u8]) -> Result<Block, Error> {
    let mut r = Reader::new(raw);
    let kind = BlockKind::from_u8(r.take(1)?[0]).ok_or(Error::UnknownKind(0))?;
    let len = r.uvarint()?;
    let body = Bytes::copy_from_slice(r.rest());
    if body.len() as u64 != len {
        return Err(Error::Codec(CodecError::Bad("block length mismatch")));
    }
    Ok(Block::raw(digest, kind, body))
}

pub fn decode_block_program(digest: Digest, raw: &[u8], max_instrs: usize) -> Result<Block, Error> {
    let mut r = Reader::new(raw);
    let kind = BlockKind::from_u8(r.take(1)?[0]).ok_or(Error::UnknownKind(0))?;
    let len = r.uvarint()?;
    let instrs = decode_program(r.rest(), max_instrs)?;
    Ok(Block::program(digest, kind, len, instrs))
}

/// Marks a block whose body is a nested program, so one frame tag serves both
/// shapes without a length-prefix dance.
pub const PROG_MARK: u8 = 0xff;

/// `digest | [mark] kind | len | body`: a block always travels with its own
/// digest so the receiver can verify byte blocks before storing them.
pub fn encode_block_frame(b: &Block) -> Vec<u8> {
    let mut out = Vec::with_capacity(DIGEST_LEN + 12);
    out.extend_from_slice(b.digest.as_bytes());
    out.extend_from_slice(&encode_block_body(b));
    out
}

pub fn decode_block_frame(raw: &[u8], max_instrs: usize) -> Result<Block, Error> {
    if raw.len() < DIGEST_LEN + 2 {
        return Err(Error::Codec(CodecError::Bad("short block frame")));
    }
    let mut a = [0u8; DIGEST_LEN];
    a.copy_from_slice(&raw[..DIGEST_LEN]);
    let digest = Digest(a);
    let body = &raw[DIGEST_LEN..];
    if body.first() == Some(&PROG_MARK) {
        return decode_block_program(digest, &body[1..], max_instrs);
    }
    decode_block_bytes(digest, body)
}

pub fn encode_block_body(b: &Block) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + b.wire_cost() as usize);
    if matches!(b.body, BlockBody::Program(_)) {
        out.push(PROG_MARK);
    }
    out.push(b.kind as u8);
    write_uvarint(&mut out, b.len);
    match &b.body {
        BlockBody::Bytes(x) => out.extend_from_slice(x),
        BlockBody::Program(p) => out.extend_from_slice(&encode_program(p)),
    }
    out
}

/// The digest a block must have for its own raw bytes; the receiver re-checks
/// it, so a corrupt block can never poison a reconstructed request.
pub fn block_digest(b: &Block) -> Digest {
    match &b.body {
        BlockBody::Bytes(x) => muka_split::digest_of(b.kind, x),
        BlockBody::Program(_) => b.digest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use muka_split::{digest_of, BlockKind};

    fn instrs() -> Vec<Instr> {
        vec![
            Instr::Lit(Bytes::from_static(b"{\"a\":")),
            Instr::Ref { digest: Digest([7; DIGEST_LEN]), len: 4096 },
            Instr::Lit(Bytes::from_static(b"}")),
        ]
    }

    #[test]
    fn program_codec_roundtrips() {
        let i = instrs();
        let enc = encode_program(&i);
        assert_eq!(decode_program(&enc, 1000).unwrap(), i);
        // The split layer uses `program_wire_cost` to decide whether a split is
        // worth doing at all, so it must never understate the real encoding.
        let model = muka_split::program_wire_cost(&i) as usize;
        assert!(enc.len() <= model, "model understated: {enc:?} vs {model}");
        assert!(
            model - enc.len() <= 8,
            "model too loose to be useful: {enc:?} vs {model}"
        );
    }

    #[test]
    fn frame_codec_roundtrips() {
        for tag in [Tag::Hello, Tag::ResponseBody, Tag::Cancel, Tag::PeerStats] {
            let f = Frame::new(tag, 12345, Bytes::from_static(b"payload"));
            let back = Frame::decode(&f.encode()).unwrap();
            assert_eq!(back, f);
            assert_eq!(f.encode().len(), Frame::frame_len(12345, 7));
        }
        assert_eq!(Frame::decode(&[99, 0, 0]).unwrap_err(), Error::UnknownTag(99));
        let mut big = vec![Tag::ResponseBody as u8, 1, 0xf0, 0xff, 0xff, 0x7f];
        big.resize(10, 0);
        assert!(matches!(Frame::decode(&big), Err(Error::TooLarge(_))));
    }

    #[test]
    fn block_roundtrip_preserves_kind_and_length() {
        let data = Bytes::from_static(b"hello world");
        let d = digest_of(BlockKind::Media, &data);
        let b = Block::raw(d, BlockKind::Media, data.clone());
        assert_eq!(decode_block_frame(&encode_block_frame(&b), 100).unwrap(), b);

        let prog = Block::program(Digest([9; DIGEST_LEN]), BlockKind::JsonMember, 16, instrs());
        assert_eq!(decode_block_frame(&encode_block_frame(&prog), 100).unwrap(), prog);
        // a truncated frame must not decode into a wrong block
        let mut cut = encode_block_frame(&b);
        cut.truncate(cut.len() - 3);
        assert!(decode_block_frame(&cut, 100).is_err());
    }

    #[test]
    fn a_tampered_block_body_is_caught_by_the_digest() {
        let data = Bytes::from_static(b"original");
        let d = digest_of(BlockKind::Media, &data);
        let b = Block::raw(d, BlockKind::Media, data);
        let mut bad = b.clone();
        bad.body = BlockBody::Bytes(Bytes::from_static(b"tampered"));
        assert_ne!(block_digest(&bad), d);
        assert_eq!(block_digest(&b), d);
    }

    #[test]
    fn program_length_limits_hold() {
        let enc = encode_program(&instrs());
        assert_eq!(decode_program(&enc, 2).unwrap_err(), Error::TooLarge(3));
        assert!(matches!(decode_program(&[1], 10), Err(_)));
    }
}
