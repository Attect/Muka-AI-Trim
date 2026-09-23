//! Unsigned LEB128 varints, with a bounded reader.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CodecError {
    #[error("varint longer than 10 bytes")]
    VarintTooLong,
    #[error("value {0} does not fit")]
    Overflow(&'static str),
    #[error("unexpected end of input at {0}")]
    Eof(usize),
    #[error("malformed input: {0}")]
    Bad(&'static str),
}

pub fn write_uvarint(buf: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            buf.push(byte);
            return;
        }
        buf.push(byte | 0x80);
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub const fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn uvarint(&mut self) -> Result<u64, CodecError> {
        let mut out: u64 = 0;
        for i in 0..10 {
            let b = *self.buf.get(self.pos).ok_or(CodecError::Eof(self.pos))?;
            self.pos += 1;
            let shifted = (b & 0x7f) as u64;
            out = out
                .checked_add(shifted.checked_shl(7 * i).ok_or(CodecError::VarintTooLong)?)
                .ok_or(CodecError::VarintTooLong)?;
            if b & 0x80 == 0 {
                return Ok(out);
            }
        }
        Err(CodecError::VarintTooLong)
    }

    pub fn u64_as(&mut self, what: &'static str) -> Result<usize, CodecError> {
        let v = self.uvarint()?;
        usize::try_from(v).map_err(|_| CodecError::Overflow(what))
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if self.remaining() < n {
            return Err(CodecError::Eof(self.pos));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrips_at_boundaries() {
        for v in [0u64, 1, 127, 128, 16383, 16384, u32::MAX as u64, u64::MAX] {
            let mut buf = Vec::new();
            write_uvarint(&mut buf, v);
            let mut r = Reader::new(&buf);
            assert_eq!(r.uvarint().unwrap(), v, "value {v}");
            assert_eq!(r.remaining(), 0);
        }
    }

    #[test]
    fn truncated_and_oversized_inputs_are_rejected() {
        let mut r = Reader::new(&[0x80]);
        assert_eq!(r.uvarint(), Err(CodecError::Eof(1)));
        let mut r = Reader::new(&[0xff; 11]);
        assert_eq!(r.uvarint(), Err(CodecError::VarintTooLong));
        let mut r = Reader::new(b"ab");
        assert!(matches!(r.take(3), Err(CodecError::Eof(_))));
        assert_eq!(r.take(2).unwrap(), b"ab");
    }

    #[test]
    fn small_values_use_one_byte() {
        let mut buf = Vec::new();
        write_uvarint(&mut buf, 127);
        assert_eq!(buf.len(), 1);
        let mut buf = Vec::new();
        write_uvarint(&mut buf, 128);
        assert_eq!(buf.len(), 2);
    }
}
