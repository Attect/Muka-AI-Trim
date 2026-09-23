//! Async frame IO.

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::codec::{Error, Frame, MAX_FRAME_PAYLOAD};
use crate::varint::CodecError;

/// Write one frame. Returns `Error::Io` on a broken link.
pub async fn write_frame<W>(w: &mut W, f: &Frame) -> Result<(), Error>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut hdr = [0u8; 12];
    hdr[0] = f.tag as u8;
    let mut n = 1usize;
    write_varint_into(&mut hdr, &mut n, f.stream);
    write_varint_into(&mut hdr, &mut n, f.payload.len() as u64);
    w.write_all(&hdr[..n]).await.map_err(|e| Error::Io(e.to_string()))?;
    w.write_all(&f.payload).await.map_err(|e| Error::Io(e.to_string()))?;
    w.flush().await.map_err(|e| Error::Io(e.to_string()))?;
    Ok(())
}

fn write_varint_into(dst: &mut [u8; 12], at: &mut usize, v: u64) {
    let mut x = v;
    loop {
        let byte = (x & 0x7f) as u8;
        x >>= 7;
        dst[*at] = if x == 0 { byte } else { byte | 0x80 };
        *at += 1;
        if x == 0 {
            return;
        }
    }
}

/// Read one frame, or `Ok(None)` on a clean EOF between frames.
pub async fn read_frame<R>(r: &mut R) -> Result<Option<Frame>, Error>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut one = [0u8; 1];
    match r.read_exact(&mut one).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(Error::Io(e.to_string())),
    }
    let tag = crate::codec::Tag::from_u8(one[0])?;
    let stream = read_varint(r).await?;
    let len = read_varint(r).await?;
    if len > MAX_FRAME_PAYLOAD as u64 {
        return Err(Error::TooLarge(len as usize));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).await.map_err(|e| Error::Io(e.to_string()))?;
    Ok(Some(Frame { tag, stream, payload: Bytes::from(payload) }))
}

async fn read_varint<R>(r: &mut R) -> Result<u64, Error>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut out: u64 = 0;
    for i in 0..10 {
        let mut one = [0u8; 1];
        r.read_exact(&mut one).await.map_err(|e| Error::Io(e.to_string()))?;
        let b = one[0];
        let shifted = (b & 0x7f) as u64;
        out = out
            .checked_add(shifted.checked_shl(7 * i).ok_or(Error::Codec(CodecError::VarintTooLong))?)
            .ok_or(Error::Codec(CodecError::VarintTooLong))?;
        if b & 0x80 == 0 {
            return Ok(out);
        }
    }
    Err(Error::Codec(CodecError::VarintTooLong))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Tag;
    use tokio::io::duplex;

    #[tokio::test]
    async fn frames_survive_a_duplex_pipe() {
        let (mut a, mut b) = duplex(4096);
        let frames = [
            Frame::control(Tag::Ping, Bytes::from_static(b"")),
            Frame::new(Tag::ResponseBody, 7, Bytes::from_static(b"data: {\"x\":1}\n\n")),
            Frame::new(Tag::BlockBytes, 1 << 40, Bytes::from(vec![9u8; 300_000])),
        ];
        let tx = frames.to_vec();
        let writer = tokio::spawn(async move {
            for f in &tx[..] {
                write_frame(&mut a, f).await.unwrap();
            }
        });
        for expected in &frames {
            let got = read_frame(&mut b).await.unwrap().expect("a frame");
            assert_eq!(&got, expected);
        }
        writer.await.unwrap();
        assert!(read_frame(&mut b).await.unwrap().is_none(), "clean EOF");
    }

    #[tokio::test]
    async fn oversized_frames_are_refused() {
        let (mut a, mut b) = duplex(64);
        tokio::spawn(async move {
            // tag, stream, then a length varint claiming 1 GB
            let bytes = [Tag::BlockBytes as u8, 0x00, 0x80, 0x80, 0x80, 0x80, 0x04];
            let _ = a.write_all(&bytes).await;
            let _ = a.flush().await;
        });
        assert!(matches!(
            read_frame(&mut b).await,
            Err(Error::TooLarge(_))
        ));
    }
}
