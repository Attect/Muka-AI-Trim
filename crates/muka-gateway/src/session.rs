//! The per-request protocol, both ends.
//!
//! One connection carries many requests, but only one at a time: that keeps the
//! framing free of multiplexing and flow-control windows while still letting
//! keep-alive remove a TCP (and TLS) round trip from every turn. Concurrency
//! comes from the connection pool, not from streams.
//!
//! ```text
//! local  -> remote   Hello, RequestHead, (Program | RequestBody)*, Block*, EndOfBody
//!                   [Block*, EndOfBody again after each Need], [Reset]
//! remote -> local   HelloAck, [Need | Fail | Reset], ResponseHead, ResponseBody*,
//!                   Bloom, ResponseEnd
//! ```
//!
//! Every rebuild is checked against the `body_digest` the sender declared
//! *before* anything goes upstream, so a protocol or cache bug can only cost a
//! retry - never a wrong prompt.

use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use bytes::Bytes;
use muka_proto::codec::{
    decode_block_frame, decode_program, encode_block_frame, encode_program, Frame, Tag,
};
use muka_proto::io::{read_frame, write_frame};
use muka_proto::msg::{
    decode_bloom, decode_needs, encode_bloom, encode_needs, Hello, HelloAck, PeerStats,
    RequestHead, ResponseEnd, ResponseHead, VERSION,
};
use muka_split::{digest_of, Block, BlockKind, Digest, Instr, Optimistic, Presence, SplitOutput, SplitStats};
use muka_store::{Bloom, Store};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::sync::{mpsc, RwLock};

use crate::metrics::Counters;

/// Largest program we accept, matched with the splitter's own guard.
pub const MAX_INSTRS: usize = 200_000;
/// Repair rounds before we give up and make the sender re-send the body whole.
pub const MAX_REPAIRS: u32 = 4;
/// Chunk size for verbatim bodies and response relay.
pub const RELAY_CHUNK: usize = 256 * 1024;
/// Body chunk size used when relaying an upstream response.
pub const MAX_BODY_BYTES: usize = 512 << 20;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Proto(#[from] muka_proto::Error),
    #[error("link closed before the response finished")]
    LinkClosed,
    #[error("peer rejected the handshake: {0}")]
    Rejected(String),
    #[error("peer wants the body sent whole: {0}")]
    SendWhole(String),
    #[error("rebuild failed after {0} repair rounds")]
    Unrebuildable(u32),
    #[error("rebuilt body does not match the declared digest")]
    DigestMismatch,
    #[error("malformed payload: {0}")]
    BadPayload(String),
    #[error("io: {0}")]
    Io(String),
    #[error(transparent)]
    Compress(#[from] muka_proto::CompressError),
}

impl From<io::Error> for SessionError {
    fn from(e: io::Error) -> Self {
        SessionError::Io(e.to_string())
    }
}

/// True for errors where re-sending the body verbatim is the right recovery.
impl SessionError {
    pub fn fallback_to_whole(&self) -> bool {
        matches!(
            self,
            SessionError::SendWhole(_)
                | SessionError::Rejected(_)
                | SessionError::Unrebuildable(_)
                | SessionError::DigestMismatch
                | SessionError::LinkClosed
                | SessionError::Io(_)
                | SessionError::Proto(_)
        )
    }
}

/// Why the peer could not rebuild. Sent as `Fail` so the sender can retry whole
/// instead of the agent seeing a broken request.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Fail {
    pub reason: String,
    /// Ask the sender to drop its optimistic view (peer restarted or evicted).
    #[serde(default)]
    pub clear_presence: bool,
}

/// `tag | stream | len` costs up to 12 bytes; good enough for wire accounting
/// and cheap enough to do on every frame.
pub const fn frame_charge(f: &Frame) -> u64 {
    (f.payload.len() + 12) as u64
}

pub fn json_frame(tag: Tag, stream: u64, v: &impl Serialize) -> Frame {
    match serde_json::to_vec(v) {
        Ok(payload) => Frame::new(tag, stream, Bytes::from(payload)),
        Err(_) => Frame::new(tag, stream, Bytes::new()),
    }
}

pub fn json_of<T: serde::de::DeserializeOwned>(f: &Frame) -> Result<T, SessionError> {
    serde_json::from_slice(&f.payload).map_err(|e| SessionError::BadPayload(e.to_string()))
}

/// A body prepared for one request.
pub enum Payload {
    Split(SplitOutput),
    Whole(Bytes),
}

impl Payload {
    pub const fn is_split(&self) -> bool {
        matches!(self, Payload::Split(_))
    }

    pub fn stats(&self) -> Option<&SplitStats> {
        match self {
            Payload::Split(o) => Some(&o.stats),
            Payload::Whole(_) => None,
        }
    }
}

/// One socket, already split and type-erased, kept warm across requests.
///
/// Erased so a plain `TcpStream` and a `TlsStream<TcpStream>` share every code
/// path - the protocol must not care which transport it is on.
pub struct Conn {
    pub r: BufReader<Box<dyn AsyncRead + Unpin + Send>>,
    pub w: Box<dyn AsyncWrite + Unpin + Send>,
    pub id: u64,
    pub requests: u64,
    /// Bytes we have put on the link through this connection.
    pub sent: u64,
}

impl Conn {
    pub fn new<S>(sock: S, id: u64) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (r, w) = tokio::io::split(sock);
        Conn { r: BufReader::new(Box::new(r)), w: Box::new(w), id, requests: 0, sent: 0 }
    }
}

/// Bloom the peer last reported, shared between requests.
#[derive(Clone, Default)]
pub struct SharedBloom {
    inner: Arc<RwLock<Bloom>>,
}

impl SharedBloom {
    pub fn new(b: Bloom) -> Self {
        SharedBloom { inner: Arc::new(RwLock::new(b)) }
    }

    pub async fn replace(&self, b: Bloom) {
        *self.inner.write().await = b;
    }

    /// Forget the peer's membership outright. An empty filter answers "not
    /// here" for everything, which is the only safe belief after either cache
    /// was cleared: it costs a re-push, never a block the peer cannot resolve.
    pub async fn clear(&self) {
        *self.inner.write().await = Bloom::empty();
    }
}

impl Presence for SharedBloom {
    fn has(&self, d: &Digest) -> bool {
        // `Presence::has` is synchronous and called from the splitter; the
        // bloom is only swapped between requests, so contention means "unknown"
        // - which costs one re-push and can never corrupt a request.
        self.inner.try_read().map(|g| g.has(d)).unwrap_or(false)
    }
}

/// Everything the local end needs across requests.
pub struct LinkState {
    pub store: Arc<Store>,
    pub presence: Arc<Optimistic>,
    pub bloom: Arc<SharedBloom>,
    pub counters: Arc<Counters>,
    pub peer_name: String,
    /// Compress the upload side of the link (never the token stream back).
    pub compress: bool,
    /// Proof of the shared secret. Static by design for v0: it stops a
    /// random port scanner, not a wire tapper - the link itself must be TLS
    /// (or an SSH tunnel) before real prompts go over it.
    pub proof: String,
}

/// Local end: push one request, relay one response.
///
/// Returns once the response is complete; body chunks leave on `body_tx` as
/// they arrive and the head is handed over `head_tx` first.
///
/// `head_sent` is set as soon as the response head has gone to the agent: after
/// that a retry would duplicate output, so errors have to surface instead.
pub async fn local_end(
    conn: &mut Conn,
    head: &RequestHead,
    payload: &Payload,
    st: &LinkState,
    body_tx: mpsc::Sender<Result<Bytes, io::Error>>,
    head_tx: mpsc::Sender<ResponseHead>,
    head_sent: Arc<AtomicBool>,
) -> Result<ResponseEnd, SessionError> {
    let stream = conn.id;
    let mut wire = 0u64;
    conn.requests += 1;
    if conn.requests == 1 {
        let hello = Hello {
            version: VERSION,
            peer_name: st.peer_name.clone(),
            proof: st.proof.clone(),
            blocks: st.store.stats().blocks,
        };
        let f = json_frame(Tag::Hello, 0, &hello);
        wire += frame_charge(&f);
        write_frame(&mut conn.w, &f).await?;
    }

    // The head has to describe the payload actually on the wire: a request that
    // failed to rebuild is re-sent whole on the next attempt, and a stale
    // `split: true` would make the peer resolve an empty program instead of
    // reading the body frames.
    let mut head = head.clone();
    head.split = payload.is_split();
    let f = json_frame(Tag::RequestHead, stream, &head);
    wire += frame_charge(&f);
    write_frame(&mut conn.w, &f).await?;

    let mut pushed = Vec::new();
    match payload {
        Payload::Split(out) => {
            let f = upload_frame(Tag::Program, stream, encode_program(&out.instrs), st.compress);
            wire += frame_charge(&f);
            write_frame(&mut conn.w, &f).await?;
            for b in &out.to_push {
                let f = block_frame(b, stream, st.compress);
                wire += frame_charge(&f);
                pushed.push(b.digest);
                write_frame(&mut conn.w, &f).await?;
            }
        }
        Payload::Whole(body) => {
            for chunk in body.chunks(RELAY_CHUNK) {
                let f = upload_frame(Tag::RequestBody, stream, chunk.to_vec(), st.compress);
                wire += frame_charge(&f);
                write_frame(&mut conn.w, &f).await?;
            }
        }
    }
    let f = Frame::new(Tag::EndOfBody, stream, Bytes::new());
    wire += frame_charge(&f);
    write_frame(&mut conn.w, &f).await?;
    conn.sent += wire;
    // We believe the peer has what we just pushed. If that guess is wrong the
    // `Need` path repairs it, so the only cost is a re-push.
    st.presence.note_pushed(pushed);

    let mut repairs = 0u32;
    loop {
        let Some(f) = read_frame(&mut conn.r).await? else {
            st.counters.link_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(SessionError::LinkClosed);
        };
        match f.tag {
            Tag::HelloAck => {
                let a: HelloAck = json_of(&f)?;
                if !a.ok {
                    return Err(SessionError::Rejected(a.reason.unwrap_or_else(|| "no reason given".into())));
                }
                if a.blocks == 0 && a.epoch != 0 {
                    st.presence.clear();
                }
            }
            Tag::Need => {
                repairs += 1;
                if repairs > MAX_REPAIRS {
                    return Err(SessionError::Unrebuildable(repairs - 1));
                }
                let need = decode_needs(&f.payload, MAX_INSTRS)?;
                let mut resent = 0u64;
                for d in need {
                    if let Some(b) = st.store.get(&d) {
                        let f = block_frame(&b, stream, st.compress);
                        wire += frame_charge(&f);
                        write_frame(&mut conn.w, &f).await?;
                        resent += 1;
                    }
                }
                let f = Frame::new(Tag::EndOfBody, stream, Bytes::new());
                wire += frame_charge(&f);
                write_frame(&mut conn.w, &f).await?;
                st.counters.repairs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::debug!(resent, "peer re-asked for blocks");
            }
            Tag::Fail => {
                let fail: Fail = json_of(&f)?;
                if fail.clear_presence {
                    st.presence.clear();
                }
                return Err(SessionError::SendWhole(fail.reason));
            }
            Tag::Reset => {
                st.presence.clear();
                return Err(SessionError::SendWhole("peer reset".into()));
            }
            Tag::Bloom => {
                let (_, _, b) = decode_bloom(&f.payload)?;
                st.bloom.replace(b).await;
            }
            Tag::ResponseHead => {
                let h: ResponseHead = json_of(&f)?;
                if head_tx.send(h).await.is_err() {
                    return Err(SessionError::LinkClosed);
                }
                head_sent.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            Tag::ResponseBody => {
                st.counters.response_bytes.fetch_add(f.payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
                if body_tx.send(Ok(f.payload.clone())).await.is_err() {
                    return Err(SessionError::LinkClosed);
                }
            }
            Tag::ResponseEnd => {
                let mut e: ResponseEnd = json_of(&f)?;
                e.wire_bytes = wire;
                e.body_bytes = e.body_bytes.max(head.body_len);
                e.repairs = repairs;
                if e.body_bytes == 0 {
                    e.body_bytes = head.body_len;
                }
                record_turn(&st.counters, &e, &payload);
                break Ok(e);
            }
            Tag::PeerStats => {
                let s: PeerStats = json_of(&f)?;
                tracing::debug!(?s, "peer counters");
            }
            Tag::Ping => {
                write_frame(&mut conn.w, &Frame::control(Tag::Pong, Bytes::new())).await?;
            }
            other => {
                tracing::warn!(?other, "ignoring unexpected frame from peer");
            }
        }
    }
}

fn record_turn(c: &Counters, e: &ResponseEnd, payload: &Payload) {
    use std::sync::atomic::Ordering::Relaxed;
    c.requests.fetch_add(1, Relaxed);
    c.body_bytes.fetch_add(e.body_bytes, Relaxed);
    c.wire_bytes.fetch_add(e.wire_bytes, Relaxed);
    c.upstream_us.fetch_add(e.upstream_us, Relaxed);
    c.repairs.fetch_add(u64::from(e.repairs), Relaxed);
    match payload {
        Payload::Split(_) => {
            c.split_requests.fetch_add(1, Relaxed);
            if let Some(s) = payload.stats() {
                c.refs.fetch_add(u64::from(s.refs), Relaxed);
                c.refs_hit.fetch_add(u64::from(s.refs_hit), Relaxed);
                c.blocks_pushed.fetch_add(u64::from(s.push_blocks), Relaxed);
            }
        }
        Payload::Whole(_) => {
            c.passthrough.fetch_add(1, Relaxed);
        }
    }
}

pub fn block_frame(b: &Block, stream: u64, compress: bool) -> Frame {
    let tag = match b.body {
        muka_split::BlockBody::Bytes(_) => Tag::BlockBytes,
        muka_split::BlockBody::Program(_) => Tag::BlockProgram,
    };
    upload_frame(tag, stream, encode_block_frame(b), compress)
}

/// The tags that mean "this payload is a zstd frame". Upload only, so the
/// response path is never made to wait on a compressed block boundary.
pub const fn compressed_tag(tag: Tag) -> Tag {
    match tag {
        Tag::Program => Tag::ProgramZ,
        Tag::BlockBytes => Tag::BlockBytesZ,
        Tag::BlockProgram => Tag::BlockProgramZ,
        Tag::RequestBody => Tag::RequestBodyZ,
        other => other,
    }
}

/// Inverse of [`compressed_tag`]: the tag to process and whether to inflate.
pub const fn plain_tag(tag: Tag) -> (Tag, bool) {
    match tag {
        Tag::ProgramZ => (Tag::Program, true),
        Tag::BlockBytesZ => (Tag::BlockBytes, true),
        Tag::BlockProgramZ => (Tag::BlockProgram, true),
        Tag::RequestBodyZ => (Tag::RequestBody, true),
        other => (other, false),
    }
}

pub fn upload_frame(tag: Tag, stream: u64, payload: Vec<u8>, compress: bool) -> Frame {
    if compress {
        if let Some(z) = muka_proto::zstd_compress(&payload) {
            return Frame::new(compressed_tag(tag), stream, Bytes::from(z));
        }
    }
    Frame::new(tag, stream, Bytes::from(payload))
}

/// Payload of an upload frame, inflated if the tag says so.
pub fn plain_payload(f: &Frame) -> Result<(Tag, Bytes), SessionError> {
    let (tag, packed) = plain_tag(f.tag);
    if !packed {
        return Ok((tag, f.payload.clone()));
    }
    Ok((tag, Bytes::from(muka_proto::zstd_decompress(&f.payload)?)))
}

/// What a rebuilt request looks like to whoever performs the upstream call.
pub struct Rebuilt {
    pub head: RequestHead,
    pub body: Bytes,
    pub rebuild_us: u64,
}

/// Remote end: serve requests from one connection until it closes.
pub async fn remote_end<Fut, F>(
    mut conn: Conn,
    store: Arc<Store>,
    counters: Arc<Counters>,
    epoch: u64,
    proof: Option<String>,
    mut forward: F,
) -> Result<(), SessionError>
where
    F: FnMut(Rebuilt) -> Fut,
    Fut: std::future::Future<Output = Result<(ResponseHead, mpsc::Receiver<Result<Bytes, io::Error>>), SessionError>>,
{
    let mut head: Option<RequestHead> = None;
    let mut instrs: Vec<Instr> = Vec::new();
    let mut literal: Vec<u8> = Vec::new();
    let mut wire_in = 0u64;
    let mut greeted = false;
    let mut started = std::time::Instant::now();

    loop {
        let Some(f) = read_frame(&mut conn.r).await? else { return Ok(()) };
        wire_in += frame_charge(&f);
        match f.tag {
            Tag::Hello => {
                let h: Hello = json_of(&f)?;
                let bad = if h.version != VERSION {
                    Some(format!("protocol version {} != {VERSION}", h.version))
                } else if let Some(expected) = &proof {
                    (h.proof != *expected).then(|| "bad pairing proof".to_string())
                } else {
                    None
                };
                let s = store.stats();
                let ack = HelloAck {
                    version: VERSION,
                    ok: bad.is_none(),
                    reason: bad.clone(),
                    blocks: s.blocks,
                    epoch,
                };
                write_frame(&mut conn.w, &json_frame(Tag::HelloAck, 0, &ack)).await?;
                if let Some(reason) = bad {
                    return Err(SessionError::Rejected(reason));
                }
                greeted = true;
            }
            Tag::RequestHead => {
                started = std::time::Instant::now();
                if !greeted && proof.is_some() {
                    return Err(SessionError::Rejected("request before handshake".into()));
                }
                head = Some(json_of(&f)?);
                counters.requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            Tag::Program | Tag::ProgramZ | Tag::RequestBody | Tag::RequestBodyZ | Tag::BlockBytes | Tag::BlockBytesZ | Tag::BlockProgram | Tag::BlockProgramZ => {
                let (tag, payload) = plain_payload(&f)?;
                match tag {
                    Tag::Program => {
                        instrs = decode_program(&payload, MAX_INSTRS)?;
                    }
                    Tag::RequestBody => {
                        if literal.len() + payload.len() > MAX_BODY_BYTES {
                            return Err(SessionError::BadPayload("body too large".into()));
                        }
                        literal.extend_from_slice(&payload);
                    }
                    _ => {
                        let b = decode_block_frame(&payload, MAX_INSTRS)?;
                        let d = b.digest;
                        if store.has(&d) {
                            store.touch(&d);
                        } else if !store.insert(b) {
                            counters.io_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
            }
            Tag::EndOfBody => {
                let Some(h) = head.clone() else {
                    return Err(SessionError::SendWhole("head never arrived".into()));
                };
                let stream = f.stream;
                let mut repairs = 0u32;
                let body = loop {
                    match rebuild(&store, &h, &instrs, &mut literal, &counters) {
                        Ok(b) => break b,
                        Err(RebuildError::Missing(digs)) => {
                            repairs += 1;
                            if repairs > MAX_REPAIRS {
                                let _ = write_frame(&mut conn.w, &json_frame(Tag::Fail, stream, &Fail { reason: "too many repairs".into(), clear_presence: true })).await;
                                return Err(SessionError::Unrebuildable(repairs - 1));
                            }
                            counters.repairs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            write_frame(&mut conn.w, &Frame::new(Tag::Need, stream, Bytes::from(encode_needs(&digs)))).await?;
                            // Read the re-pushed blocks.
                            loop {
                                let Some(g) = read_frame(&mut conn.r).await? else {
                                    return Err(SessionError::LinkClosed);
                                };
                                wire_in += frame_charge(&g);
                                match g.tag {
                                    Tag::BlockBytes | Tag::BlockBytesZ | Tag::BlockProgram | Tag::BlockProgramZ => {
                                        let (_, payload) = plain_payload(&g)?;
                                        let b = decode_block_frame(&payload, MAX_INSTRS)?;
                                        let d = b.digest;
                                        if !store.has(&d) {
                                            store.insert(b);
                                        }
                                    }
                                    Tag::EndOfBody => break,
                                    other => {
                                        return Err(SessionError::BadPayload(format!("unexpected {other:?} during repair")));
                                    }
                                }
                            }
                        }
                        Err(RebuildError::Mismatch) => {
                            counters.rebuild_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let _ = write_frame(&mut conn.w, &json_frame(Tag::Fail, stream, &Fail { reason: "digest mismatch".into(), clear_presence: false })).await;
                            return Err(SessionError::DigestMismatch);
                        }
                    }
                };

                let rebuild_us = started.elapsed().as_micros() as u64;
                counters.rebuilds.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let at = std::time::Instant::now();
                let (mut resp_head, mut rx) = forward(Rebuilt { head: h.clone(), body, rebuild_us }).await?;
                let upstream_us = at.elapsed().as_micros() as u64;
                resp_head.rebuild_us = rebuild_us;
                write_frame(&mut conn.w, &json_frame(Tag::ResponseHead, stream, &resp_head)).await?;
                while let Some(chunk) = rx.recv().await {
                    let chunk = chunk?;
                    let f = Frame::new(Tag::ResponseBody, stream, chunk);
                    write_frame(&mut conn.w, &f).await?;
                }
                let s = store.stats();
                write_frame(&mut conn.w, &Frame::new(Tag::Bloom, 0, Bytes::from(encode_bloom(epoch, s.blocks, &store.bloom())))).await?;
                let end = ResponseEnd {
                    wire_bytes: wire_in,
                    body_bytes: h.body_len,
                    upstream_us,
                    stats: None,
                    repairs,
                    store_blocks: s.blocks,
                    store_bytes: s.bytes,
                };
                write_frame(&mut conn.w, &json_frame(Tag::ResponseEnd, stream, &end)).await?;
                wire_in = 0;
                instrs.clear();
                head = None;
            }
            Tag::Ping => {
                write_frame(&mut conn.w, &Frame::control(Tag::Pong, Bytes::new())).await?;
            }
            Tag::Reset => {
                // The agent side wants us to really forget, otherwise its reset
                // only re-pushes into a store that already has the blocks. No
                // reply: the next response carries a fresh bloom regardless.
                let dropped = store.clear();
                tracing::info!(dropped, "peer cache cleared on request");
            }
            other => {
                tracing::warn!(?other, "unexpected frame on peer side");
            }
        }
    }
}

enum RebuildError {
    Missing(Vec<Digest>),
    Mismatch,
}

fn rebuild(
    store: &Store,
    head: &RequestHead,
    instrs: &[Instr],
    literal: &mut Vec<u8>,
    _counters: &Counters,
) -> Result<Bytes, RebuildError> {
    let body = if head.split {
        let missing = muka_split::missing_blocks(store, &StorePresence(store), instrs, MAX_INSTRS);
        if !missing.is_empty() {
            return Err(RebuildError::Missing(missing));
        }
        match muka_split::resolve(store, instrs, head.body_len as usize + 1, 32) {
            Ok(b) => b,
            Err(muka_split::ResolveError::Missing(d)) => return Err(RebuildError::Missing(vec![d])),
            Err(_) => return Err(RebuildError::Mismatch),
        }
    } else {
        Bytes::from(std::mem::take(literal))
    };
    if body.len() as u64 != head.body_len || digest_of(BlockKind::Raw, &body) != head.body_digest {
        return Err(RebuildError::Mismatch);
    }
    Ok(body)
}

struct StorePresence<'a>(&'a Store);

impl Presence for StorePresence<'_> {
    fn has(&self, d: &Digest) -> bool {
        self.0.has(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use muka_split::Block;

    fn head(body: &[u8], split: bool) -> RequestHead {
        RequestHead {
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers: vec![("content-type".into(), "application/json".into())],
            body_len: body.len() as u64,
            body_digest: digest_of(BlockKind::Raw, body),
            kind: muka_proto::msg::Kind::ChatCompletions,
            split,
        }
    }

    #[test]
    fn fail_and_json_frames_roundtrip() {
        let f = json_frame(Tag::Fail, 3, &Fail { reason: "x".into(), clear_presence: true });
        let back: Fail = json_of(&f).unwrap();
        assert!(back.clear_presence);
        assert!(json_of::<Fail>(&Frame::new(Tag::Fail, 3, Bytes::from_static(b"nope"))).is_err());
    }

    #[test]
    fn needs_and_bloom_use_the_real_codec() {
        let digs = vec![digest_of(BlockKind::Media, b"a"), digest_of(BlockKind::Media, b"b")];
        assert_eq!(decode_needs(&encode_needs(&digs), 100).unwrap(), digs);
        assert!(decode_needs(&encode_needs(&digs), 1).is_err());

        let mut b = Bloom::new(2000, 6);
        for i in 0..300u64 {
            b.add(&digest_of(BlockKind::JsonMember, &i.to_le_bytes()));
        }
        let (epoch, blocks, back) = decode_bloom(&encode_bloom(7, 300, &b)).unwrap();
        assert_eq!((epoch, blocks), (7, 300));
        assert!(b.to_bytes().len() < 10_000, "bloom must stay piggyback-sized");
        assert!(back.has(&digest_of(BlockKind::JsonMember, &1u64.to_le_bytes())));
    }

    #[tokio::test]
    async fn a_split_request_survives_the_protocol_end_to_end() {
        use std::sync::atomic::AtomicBool;
        use muka_split::Instr;

        let store_l = Arc::new(Store::new(muka_store::Config::default()));
        let store_r = Arc::new(Store::new(muka_store::Config::default()));
        let counters = Arc::new(Counters::default());

        // A body whose single message is a block only the *local* store has:
        // the remote must ask for it, and rebuild byte-for-byte afterwards.
        let msg = b"{\"role\":\"user\",\"content\":\"hello there friend\"}".to_vec();
        let md = digest_of(BlockKind::JsonMember, &msg);
        store_l.insert(Block::raw(md, BlockKind::JsonMember, Bytes::from(msg.clone())));
        let body: Vec<u8> = [
            b"{\"messages\":[".as_slice(),
            &msg,
            b"]}".as_slice(),
        ]
        .concat();
        let instrs = vec![
            Instr::Lit(Bytes::from_static(b"{\"messages\":[")),
            Instr::Ref { digest: md, len: msg.len() as u64 },
            Instr::Lit(Bytes::from_static(b"]}")),
        ];
        let h = head(&body, true);
        assert_eq!(body.len(), 13 + msg.len() + 2, "fixture arithmetic");

        let out = SplitOutput {
            instrs,
            to_push: Vec::new(),
            stats: SplitStats {
                body_len: body.len() as u64,
                refs: 1,
                ref_covered: msg.len() as u64,
                ..Default::default()
            },
        };
        let (a, b) = tokio::io::duplex(1 << 20);
        let mut conn_l = Conn::new(a, 1);
        let st = LinkState {
            store: store_l.clone(),
            presence: Arc::new(Optimistic::new(Box::new(SharedBloom::default()))),
            bloom: Arc::new(SharedBloom::default()),
            counters: counters.clone(),
            peer_name: "test".into(),
            proof: String::new(),
            // Deliberately on: this test must exercise the inflate path too.
            compress: true,
        };
        // `to_push` is empty on purpose: this is the case the design guesses
        // wrong about - the sender believed the peer already had the block (its
        // optimistic view after an earlier turn), and the peer has since lost
        // it. The `Need` repair path is what makes that guess safe.
        st.presence.clear();
        let (body_tx, mut body_rx) = mpsc::channel(4);
        let (head_tx, mut head_rx) = mpsc::channel(1);
        let head_sent = Arc::new(AtomicBool::new(false));
        let hb = h.clone();
        let payload = Payload::Split(out);
        let lw = tokio::spawn(async move {
            local_end(&mut conn_l, &hb, &payload, &st, body_tx, head_tx, head_sent).await
        });
        let store_r_moved = store_r.clone();
        let expect = body.clone();
        let rc = counters.clone();
        let store_for_check = store_r.clone();
        let store_after = store_r.clone();
        let md_for_check = md;
        let rw = tokio::spawn(async move {
            remote_end(Conn::new(b, 1), store_r_moved, rc, 3, None, move |rb: Rebuilt| {
                let want = expect.clone();
                let store = store_for_check.clone();
                async move {
                    assert_eq!(&rb.body[..], &want[..], "rebuilt body must be byte-identical");
                    assert!(store.has(&md_for_check), "the block had to arrive");
                    let (tx, rx) = mpsc::channel(2);
                    tx.send(Ok(Bytes::from_static(b"data: [DONE]

"))).await.unwrap();
                    drop(tx);
                    Ok((
                        ResponseHead {
                            status: 200,
                            headers: vec![("content-type".into(), "text/event-stream".into())],
                            content_length: None,
                            rebuild_us: rb.rebuild_us,
                        },
                        rx,
                    ))
                }
            })
            .await
        });
        let resp_head = head_rx.recv().await.expect("a response head");
        assert_eq!(resp_head.status, 200);
        let chunk = body_rx.recv().await.unwrap().unwrap();
        assert_eq!(chunk, Bytes::from_static(b"data: [DONE]

"));
        let end = lw.await.unwrap().expect("local end");
        rw.await.unwrap().expect("remote end");

        // Two frames of program + one block + head, and nothing else: the whole
        // 60-byte body never went out verbatim.
        assert!(end.wire_bytes < 600, "wire {} bytes", end.wire_bytes);
        assert!(end.repairs >= 1, "the missing block must have been re-asked for");
        assert_eq!(counters.rebuilds.load(std::sync::atomic::Ordering::Relaxed), 1);
        // One process holds both ends here, so this counter adds the peer's
        // "I need it" (1), the sender's re-push (1) and the turn record (1).
        assert_eq!(counters.repairs.load(std::sync::atomic::Ordering::Relaxed), 3);
        // The peer now holds the block, so a second turn needs no repair.
        assert!(store_after.has(&md));
    }

    #[test]
    fn frame_charge_covers_the_header() {
        let f = Frame::new(Tag::Program, 1, Bytes::from(vec![0u8; 100]));
        assert_eq!(f.encode().len() as u64, 100 + 3);
        assert!(frame_charge(&f) >= f.encode().len() as u64);
    }
}
