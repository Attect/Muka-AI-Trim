//! The agent-facing end: an HTTP/1.1 listener that splits requests and pushes
//! them at the peer, relaying the upstream answer as a stream.

use std::collections::HashMap;
use std::convert::Infallible;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use muka_proto::codec::{Frame, Tag};
use muka_proto::io::write_frame;
use muka_proto::msg::{classify, RequestHead, ResponseEnd, ResponseHead, Kind};
use muka_split::{digest_of, split_body, Action, Ctx, Optimistic};
use muka_split::{BlockKind, Policy};
use muka_store::Store;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;

use crate::config::{Config, LocalConfig, Role};
use crate::metrics::{Counters, Turn, TurnLog};
use crate::session::{local_end, Conn, LinkState, Payload, SessionError, SharedBloom};

/// Hop-by-hop and framing headers that must not be relayed.
pub const DROP_REQUEST: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "host",
    "expect",
];
pub const DROP_RESPONSE: &[&str] =
    &["connection", "keep-alive", "transfer-encoding", "content-length"];

/// Boxed error the HTTP body types carry.
pub type BoxErr = Box<dyn std::error::Error + Send + Sync>;

/// A complete body. `Full` cannot fail, so the error arm is unreachable.
pub fn full(data: impl Into<Bytes>) -> Body {
    Body::new(Full::new(data.into()).map_err(|e| match e {}))
}
/// One boxed body type for everything this end answers with.
pub type Body = BoxBody<Bytes, BoxErr>;

/// State shared by every profile in this process: one cache, one ledger. The
/// peer differs per profile; blocks do not, because they are named by their
/// content - a screenshot two agents share is pushed to the peer once.
pub struct Hub {
    pub cfg: Arc<Config>,
    pub store: Arc<Store>,
    pub counters: Arc<Counters>,
    pub turns: Arc<TurnLog>,
    /// Live-switchable from the console; `profile.shadow` is the startup value.
    shadow: AtomicBool,
    /// Profiles that dial the same peer share their idea of what it holds,
    /// otherwise the second listener would re-upload blocks the peer already
    /// has and one cache would stop meaning anything.
    peers: std::sync::Mutex<HashMap<String, Arc<PeerView>>>,
}

struct PeerView {
    presence: Arc<Optimistic>,
    bloom: Arc<SharedBloom>,
}

impl Hub {
    /// Measure savings but send whole. Switchable at runtime from the console.
    pub fn set_shadow(&self, on: bool) {
        self.shadow.store(on, Ordering::Relaxed);
        tracing::info!(on, "shadow mode");
    }

    pub fn shadow(&self) -> bool {
        self.shadow.load(Ordering::Relaxed)
    }

    /// The shared view of one peer address, created on first use.
    fn view_for(hub: &Arc<Hub>, peer: &str) -> Arc<PeerView> {
        let mut g = hub.peers.lock().expect("peer map poisoned");
        g.entry(peer.to_string())
            .or_insert_with(|| {
                let bloom = Arc::new(SharedBloom::default());
                Arc::new(PeerView {
                    presence: Arc::new(Optimistic::new(Box::new((*bloom).clone()))),
                    bloom,
                })
            })
            .clone()
    }
}

impl Hub {
    pub fn new(cfg: Arc<Config>) -> anyhow::Result<Arc<Hub>> {
        Ok(Arc::new(Hub {
            peers: std::sync::Mutex::new(HashMap::new()),
            shadow: AtomicBool::new(cfg.local.shadow || cfg.profiles.iter().any(|p| p.shadow)),
            counters: Arc::new(Counters::default()),
            store: Arc::new(Store::new(cfg.store.clone())),
            turns: Arc::new(TurnLog::new(cfg.turn_log_cap)),
            cfg,
        }))
    }
}

/// One listener: a profile of the local end.
pub struct App {
    pub cfg: Arc<Config>,
    /// Which listener this is: address, peer, TLS, compression.
    pub profile: LocalConfig,
    pub link: Arc<LinkState>,
    pub pool: Mutex<Vec<Conn>>,
    pub seq: AtomicU64,
    pub turns: Arc<TurnLog>,
    pub tls: Option<Arc<rustls::ClientConfig>>,
    /// Kept so the shared store (and its lock) outlives every profile.
    pub hub: Arc<Hub>,
}

/// Keyed proof of the pairing secret. It never leaves the process.
pub fn pairing_proof(token: &str, salt: u64) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"MUKA-PAIR-1");
    h.update(token.as_bytes());
    h.update(&salt.to_le_bytes());
    h.finalize().to_hex().to_string()
}

/// What one request will be sent as, and why if not.
pub(crate) struct Prepared {
    pub(crate) payload: Payload,
    pub(crate) skip_reason: Option<String>,
}

impl App {
    /// The single-profile case: whatever `[local]` says.
    pub fn new(cfg: Arc<Config>) -> anyhow::Result<Arc<App>> {
        let hub = Hub::new(cfg.clone())?;
        Self::for_profile(&hub, cfg.local.clone())
    }

    /// One listener, sharing the hub's cache and counters.
    pub fn for_profile(hub: &Arc<Hub>, profile: LocalConfig) -> anyhow::Result<Arc<App>> {
        let cfg = hub.cfg.clone();
        let compress = profile.compress;
        anyhow::ensure!(cfg.role == Role::Local, "use muka_gateway::remote for the peer end");
        let tls = match (profile.tls, &profile.tls_ca_file) {
            (true, Some(ca)) => Some(crate::tls::client(ca).map_err(|e| anyhow::anyhow!("{e}"))?),
            _ => None,
        };
        let view = Hub::view_for(hub, &profile.peer);
        let bloom = view.bloom.clone();
        let presence = view.presence.clone();
        let peer_name = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "muka-local".into());
        let proof = match &cfg.pairing_token {
            Some(t) => pairing_proof(t, cfg.epoch_salt),
            None => String::new(),
        };
        Ok(Arc::new(App {
            cfg,
            hub: hub.clone(),
            profile,
            turns: hub.turns.clone(),
            link: Arc::new(LinkState {
                store: hub.store.clone(),
                presence,
                bloom,
                counters: hub.counters.clone(),
                peer_name,
                proof,
                compress,
            }),
            pool: Mutex::new(Vec::new()),
            seq: AtomicU64::new(1),
            tls,
        }))
    }

    /// Every listener this process should run, from the config.
    pub fn all(hub: &Arc<Hub>) -> anyhow::Result<Vec<Arc<App>>> {
        let mut out = Vec::new();
        for p in hub.cfg.effective_profiles() {
            out.push(Self::for_profile(hub, p)?);
        }
        Ok(out)
    }

    pub fn counters(&self) -> Arc<Counters> {
        self.link.counters.clone()
    }

    pub fn name(&self) -> &str {
        &self.profile.name
    }

    pub fn store(&self) -> Arc<Store> {
        self.link.store.clone()
    }

    pub fn hub(&self) -> Arc<Hub> {
        self.hub.clone()
    }

    /// Forget what this process believes the peer holds, and optionally clear
    /// both caches. The next turns then re-push their blocks, which is how you
    /// recover from a suspect cache without restarting either machine.
    /// Returns how many *local* blocks were discarded.
    pub async fn reset_cache(&self, drop_store: bool) -> u64 {
        // Cloned out of the map so the std lock is not held across an await.
        let views: Vec<Arc<PeerView>> = self
            .hub
            .peers
            .lock()
            .expect("peer map poisoned")
            .values()
            .cloned()
            .collect();
        for v in &views {
            v.presence.clear();
            // The split asks the optimistic presence *and* the peer's bloom, so
            // "forget what the peer holds" has to reset both - a stale bloom
            // would keep answering "present" and nothing would be re-pushed.
            // The peer's next response restores the real view.
            v.bloom.clear().await;
        }
        let mut n = 0;
        if drop_store {
            // The peer is the cache authority: unless it forgets too, the next
            // turns resolve from its store and nothing is re-pushed, which
            // would make the console button a lie. The message rides an already
            // greeted connection - so pairing applies - and stays ordered on
            // it, which means the peer has cleared before any later request
            // uses that connection.
            let mut pool = self.pool.lock().await;
            let mut kept = Vec::with_capacity(pool.len());
            for mut c in pool.drain(..) {
                let f = Frame::control(Tag::Reset, Bytes::new());
                match write_frame(&mut c.w, &f).await {
                    Ok(()) => kept.push(c),
                    Err(e) => tracing::debug!(error = %e, "peer connection was already gone"),
                }
            }
            *pool = kept;
            n = self.link.store.clear();
        }
        tracing::info!(dropped = n, "cache reset");
        n
    }

    pub fn turns(&self) -> Arc<TurnLog> {
        self.turns.clone()
    }

    /// Idle connections are reused, so a steady conversation pays one
    /// handshake instead of one per turn.
    async fn take_conn(&self) -> Result<Conn, SessionError> {
        if let Some(c) = self.pool.lock().await.pop() {
            return Ok(c);
        }
        let id = self.seq.fetch_add(1, Ordering::Relaxed);
        let sock = TcpStream::connect(&self.profile.peer)
            .await
            .map_err(|e| SessionError::Io(format!("dial {}: {e}", self.profile.peer)))?;
        sock.set_nodelay(true).ok();
        match &self.tls {
            None => Ok(Conn::new(sock, id)),
            Some(cfg) => {
                let name = rustls::pki_types::ServerName::try_from(crate::tls::SERVER_NAME.to_string())
                    .map_err(|e| SessionError::Io(format!("bad peer name: {e}")))?;
                let tls = tokio_rustls::TlsConnector::from(cfg.clone())
                    .connect(name, sock)
                    .await
                    .map_err(|e| {
                        SessionError::Io(format!("tls handshake with {}: {e}", self.profile.peer))
                    })?;
                Ok(Conn::new(tls, id))
            }
        }
    }

    async fn put_conn(&self, c: Conn) {
        // Connections are recycled only while they stay healthy; the peer closes
        // a connection after a protocol error, so a stale one costs a reconnect.
        if c.requests > 512 {
            return;
        }
        let mut g = self.pool.lock().await;
        if g.len() < self.profile.max_conns {
            g.push(c);
        }
    }

    pub async fn handle(self: Arc<Self>, req: Request<Incoming>) -> Response<Body> {
        let path = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let method = req.method().as_str().to_string();
        let headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .filter(|(k, _)| !DROP_REQUEST.contains(&k.as_str().to_ascii_lowercase().as_str()))
            .map(|(k, v)| (k.as_str().to_ascii_lowercase(), v.to_str().unwrap_or_default().to_string()))
            .collect();

        let body = match req.into_body().collect().await {
            Ok(c) => c.to_bytes(),
            Err(e) => return json_error(StatusCode::BAD_REQUEST, &format!("unreadable request body: {e}")),
        };
        if body.len() > self.cfg.policy.max_body_bytes {
            return json_error(StatusCode::PAYLOAD_TOO_LARGE, "request body exceeds policy.max_body_bytes");
        }

        let kind = classify(&path);
        let Prepared { payload, skip_reason } = self.prepare(kind, &self.cfg.policy, &body);
        let head = RequestHead {
            method,
            path,
            headers,
            body_len: body.len() as u64,
            body_digest: digest_of(BlockKind::Raw, &body),
            kind,
            split: payload.is_split(),
        };

        let peer_label = self.profile.peer.clone();
        let (head_tx, mut head_rx) = mpsc::channel::<ResponseHead>(1);
        let (body_tx, body_rx) = mpsc::channel::<Result<Bytes, io::Error>>(8);
        let app = self.clone();
        let driver = tokio::spawn(async move { app.drive(head, body, payload, skip_reason, head_tx, body_tx).await });

        let resp_head = match head_rx.recv().await {
            Some(h) => h,
            None => {
                let err = driver.await.map(|e| e.err()).unwrap_or(None);
                return json_error(
                    StatusCode::BAD_GATEWAY,
                    &format!("link to {peer_label} is not usable: {}", err.map(|e| e.to_string()).unwrap_or_else(|| "closed".into())),
                );
            }
        };

        let mut builder = Response::builder().status(resp_head.status);
        for (k, v) in &resp_head.headers {
            if DROP_RESPONSE.contains(&k.as_str()) {
                continue;
            }
            let Ok(name) = http::header::HeaderName::from_bytes(k.as_bytes()) else { continue };
            let Ok(value) = http::header::HeaderValue::from_str(v) else { continue };
            if let Some(map) = builder.headers_mut() {
                map.insert(name, value);
            }
        }
        match builder.body(Body::new(StreamBody::new(
            futures_util::StreamExt::map(ReceiverStream::new(body_rx), |c| {
                c.map(hyper::body::Frame::data).map_err(BoxErr::from)
            }),
        ))) {
            Ok(r) => r,
            Err(e) => {
                let _ = driver.await;
                json_error(StatusCode::BAD_GATEWAY, &format!("unbuildable response: {e}"))
            }
        }
    }

    /// Decide split vs verbatim.
    pub(crate) fn prepare(&self, kind: Kind, policy: &Policy, body: &Bytes) -> Prepared {
        let mut payload = Payload::Whole(body.clone());
        let mut skip_reason = None;
        if !kind.dedupable() {
            skip_reason = Some("path".to_string());
        } else if !policy.enabled {
            skip_reason = Some("disabled".to_string());
        } else if body.len() < policy.min_body_bytes.max(self.profile.min_body_bytes) {
            skip_reason = Some("too_small".to_string());
        } else {
            let ctx = Ctx {
                peer: &*self.link.presence,
                local: &*self.link.store,
                policy,
            };
            match split_body(body, &ctx) {
                Action::Split(out) => {
                    if self.profile.shadow || self.hub.shadow() {
                        // Measure only: report the saving, send it whole.
                        skip_reason = Some("shadow".to_string());
                        let est = out.stats.wire_bytes();
                        tracing::info!(
                            body = body.len(),
                            wire = est,
                            refs = out.stats.refs,
                            hits = out.stats.refs_hit,
                            "shadow: would have saved {}%",
                            100.0 - est as f64 * 100.0 / body.len() as f64
                        );
                    } else {
                        payload = Payload::Split(out);
                    }
                }
                Action::Passthrough(s) => skip_reason = Some(s.reason().to_string()),
            }
        }
        Prepared { payload, skip_reason }
    }

    /// Own one turn: attempt, retry verbatim if the split itself is what broke,
    /// then record the accounting.
    async fn drive(
        self: Arc<Self>,
        head: RequestHead,
        body: Bytes,
        mut payload: Payload,
        mut skip_reason: Option<String>,
        head_tx: mpsc::Sender<ResponseHead>,
        body_tx: mpsc::Sender<Result<Bytes, io::Error>>,
    ) -> Result<ResponseEnd, SessionError> {
        let started = std::time::Instant::now();
        let head_sent = Arc::new(AtomicBool::new(false));
        let mut attempts = 0u32;
        let end = loop {
            attempts += 1;
            let mut conn = match self.take_conn().await {
                Ok(c) => c,
                Err(e) => {
                    self.link.counters.link_errors.fetch_add(1, Ordering::Relaxed);
                    return Err(e);
                }
            };
            let outcome = local_end(&mut conn, &head, &payload, &self.link, body_tx.clone(), head_tx.clone(), head_sent.clone()).await;
            match outcome {
                Ok(end) => {
                    self.put_conn(conn).await;
                    break end;
                }
                Err(e) => {
                    let retryable = e.fallback_to_whole()
                        && attempts == 1
                        && payload.is_split()
                        && !head_sent.load(Ordering::SeqCst);
                    drop(conn);
                    if !retryable {
                        self.link.counters.link_errors.fetch_add(1, Ordering::Relaxed);
                        return Err(e);
                    }
                    tracing::warn!(error = %e, "peer could not rebuild; re-sending the body whole");
                    self.link.counters.rebuild_failures.fetch_add(1, Ordering::Relaxed);
                    skip_reason = Some("rebuild failed".into());
                    payload = Payload::Whole(body.clone());
                }
            }
        };
        // The peer does not echo the split statistics back - the local side is
        // the one that produced them, and it still has them here.
        let sent = payload.stats();
        self.turns.push(Turn {
            profile: self.profile.name.clone(),
            seq: self.seq.load(Ordering::Relaxed),
            path: head.path.clone(),
            status: 200,
            body_bytes: head.body_len,
            // Measured on the peer, not estimated here: the estimate ignores
            // compression, so a shadowed turn would look twice as expensive as
            // it was.
            wire_bytes: end.wire_bytes,
            refs: sent.map(|s| s.refs).unwrap_or(0),
            refs_hit: sent.map(|s| s.refs_hit).unwrap_or(0),
            pushed: sent.map(|s| s.push_blocks).unwrap_or(0),
            repairs: end.repairs,
            link_ms: started.elapsed().as_millis() as u64,
            upstream_ms: end.upstream_us / 1000,
            // What actually left: after a rebuild failure the body goes whole,
            // and the console should not claim it was a program.
            split: payload.is_split(),
            skip_reason,
            store_blocks: end.store_blocks,
        });
        self.link.counters.link_us.fetch_add(started.elapsed().as_micros() as u64, Ordering::Relaxed);
        tracing::info!(
            path = %head.path,
            body = head.body_len,
            wire = end.wire_bytes,
            saved = format!("{:.1}%", end.saved_ratio() * 100.0),
            refs = sent.map(|s| s.refs).unwrap_or(0),
            hits = sent.map(|s| s.refs_hit).unwrap_or(0),
            pushed = sent.map(|s| s.push_blocks).unwrap_or(0),
            repairs = end.repairs,
            link_ms = started.elapsed().as_millis() as u64,
            upstream_ms = end.upstream_us / 1000,
            peer_blocks = end.store_blocks,
            "turn"
        );
        Ok(end)
    }
}

fn json_error(status: StatusCode, msg: &str) -> Response<Body> {
    let body = format!(
        "{{\"error\":{{\"message\":\"muka: {}\",\"type\":\"proxy_error\",\"code\":\"muka_link\"}}}}",
        msg.replace('\\', "\\\\").replace('"', "'")
    );
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(full(body))
        .unwrap_or_else(|_| Response::new(full(Bytes::new())))
}

/// Bind `local.listen` and report the address, so a test can use port 0.
pub async fn bind(app: Arc<App>) -> anyhow::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(&app.profile.listen).await?;
    let addr = listener.local_addr()?;
    let never = Arc::new(tokio::sync::Notify::new());
    let handle = tokio::spawn(async move {
        // `never` is not notified: a bound server lives until the task aborts.
        let _ = accept(app, never, listener).await;
    });
    Ok((addr, handle))
}

/// Serve the agent-facing listener until `shutdown` fires.
pub async fn serve(app: Arc<App>, shutdown: Arc<tokio::sync::Notify>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&app.profile.listen).await?;
    accept(app, shutdown, listener).await
}

async fn accept(app: Arc<App>, shutdown: Arc<tokio::sync::Notify>, listener: TcpListener) -> anyhow::Result<()> {
    tracing::info!(
        listen = %listener.local_addr()?,
        profile = %app.profile.name,
        peer = %app.profile.peer,
        "muka local end listening"
    );
    // One `notified()` future kept alive across iterations: building a fresh
    // one each pass is not cancel-safe.
    let shutdown = shutdown.notified();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = shutdown.as_mut() => return Ok(()),
            accepted = listener.accept() => {
                let (sock, peer) = accepted?;
                sock.set_nodelay(true).ok();
                let app = app.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(sock);
                    let svc = hyper::service::service_fn(move |r: Request<Incoming>| {
                        let app = app.clone();
                        async move { Ok::<Response<Body>, Infallible>(app.handle(r).await) }
                    });
                    if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                        tracing::debug!(%peer, error = %e, "agent connection ended");
                    }
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_filters_cover_framing_fields() {
        for h in ["content-length", "transfer-encoding", "connection", "upgrade"] {
            assert!(DROP_REQUEST.iter().any(|d| *d == h), "{h} must be dropped outbound");
        }
        for h in ["content-length", "transfer-encoding", "connection"] {
            assert!(DROP_RESPONSE.iter().any(|d| *d == h), "{h} must be dropped inbound");
        }
        assert!(!DROP_REQUEST.contains(&"authorization"));
        assert!(!DROP_REQUEST.contains(&"content-type"));
    }

    #[test]
    fn classify_is_conservative_about_unknown_paths() {
        assert_eq!(classify("/v1/chat/completions"), Kind::ChatCompletions);
        assert_eq!(classify("/v1/chat/completions?x=1"), Kind::ChatCompletions);
        assert_eq!(classify("/v1/models"), Kind::Models);
        assert_eq!(classify("/v1/uploads"), Kind::Other);
        assert!(!Kind::Other.dedupable());
        assert!(Kind::Responses.dedupable());
    }

    #[test]
    fn proof_is_stable_keyed_and_off_the_wire() {
        let a = pairing_proof("0123456789abcdef", 1);
        assert_eq!(a, pairing_proof("0123456789abcdef", 1));
        assert_ne!(a, pairing_proof("0123456789abcdef", 2));
        assert_ne!(a, pairing_proof("fedcba9876543210", 1));
        assert_eq!(a.len(), 64);
        assert!(!a.contains("0123456789abcdef"));
    }

    #[tokio::test]
    async fn app_prepare_falls_back_for_small_and_unknown_requests() {
        let app = App::new(Arc::new(Config { role: Role::Local, pairing_token: Some("0123456789abcdef".into()), ..Default::default() })).unwrap();
        let tiny = Bytes::from_static(br#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#);
        let p = app.prepare(Kind::ChatCompletions, &app.cfg.policy, &tiny);
        assert!(!p.payload.is_split());
        assert_eq!(p.skip_reason.as_deref(), Some("too_small"));
        assert!(
            matches!(&p.payload, Payload::Whole(b) if b.as_ref() == &tiny[..]),
            "a body below the floor goes out verbatim"
        );

        let up = app.prepare(Kind::Other, &app.cfg.policy, &Bytes::from(vec![b'x'; 9000]));
        assert_eq!(up.skip_reason.as_deref(), Some("path"));
    }

}
