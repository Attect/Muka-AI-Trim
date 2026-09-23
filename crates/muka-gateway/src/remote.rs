//! The proxy-machine end: accepts the link, rebuilds each request, forwards it
//! to the real API and relays the answer back.

use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use bytes::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use muka_proto::msg::ResponseHead;
use muka_store::Store;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::config::Config;
use crate::metrics::Counters;
use crate::session::{remote_end, Conn, SessionError};
use crate::upstream::Upstream;

pub struct Peer {
    pub cfg: Arc<Config>,
    pub store: Arc<Store>,
    pub counters: Arc<Counters>,
    pub upstream: Arc<Upstream>,
    pub epoch: u64,
    pub proof: Option<String>,
    pub tls: Option<Arc<tokio_rustls::TlsAcceptor>>,
    pub ca_file: Option<std::path::PathBuf>,
}

impl Peer {
    pub fn new(cfg: Arc<Config>) -> anyhow::Result<Arc<Peer>> {
        let store = Arc::new(Store::new(cfg.store.clone()));
        let upstream = Upstream::new(&cfg.remote)?;
        let proof = cfg
            .pairing_token
            .as_deref()
            .map(|t| crate::local::pairing_proof(t, cfg.epoch_salt));
        if proof.is_none() {
            tracing::warn!(
                "no pairing_token configured: anyone who can reach this port can \
                 use it to reach the upstream API"
            );
        }
        let (tls, ca_file) = match (cfg.remote.tls, cfg.remote.tls_dir.clone()) {
            (true, Some(dir)) => {
                let id = crate::tls::serve(&dir).map_err(|e| anyhow::anyhow!("{e}"))?;
                tracing::info!(
                    ca = %id.ca_file.display(),
                    "link TLS on: copy that ca.der to the other machine and set local.tls_ca_file to it"
                );
                (Some(Arc::new(tokio_rustls::TlsAcceptor::from(id.config))), Some(id.ca_file))
            }
            (true, None) => anyhow::bail!("remote.tls needs a directory for key material: set remote.tls_dir"),
            (false, _) => (None, None),
        };
        Ok(Arc::new(Peer {
            cfg,
            store,
            counters: Arc::new(Counters::default()),
            upstream,
            epoch: rand_epoch(),
            proof,
            tls,
            ca_file,
        }))
    }

    /// Bind `remote.listen` and report the address, so a test can use port 0.
    pub async fn bind(self: Arc<Self>) -> anyhow::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
        let listener = TcpListener::bind(&self.cfg.remote.listen).await?;
        let addr = listener.local_addr()?;
        let me = self.clone();
        let never = Arc::new(tokio::sync::Notify::new());
        let handle = tokio::spawn(async move {
            // `never` is not notified: a bound server lives until aborted.
            let _ = me.accept(never, listener).await;
        });
        Ok((addr, handle))
    }

    /// Serve the link until `shutdown` fires.
    pub async fn serve(self: Arc<Self>, shutdown: Arc<tokio::sync::Notify>) -> anyhow::Result<()> {
        let listener = TcpListener::bind(&self.cfg.remote.listen).await?;
        self.accept(shutdown, listener).await
    }

    async fn accept(self: Arc<Self>, shutdown: Arc<tokio::sync::Notify>, listener: TcpListener) -> anyhow::Result<()> {
        tracing::info!(
            listen = %listener.local_addr()?,
            upstream = %self.cfg.remote.upstream,
            store_blocks = self.store.stats().blocks,
            "muka peer end listening"
        );
        let shutdown = shutdown.notified();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = shutdown.as_mut() => return Ok(()),
                accepted = listener.accept() => {
                    let (sock, peer) = accepted?;
                    sock.set_nodelay(true).ok();
                    let me = self.clone();
                    tokio::spawn(async move {
                        let conn = match me.handshake(sock).await {
                            Ok(c) => c,
                            Err(e) => {
                                // A peer that cannot even complete TLS is either
                                // unpaired or scanning us: log and drop.
                                tracing::debug!(%peer, error = %e, "link handshake refused");
                                return;
                            }
                        };
                        if let Err(e) = me.serve_conn(conn).await {
                            tracing::debug!(%peer, error = %e, "link connection ended");
                        }
                    });
                }
            }
        }
    }

    /// Wrap the accepted socket in TLS when configured, then run the protocol.
    async fn handshake(self: &Arc<Self>, sock: TcpStream) -> Result<Conn, SessionError> {
        match &self.tls {
            None => Ok(Conn::new(sock, 1)),
            Some(acceptor) => {
                let tls = acceptor
                    .accept(sock)
                    .await
                    .map_err(|e| SessionError::Rejected(format!("tls handshake failed: {e}")))?;
                Ok(Conn::new(tls, 1))
            }
        }
    }

    async fn serve_conn(self: Arc<Self>, conn: Conn) -> Result<(), SessionError> {
        let store = self.store.clone();
        let epoch = self.epoch;
        let proof = self.proof.clone();
        let up = self.upstream.clone();
        let link_counters = self.counters.clone();
        let err_counters = self.counters.clone();
        remote_end(conn, store, link_counters, epoch, proof, move |rb| {
            let up = up.clone();
            let counters = err_counters.clone();
            async move {
                let rebuilt = rb.rebuild_us;
                match up.send(rb).await {
                    Ok((mut head, rx)) => {
                        head.rebuild_us = rebuilt;
                        Ok((head, rx))
                    }
                    // An unreachable or 5xx-ing upstream is still an answer: the
                    // agent must see a status, not a dropped connection.
                    Err(e) => {
                        counters.upstream_errors.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(error = %e, "upstream failed");
                        let (tx, rx) = mpsc::channel::<Result<Bytes, io::Error>>(1);
                        let body = format!(
                            "{{\"error\":{{\"message\":\"{}\",\"type\":\"upstream_unreachable\"}}}}",
                            e.to_string().replace('"', "'")
                        );
                        tx.send(Ok(Bytes::from(body))).await.ok();
                        drop(tx);
                        Ok((
                            ResponseHead {
                                status: StatusCode::BAD_GATEWAY.as_u16(),
                                headers: vec![("content-type".into(), "application/json".into())],
                                content_length: None,
                                rebuild_us: rebuilt,
                            },
                            rx,
                        ))
                    }
                }
            }
        })
        .await
    }
}

/// Distinguishes "the peer has been running since before my last request" from
/// "the peer restarted and its store is empty".
fn rand_epoch() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    (nanos ^ (std::process::id() as u64) << 32) | 1
}

/// A minimal stand-in upstream for tests and `--dry-run`: answers every
/// request with a short SSE stream and reports what it received.
pub struct MockUpstream {
    pub seen: std::sync::Mutex<Vec<Bytes>>,
    /// Headers of the most recent request: which credential actually arrived.
    pub saw_headers: std::sync::Mutex<Vec<(String, String)>>,
    /// Path-and-query of the most recent request, so a dropped `?beta=true` is
    /// visible rather than silently served differently.
    pub saw_path: std::sync::Mutex<String>,
    pub status: u16,
}

impl MockUpstream {
    pub fn new() -> Arc<MockUpstream> {
        Arc::new(MockUpstream {
            seen: std::sync::Mutex::new(Vec::new()),
            saw_headers: std::sync::Mutex::new(Vec::new()),
            saw_path: std::sync::Mutex::new(String::new()),
            status: 200,
        })
    }

    pub fn last_body(&self) -> Option<Bytes> {
        self.seen.lock().unwrap().last().cloned()
    }

    pub fn last_path(&self) -> String {
        self.saw_path.lock().unwrap().clone()
    }

    pub fn last_header(&self, name: &str) -> Option<String> {
        self.saw_headers
            .lock()
            .unwrap()
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    }

    /// Bind on an ephemeral port and report it, so tests never hardcode one.
    pub async fn bind(self: Arc<Self>) -> anyhow::Result<(String, tokio::task::JoinHandle<()>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?.to_string();
        let me = self.clone();
        let handle = tokio::spawn(async move {
            let (_tx, rx) = tokio::sync::oneshot::channel();
            let _ = me.accept_loop(listener, rx).await;
        });
        Ok((addr, handle))
    }

    async fn accept_loop(self: Arc<Self>, listener: TcpListener, mut shutdown: tokio::sync::oneshot::Receiver<()>) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                _ = &mut shutdown => return Ok(()),
                accepted = listener.accept() => {
                    let (sock, _) = accepted?;
                    let me = self.clone();
                    tokio::spawn(async move {
                        let io = TokioIo::new(sock);
                        let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                            let me = me.clone();
                            async move { Ok::<Response<crate::local::Body>, std::convert::Infallible>(me.answer(req).await) }
                        });
                        let _ = http1::Builder::new().serve_connection(io, svc).await;
                    });
                }
            }
        }
    }

    async fn answer(self: Arc<Self>, req: Request<hyper::body::Incoming>) -> Response<crate::local::Body> {
        use http_body_util::BodyExt;
        *self.saw_path.lock().unwrap() = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| req.uri().path().to_string());
        *self.saw_headers.lock().unwrap() = req
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = req.into_body().collect().await.map(|c| c.to_bytes()).unwrap_or_default();
        self.seen.lock().unwrap().push(body.clone());
        let mut values: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::json!(null));
        let turns = values
            .get("messages")
            .and_then(|m| m.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        if let Some(obj) = values.as_object_mut() {
            obj.insert("muka_saw_items".into(), serde_json::json!(turns));
        }
        let payload = format!(
            "data: {}\n\ndata: [DONE]\n\n",
            serde_json::to_string(&values).unwrap_or_default()
        );
        Response::builder()
            .status(self.status)
            .header("content-type", "text/event-stream")
            .body(crate::local::full(payload))
            .unwrap()
    }
}

impl Default for MockUpstream {
    fn default() -> Self {
        MockUpstream {
            seen: std::sync::Mutex::new(Vec::new()),
            saw_headers: std::sync::Mutex::new(Vec::new()),
            saw_path: std::sync::Mutex::new(String::new()),
            status: 200,
        }
    }
}
