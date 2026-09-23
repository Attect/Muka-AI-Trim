//! The upstream client, used by the peer end.
//!
//! This is the only place that holds the real API key: when `api_key` is set it
//! replaces whatever credential the agent sent (`Authorization` for the OpenAI
//! family, `x-api-key` for the Messages API), so the key never crosses the slow
//! link and never has to exist on the laptop at all.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::Request;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use muka_proto::msg::{classify, Kind, ResponseHead};
use tokio::sync::mpsc;

use crate::config::RemoteConfig;
use crate::session::{Rebuilt, SessionError, RELAY_CHUNK};

/// Wait this long for response *headers*. Never applied to the body: an agent
/// stream can legitimately stay open for minutes.
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(120);

pub type Connector = HttpsConnector<HttpConnector>;

pub struct Upstream {
    base: http::Uri,
    client: Client<Connector, crate::local::Body>,
    key: Option<String>,
}

impl Upstream {
    pub fn new(cfg: &RemoteConfig) -> anyhow::Result<Arc<Upstream>> {
        let base: http::Uri = cfg
            .upstream
            .parse()
            .map_err(|_| anyhow::anyhow!("upstream {url} is not a valid URI", url = cfg.upstream))?;
        anyhow::ensure!(
            matches!(base.scheme().map(|s| s.as_str()), Some("http") | Some("https")),
            "upstream must be http:// or https://"
        );
        anyhow::ensure!(base.authority().is_some(), "upstream must include a host");
        let key = match (&cfg.api_key, &cfg.api_key_file) {
            (Some(k), _) if !k.trim().is_empty() => Some(k.trim().to_string()),
            (_, Some(f)) => Some(std::fs::read_to_string(f)?.trim().to_string()),
            _ => None,
        };
        // `ring` is the only provider we build with; installing it lazily keeps
        // a library consumer from having to remember to do it.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(8)
            .build::<_, crate::local::Body>(https);
        Ok(Arc::new(Upstream {
            base,
            client,
            key,
        }))
    }

    /// Absolute URI for a request path, refusing to be pointed at a third
    /// host (this process can reach the internet; that does not make it a
    /// general-purpose proxy).
    pub fn absolute(&self, path: &str) -> anyhow::Result<http::Uri> {
        anyhow::ensure!(path.starts_with('/'), "request path must be absolute: {path}");
        let scheme = self.base.scheme().map(|s| s.as_str()).unwrap_or("https");
        let host = self.base.authority().map(|a| a.to_string()).unwrap_or_default();
        let uri: http::Uri = format!("{scheme}://{host}{path}").parse()?;
        Ok(uri)
    }

    fn host_header(&self) -> String {
        self.base.authority().map(|a| a.host().to_string()).unwrap_or_default()
    }

    /// Send one rebuilt request and hand back its head plus a stream of body
    /// chunks. Nothing is buffered here: SSE must reach the agent live.
    pub async fn send(self: Arc<Self>, rb: Rebuilt) -> Result<(ResponseHead, mpsc::Receiver<Result<Bytes, io::Error>>), SessionError> {
        let rebuild_us = rb.rebuild_us;
        let uri = self
            .absolute(&rb.head.path)
            .map_err(|e| SessionError::BadPayload(format!("bad path: {e}")))?;
        let mut b = Request::builder().method(rb.head.method.as_str()).uri(uri);
        {
            let headers = b.headers_mut().ok_or_else(|| SessionError::BadPayload("headers".into()))?;
            for (k, v) in &rb.head.headers {
                if crate::local::DROP_REQUEST.contains(&k.as_str()) {
                    continue;
                }
                let (Ok(name), Ok(value)) = (
                    hyper::header::HeaderName::from_bytes(k.as_bytes()),
                    hyper::header::HeaderValue::from_str(v),
                ) else {
                    continue;
                };
                headers.insert(name, value);
            }
            headers.insert(
                hyper::header::HOST,
                hyper::header::HeaderValue::from_str(&self.host_header())
                    .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("localhost")),
            );
            if let Some(key) = &self.key {
                // Two families, two headers. The Messages API authenticates with
                // `x-api-key` and refuses a request that also carries a bearer
                // `Authorization`, so guessing wrong costs every request.
                let bad = || SessionError::BadPayload("api key contains invalid characters".into());
                if classify(&rb.head.path) == Kind::Messages {
                    headers.remove(hyper::header::AUTHORIZATION);
                    headers.insert(
                        "x-api-key",
                        hyper::header::HeaderValue::from_str(key).map_err(|_| bad())?,
                    );
                    headers
                        .entry("anthropic-version")
                        .or_insert(hyper::header::HeaderValue::from_static("2023-06-01"));
                } else {
                    headers.insert(
                        hyper::header::AUTHORIZATION,
                        hyper::header::HeaderValue::from_str(&format!("Bearer {key}")).map_err(|_| bad())?,
                    );
                }
            }
        }
        let req = b
            .body(crate::local::full(rb.body))
            .map_err(|e| SessionError::BadPayload(e.to_string()))?;

        let resp = match tokio::time::timeout(HEAD_TIMEOUT, self.client.request(req)).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => {
                return Err(SessionError::Io(format!("upstream request failed: {e}")));
            }
            Err(_) => {
                return Err(SessionError::Io(format!(
                    "upstream {} sent no response headers within {}s",
                    self.host_header(),
                    HEAD_TIMEOUT.as_secs()
                )));
            }
        };

        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_ascii_lowercase(), v.to_str().unwrap_or_default().to_string()))
            .filter(|(k, _)| !crate::local::DROP_RESPONSE.contains(&k.as_str()))
            .collect();
        let content_length = resp
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());
        let head = ResponseHead { status, headers, content_length, rebuild_us };

        let (tx, rx) = mpsc::channel::<Result<Bytes, io::Error>>(8);
        tokio::spawn(pump(resp.into_body(), tx));
        Ok((head, rx))
    }
}

/// Relay the upstream body, honouring backpressure from the link.
async fn pump(mut resp: Incoming, tx: mpsc::Sender<Result<Bytes, io::Error>>) {
    loop {
        match tokio::time::timeout(Duration::from_secs(900), resp.frame()).await {
            Err(_) => {
                let _ = tx.send(Err(io::Error::new(io::ErrorKind::TimedOut, "upstream stream stalled"))).await;
                return;
            }
            Ok(None) => return,
            Ok(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    for chunk in data.chunks(RELAY_CHUNK) {
                        if tx.send(Ok(chunk.to_vec().into())).await.is_err() {
                            return;
                        }
                    }
                }
            }
            Ok(Some(Err(e))) => {
                let _ = tx.send(Err(io::Error::other(format!("upstream chunk: {e}")))).await;
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RemoteConfig;

    fn cfg(up: &str) -> RemoteConfig {
        RemoteConfig { upstream: up.into(), ..Default::default() }
    }

    #[test]
    fn upstream_urls_are_validated_and_absolute() {
        let u = Upstream::new(&cfg("https://api.openai.com")).unwrap();
        let uri = u.absolute("/v1/chat/completions").unwrap();
        assert_eq!(uri.host().unwrap(), "api.openai.com");
        assert_eq!(uri.path(), "/v1/chat/completions");
        assert_eq!(u.host_header(), "api.openai.com");
        assert!(u.absolute("v1/nope").is_err(), "path traversal through a relative URI");
        assert!(Upstream::new(&cfg("api.openai.com")).is_err());
        assert!(Upstream::new(&cfg("ftp://api.openai.com")).is_err());
        assert!(u.absolute("/v1/chat/completions?x=1").unwrap().path().starts_with("/v1/chat"));
    }

    #[tokio::test]
    async fn an_unreachable_upstream_is_an_error_not_a_hang() {
        // Port 1 is not going to answer.
        let u = Upstream::new(&cfg("http://127.0.0.1:1")).unwrap();
        let rb = Rebuilt {
            head: muka_proto::msg::RequestHead {
                method: "POST".into(),
                path: "/v1/chat/completions".into(),
                headers: vec![],
                body_len: 2,
                body_digest: muka_split::digest_of(muka_split::BlockKind::Raw, b"{}"),
                kind: Default::default(),
                split: false,
            },
            body: Bytes::from_static(b"{}"),
            rebuild_us: 1,
        };
        let err = u.send(rb).await.unwrap_err();
        assert!(err.to_string().contains("upstream"), "{err}");
    }
}
