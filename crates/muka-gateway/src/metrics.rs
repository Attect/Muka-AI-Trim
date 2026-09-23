//! Counters for both ends of the link, plus the `/metrics` and console server.
//!
//! Everything the request path touches is an atomic: the console and Prometheus
//! scrape while requests are in flight, and a lock there would be paid for on
//! every turn.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use muka_store::Store;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

#[derive(Default, Debug)]
pub struct Counters {
    pub requests: AtomicU64,
    pub split_requests: AtomicU64,
    pub passthrough: AtomicU64,
    pub body_bytes: AtomicU64,
    pub wire_bytes: AtomicU64,
    pub refs: AtomicU64,
    pub refs_hit: AtomicU64,
    pub blocks_pushed: AtomicU64,
    pub repairs: AtomicU64,
    pub rebuilds: AtomicU64,
    pub rebuild_failures: AtomicU64,
    pub upstream_errors: AtomicU64,
    pub link_errors: AtomicU64,
    pub response_bytes: AtomicU64,
    pub link_us: AtomicU64,
    pub upstream_us: AtomicU64,
    pub io_errors: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub requests: u64,
    pub split_requests: u64,
    pub passthrough: u64,
    pub body_bytes: u64,
    pub wire_bytes: u64,
    pub refs: u64,
    pub refs_hit: u64,
    pub blocks_pushed: u64,
    pub repairs: u64,
    pub rebuilds: u64,
    pub rebuild_failures: u64,
    pub upstream_errors: u64,
    pub link_errors: u64,
    pub response_bytes: u64,
    pub link_ms: u64,
    pub upstream_ms: u64,
}

impl Counters {
    pub fn snapshot(&self) -> Snapshot {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        Snapshot {
            requests: g(&self.requests),
            split_requests: g(&self.split_requests),
            passthrough: g(&self.passthrough),
            body_bytes: g(&self.body_bytes),
            wire_bytes: g(&self.wire_bytes),
            refs: g(&self.refs),
            refs_hit: g(&self.refs_hit),
            blocks_pushed: g(&self.blocks_pushed),
            repairs: g(&self.repairs),
            rebuilds: g(&self.rebuilds),
            rebuild_failures: g(&self.rebuild_failures),
            upstream_errors: g(&self.upstream_errors),
            link_errors: g(&self.link_errors),
            response_bytes: g(&self.response_bytes),
            link_ms: g(&self.link_us) / 1000,
            upstream_ms: g(&self.upstream_us) / 1000,
        }
    }

    /// Prometheus text exposition.
    pub fn prometheus(&self) -> String {
        let mut s = String::new();
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let mut add = |name: &str, help: &str, v: u64| {
            s.push_str(&format!("# HELP {name} {help}\n# TYPE {name} counter\n{name} {v}\n"));
        };
        add("muka_requests_total", "Agent requests handled.", g(&self.requests));
        add("muka_split_requests_total", "Requests sent as a block program.", g(&self.split_requests));
        add("muka_passthrough_requests_total", "Requests sent verbatim.", g(&self.passthrough));
        add("muka_body_bytes_total", "Uncompressed request body bytes.", g(&self.body_bytes));
        add("muka_wire_bytes_total", "Bytes actually put on the slow link.", g(&self.wire_bytes));
        add("muka_refs_total", "Block references emitted.", g(&self.refs));
        add("muka_refs_hit_total", "References the peer already had.", g(&self.refs_hit));
        add("muka_blocks_pushed_total", "Blocks uploaded to the peer.", g(&self.blocks_pushed));
        add("muka_repairs_total", "Requests where the peer re-asked for blocks.", g(&self.repairs));
        add("muka_rebuilds_total", "Bodies rebuilt by the peer.", g(&self.rebuilds));
        add("muka_rebuild_failures_total", "Rebuilds that fell back to a whole body.", g(&self.rebuild_failures));
        add("muka_upstream_errors_total", "Upstream failures relayed to the agent.", g(&self.upstream_errors));
        add("muka_link_errors_total", "Link errors.", g(&self.link_errors));
        add("muka_response_bytes_total", "Bytes returned by the upstream.", g(&self.response_bytes));
        add("muka_link_microseconds_total", "Time spent on the slow link.", g(&self.link_us));
        add("muka_upstream_microseconds_total", "Time spent at the upstream.", g(&self.upstream_us));
        add("muka_store_rejected_total", "Blocks the store refused: digest mismatch or oversized.", g(&self.io_errors));
        s
    }

    /// `节省 99.24% (1.4 MiB -> 11.2 KiB)，引用命中 41/43，补传 0，请求 12`
    pub fn summary(&self) -> String {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let (body, wire) = (g(&self.body_bytes), g(&self.wire_bytes));
        let saved = if body > 0 { 100.0 - (wire as f64 * 100.0 / body as f64) } else { 0.0 };
        format!(
            "节省 {saved:.2}% ({} -> {})，引用命中 {}/{}，补传 {}，请求 {}",
            human(body),
            human(wire),
            g(&self.refs_hit),
            g(&self.refs),
            g(&self.repairs),
            g(&self.requests),
        )
    }
}

pub fn human(v: u64) -> String {
    if v < 1024 {
        format!("{v} B")
    } else if v < 1024 * 1024 {
        format!("{:.1} KiB", v as f64 / 1024.0)
    } else if v < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", v as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GiB", v as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// A single completed turn, for the console's request stream.
#[derive(Clone, Debug, Serialize)]
pub struct Turn {
    /// Which listener served it, when one process fronts several agents.
    #[serde(default)]
    pub profile: String,
    pub seq: u64,
    pub path: String,
    pub status: u16,
    pub body_bytes: u64,
    pub wire_bytes: u64,
    pub refs: u32,
    pub refs_hit: u32,
    /// Blocks this turn had to upload because the peer could not resolve them.
    pub pushed: u32,
    pub repairs: u32,
    pub link_ms: u64,
    pub upstream_ms: u64,
    pub split: bool,
    pub skip_reason: Option<String>,
    /// Blocks the peer held after this turn, relayed back to us: proof the two
    /// caches are converging rather than drifting.
    pub store_blocks: u64,
}

impl Turn {
    /// Bytes actually saved on this turn.
    pub fn saved(&self) -> u64 {
        self.body_bytes.saturating_sub(self.wire_bytes)
    }

    /// Share of this turn's body that did not cross the link.
    pub fn saved_pct(&self) -> f64 {
        if self.body_bytes == 0 {
            return 0.0;
        }
        self.saved() as f64 * 100.0 / self.body_bytes as f64
    }
}

/// Bounded ring of recent turns.
#[derive(Default)]
pub struct TurnLog {
    turns: Mutex<Vec<Turn>>,
    cap: usize,
}

impl TurnLog {
    pub fn new(cap: usize) -> Self {
        TurnLog { turns: Mutex::new(Vec::new()), cap: cap.max(1) }
    }

    pub fn push(&self, t: Turn) {
        let mut g = self.turns.lock().expect("turn log poisoned");
        g.push(t);
        if g.len() > self.cap {
            let extra = g.len() - self.cap;
            g.drain(0..extra);
        }
    }

    pub fn recent(&self, n: usize) -> Vec<Turn> {
        let g = self.turns.lock().expect("turn log poisoned");
        let start = g.len().saturating_sub(n);
        g[start..].to_vec()
    }

    pub fn cap(&self) -> usize {
        self.cap
    }
}

/// Everything the console can look at and touch.
pub struct Console {
    pub counters: Arc<Counters>,
    pub store: Arc<Store>,
    pub turns: Arc<TurnLog>,
    /// The listeners this process serves, when it is the agent-side end. The
    /// buttons act on all of them; a peer process has none.
    pub apps: Vec<Arc<crate::local::App>>,
}

impl Console {
    pub fn new(counters: Arc<Counters>, store: Arc<Store>, turns: Arc<TurnLog>) -> Console {
        Console { counters, store, turns, apps: Vec::new() }
    }

    pub fn with_apps(mut self, apps: Vec<Arc<crate::local::App>>) -> Console {
        self.apps = apps;
        self
    }
}

/// One aggregated row: by path or by profile.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Bucket {
    pub key: String,
    pub requests: u64,
    pub body_bytes: u64,
    pub wire_bytes: u64,
    pub refs: u64,
    pub refs_hit: u64,
    pub pushed: u64,
    pub repairs: u64,
    pub split_requests: u64,
    /// Share of the body that stayed off the link. A field, not a getter, so
    /// `/stats` consumers (and `muka stats`) see it without recomputing.
    pub saved_pct: f64,
    pub hit_ratio: f64,
}

impl Bucket {
    pub fn saved_bytes(&self) -> u64 {
        self.body_bytes.saturating_sub(self.wire_bytes)
    }
}

/// Group the turn ring by an arbitrary key, biggest saver first.
pub fn buckets(turns: &[Turn], key: impl Fn(&Turn) -> &str) -> Vec<Bucket> {
    let mut map: std::collections::HashMap<String, Bucket> = std::collections::HashMap::new();
    for t in turns {
        let k = key(t).to_string();
        let b = map.entry(k).or_insert_with(|| Bucket { key: key(t).to_string(), ..Default::default() });
        b.requests += 1;
        b.body_bytes += t.body_bytes;
        b.wire_bytes += t.wire_bytes;
        b.refs += u64::from(t.refs);
        b.refs_hit += u64::from(t.refs_hit);
        b.pushed += u64::from(t.pushed);
        b.repairs += u64::from(t.repairs);
        b.split_requests += u64::from(t.split);
    }
    let mut out: Vec<Bucket> = map
        .into_values()
        .map(|mut b| {
            b.saved_pct = if b.body_bytes == 0 {
                0.0
            } else {
                b.saved_bytes() as f64 * 100.0 / b.body_bytes as f64
            };
            b.hit_ratio = if b.refs == 0 {
                0.0
            } else {
                b.refs_hit as f64 * 100.0 / b.refs as f64
            };
            b
        })
        .collect();
    out.sort_by(|a, b| b.saved_bytes().cmp(&a.saved_bytes()).then_with(|| a.key.cmp(&b.key)));
    out
}

/// An inline SVG polyline: no chart library, and the console has to work on a
/// machine that is busy streaming a prompt.
pub fn sparkline(values: &[f64], w: u32, h: u32, color: &str) -> String {
    if values.is_empty() {
        return format!("<svg width=\"{w}\" height=\"{h}\"></svg>");
    }
    let max = values.iter().cloned().fold(0.0f64, f64::max).max(1.0);
    // A single turn would otherwise land at x=0 and draw nothing at all.
    let step = if values.len() > 1 { w as f64 / (values.len() - 1) as f64 } else { 0.0 };
    let offset = if values.len() == 1 { w as f64 / 2.0 } else { 0.0 };
    let pts: Vec<String> = values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let x = offset + i as f64 * step;
            let y = h as f64 - (v / max) * (h as f64 - 2.0) - 1.0;
            format!("{x:.1},{y:.1}")
        })
        .collect();
    format!(
        "<svg width=\"{w}\" height=\"{h}\" viewBox=\"0 0 {w} {h}\"><polyline fill=\"none\" stroke=\"{color}\" stroke-width=\"1.5\" points=\"{}\"/></svg>",
        pts.join(" ")
    )
}

/// `GET /` console, `GET /stats` JSON, `GET /metrics` Prometheus,
/// `POST /shadow?on=0|1`, `POST /reset?drop=1`.
pub async fn serve(
    listen: &str,
    console: Arc<Console>,
    shutdown: Arc<tokio::sync::Notify>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    let local = listener.local_addr()?;
    if !local.ip().is_loopback() {
        tracing::warn!(
            %local,
            "metrics console is reachable off-loopback: it can toggle shadow mode and \
             drop the cache, so bind it to 127.0.0.1 unless this network is trusted"
        );
    }
    tracing::info!(listen = %local, "muka metrics listening");
    let shutdown = shutdown.notified();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = shutdown.as_mut() => return Ok(()),
            accepted = listener.accept() => {
                let (sock, _) = accepted?;
                let console = console.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(sock);
                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                        let console = console.clone();
                        async move {
                            let (parts, _) = req.into_parts();
                            Ok::<Response<crate::local::Body>, std::convert::Infallible>(
                                handle(parts.method, parts.uri, console).await,
                            )
                        }
                    });
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                });
            }
        }
    }
}

/// A snapshot for `/stats` and for the page's own numbers.
#[derive(Serialize)]
struct StatsView {
    summary: String,
    counters: Snapshot,
    store: muka_store::Stats,
    /// The RAM ceiling the store evicts against, so the page can say how full
    /// the cache is rather than just how big it happens to be.
    store_limit: u64,
    shadow: bool,
    per_path: Vec<Bucket>,
    per_profile: Vec<Bucket>,
    turns: Vec<Turn>,
}

fn view(console: &Console) -> StatsView {
    let turns = console.turns.recent(console.turns.cap());
    StatsView {
        summary: console.counters.summary(),
        counters: console.counters.snapshot(),
        store: console.store.stats(),
        store_limit: console.store.limit_bytes(),
        shadow: console.apps.iter().any(|a| a.hub().shadow()),
        per_path: buckets(&turns, |t| t.path.as_str()),
        per_profile: buckets(&turns, |t| t.profile.as_str()),
        turns,
    }
}

/// The console's whole HTTP surface, split out from `serve` so the actions can
/// be tested without a socket.
pub async fn handle(
    method: Method,
    uri: Uri,
    console: Arc<Console>,
) -> Response<crate::local::Body> {
    let path = uri.path().to_string();
    let query = uri.query().unwrap_or("").to_string();
    let post = method == Method::POST;
    match (post, path.as_str()) {
        (false, "/metrics") => text(StatusCode::OK, console.counters.prometheus()),
        (false, "/healthz") => text(StatusCode::OK, "ok\n"),
        (false, "/stats") => json(&view(&console)),
        (false, "/") => html(console_page(&view(&console))),
        (true, "/shadow") => {
            if console.apps.is_empty() {
                return text(StatusCode::BAD_REQUEST, "这个进程没有 agent 端监听，切不了影子模式\n");
            }
            let on = match query_param(&query, "on") {
                Some("1") | Some("true") => true,
                Some("0") | Some("false") => false,
                _ => !console.apps.iter().any(|a| a.hub().shadow()),
            };
            for a in &console.apps {
                a.hub().set_shadow(on);
            }
            json(&serde_json::json!({ "shadow": on }))
        }
        (true, "/reset") => {
            if console.apps.is_empty() {
                return text(StatusCode::BAD_REQUEST, "这个进程没有可重置的缓存\n");
            }
            let drop_store = matches!(query_param(&query, "drop"), Some("1") | Some("true"));
            let mut dropped = 0u64;
            for a in &console.apps {
                dropped += a.reset_cache(drop_store).await;
            }
            json(&serde_json::json!({ "dropped_blocks": dropped, "dropped_store": drop_store }))
        }
        _ => text(StatusCode::NOT_FOUND, format!("no route {path}\n")),
    }
}

fn query_param<'a>(q: &'a str, want: &str) -> Option<&'a str> {
    q.split('&')
        .find_map(|kv| kv.split_once('=').filter(|(k, _)| *k == want).map(|(_, v)| v))
}

fn json(v: &impl Serialize) -> Response<crate::local::Body> {
    match serde_json::to_string_pretty(v) {
        Ok(s) => text(StatusCode::OK, s),
        Err(e) => text(StatusCode::INTERNAL_SERVER_ERROR, format!("{{\"error\":\"{e}\"}}")),
    }
}

fn html(body: String) -> Response<crate::local::Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(crate::local::full(body))
        .unwrap_or_else(|_| Response::new(crate::local::full("error")))
}

fn text(status: StatusCode, body: impl Into<String>) -> Response<crate::local::Body> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(crate::local::full(body.into()))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(crate::local::full("error"))
                .unwrap()
        })
}

/// The splitter's machine-readable reasons, translated for the page. An
/// unknown one shows as-is rather than being hidden.
fn skip_label(reason: &str) -> &str {
    match reason {
        "path" => "接口不在去重范围",
        "disabled" => "已关闭去重",
        "too_small" => "请求体太小",
        "shadow" => "影子模式",
        "rebuild failed" => "重建失败，改整包",
        other => other,
    }
}

/// The console page: server-rendered so it is readable with JS off, and polling
/// `/stats` so the numbers move while a session runs.
fn console_page(v: &StatsView) -> String {
    let saved: Vec<f64> = v.turns.iter().map(|t| t.saved_pct()).collect();
    let wire: Vec<f64> = v.turns.iter().map(|t| t.wire_bytes as f64).collect();
    let row = |b: &Bucket| {
        format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.1}%</td><td>{} / {} ({:.0}%)</td><td>{}</td><td>{}</td></tr>",
            b.key,
            b.requests,
            human(b.body_bytes),
            human(b.wire_bytes),
            b.saved_pct,
            b.refs_hit,
            b.refs,
            b.hit_ratio,
            b.pushed,
            b.repairs
        )
    };
    let table = |rows: &[Bucket]| -> String {
        if rows.is_empty() {
            return "<tr><td colspan=8 class=muted>还没有记录</td></tr>".to_string();
        }
        rows.iter().map(row).collect::<Vec<_>>().join("")
    };
    let turns = if v.turns.is_empty() {
        "<tr><td colspan=10 class=muted>暂无数据：把 agent 的 base_url 指到这个监听端口</td></tr>".to_string()
    } else {
        v.turns
            .iter()
            .rev()
            .map(|t| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{} / {}</td><td>{}</td><td>{:.1}%</td></tr>",
                    t.profile,
                    t.seq,
                    t.path,
                    human(t.body_bytes),
                    human(t.wire_bytes),
                    if t.split { "拆分" } else { "整包" },
                    t.skip_reason.as_deref().map(skip_label).unwrap_or("-"),
                    t.refs_hit,
                    t.refs,
                    t.pushed,
                    t.saved_pct(),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let snap = &v.counters;
    format!(
        "<!doctype html><meta charset=utf-8><title>muka-ai-trim 控制台</title>\
<style>body{{font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,\"Microsoft YaHei\",sans-serif;margin:1.5rem 2rem;background:#12141a;color:#dfe3ea}}\
h1{{font-size:17px;margin:0 .4rem 0 0;display:inline}}h2{{font-size:12px;color:#8b94a5;margin:1.6rem 0 .4rem;letter-spacing:.06em}}\
table{{border-collapse:collapse;min-width:72%}}td,th{{padding:2px 14px 2px 0;border-bottom:1px solid #262a34;text-align:right}}\
td:first-child,th:first-child{{text-align:left}}tr:hover td{{background:#1a1d25}}\
.big{{font-size:24px;color:#7dd88f;margin:0}}\
button{{font:inherit;background:#1f242e;color:#dfe3ea;border:1px solid #333a48;border-radius:6px;padding:4px 10px;cursor:pointer}}\
button:hover{{border-color:#7dd88f}}svg{{vertical-align:bottom}}.muted{{color:#8b94a5}}p{{margin:.3rem 0}}</style>\
<h1>muka-ai-trim</h1><span class=muted id=mode>{mode}</span>\
<p class=big>{summary}</p>\
<p class=muted>内存缓存 {blocks} 块 / {size}（上限 {limit}，LRU 淘汰，不落盘）&middot; 本进程重建 {rebuilds} &middot; 重建失败 {failures} &middot; 链路错误 {link_err} &middot; 上游错误 {up_err} &middot; 链路 {link_ms}ms / 上游 {up_ms}ms</p>\
<p><button onclick=\"act('/shadow')\">切换影子模式</button> <button onclick=\"act('/reset')\">重推（保留对端缓存）</button> <button onclick=\"act('/reset?drop=1')\">清空两端缓存</button> <span class=muted>共 {body_total}，省下 {saved_total}</span></p>\
<h2>每轮节省 %</h2>{spark_saved}\
<h2>每轮链路上的字节</h2>{spark_wire}\
<h2>按接口</h2><table><tr><th>接口</th><th>请求数</th><th>请求体</th><th>链路</th><th>节省</th><th>引用命中</th><th>上传</th><th>补传</th></tr>{by_path}</table>\
<h2>按 profile</h2><table><tr><th>profile</th><th>请求数</th><th>请求体</th><th>链路</th><th>节省</th><th>引用命中</th><th>上传</th><th>补传</th></tr>{by_profile}</table>\
<h2>最近若干轮</h2><table><tr><th>profile</th><th>序号</th><th>接口</th><th>请求体</th><th>链路</th><th>方式</th><th>跳过原因</th><th>引用命中</th><th>上传</th><th>节省</th></tr>{turns}</table>\
<script>async function act(p){{await fetch(p,{{method:'POST'}});setTimeout(()=>location.reload(),150)}}\
async function load(){{try{{const j=await (await fetch('/stats')).json();document.getElementById('mode').textContent=j.shadow?'影子模式：只统计，请求仍整包发送':'正常工作（去重已生效）';}}catch(e){{}}}}\
load();setInterval(load,2000);setInterval(()=>location.reload(),6000);</script>",
        mode = if v.shadow { "影子模式：只统计，请求仍整包发送" } else { "正常工作（去重已生效）" },
        summary = v.summary,
        blocks = v.store.blocks,
        size = human(v.store.bytes),
        limit = human(v.store_limit),
        rebuilds = snap.rebuilds,
        failures = snap.rebuild_failures,
        link_err = snap.link_errors,
        up_err = snap.upstream_errors,
        link_ms = snap.link_ms,
        up_ms = snap.upstream_ms,
        saved_total = human(snap.body_bytes.saturating_sub(snap.wire_bytes)),
        body_total = human(snap.body_bytes),
        spark_saved = sparkline(&saved, 480, 46, "#7dd88f"),
        spark_wire = sparkline(&wire, 480, 46, "#6aa8e8"),
        by_path = table(&v.per_path),
        by_profile = table(&v.per_profile),
        turns = turns,
    )
}

/// Start the endpoint only when configured.
pub fn spawn_if_configured(cfg: &crate::config::Config, console: Arc<Console>) {
    let Some(listen) = cfg.metrics_listen.clone() else { return };
    tokio::spawn(async move {
        // Never notified: the console lives as long as the process.
        let never = Arc::new(tokio::sync::Notify::new());
        if let Err(e) = serve(&listen, console, never).await {
            tracing::warn!(error = %e, "metrics endpoint stopped");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, LocalConfig, Role};
    use crate::local::{App, Hub};
    use bytes::Bytes;
    use muka_store::Config as StoreConfig;
    use std::sync::atomic::Ordering::Relaxed;

    fn turn(profile: &str, path: &str, body: u64, wire: u64, refs: u32, hits: u32) -> Turn {
        Turn {
            profile: profile.into(),
            seq: 1,
            path: path.into(),
            status: 200,
            body_bytes: body,
            wire_bytes: wire,
            refs,
            refs_hit: hits,
            pushed: 0,
            repairs: 0,
            link_ms: 1,
            upstream_ms: 2,
            split: wire < body,
            skip_reason: None,
            store_blocks: 4,
        }
    }

    async fn call(method: Method, uri: &str, c: &Arc<Console>) -> Response<crate::local::Body> {
        handle(method, uri.parse().unwrap(), c.clone()).await
    }

    async fn body_of(r: Response<crate::local::Body>) -> String {
        use http_body_util::BodyExt;
        let collected = r.into_body().collect().await.unwrap();
        String::from_utf8_lossy(&collected.to_bytes()).to_string()
    }

    #[test]
    fn prometheus_output_names_every_counter() {
        let c = Counters::default();
        c.requests.fetch_add(3, Relaxed);
        c.wire_bytes.fetch_add(1200, Relaxed);
        let text = c.prometheus();
        assert!(text.contains("muka_requests_total 3"), "{text}");
        assert!(text.contains("muka_wire_bytes_total 1200"));
        let types = text.lines().filter(|l| l.starts_with("# TYPE")).count();
        let values = text.lines().filter(|l| !l.starts_with('#')).count();
        assert_eq!(types, values, "every metric needs HELP, TYPE and a value");
        assert!(types >= 17, "counters went missing: {types}");
        assert!(c.summary().contains("节省"), "{}", c.summary());
    }

    #[test]
    fn turn_log_keeps_only_the_newest() {
        let log = TurnLog::new(3);
        for i in 0..10u64 {
            let mut t = turn("default", "/v1/chat/completions", 1000, 10, 4, 3);
            t.seq = i;
            log.push(t);
        }
        let recent = log.recent(10);
        assert_eq!(recent.len(), 3);
        assert_eq!(log.cap(), 3);
        assert_eq!(recent.last().unwrap().seq, 9);
        assert_eq!(recent[0].saved(), 990);
        assert!((recent[0].saved_pct() - 99.0).abs() < 0.01, "{}", recent[0].saved_pct());
    }

    #[test]
    fn buckets_group_by_path_and_rank_by_savings() {
        let mut cold = turn("a", "/v1/chat/completions", 1000, 10, 5, 4);
        cold.pushed = 3;
        let turns = vec![
            cold,
            turn("a", "/v1/chat/completions", 1000, 20, 5, 3),
            turn("b", "/v1/embeddings", 500, 480, 2, 1),
            turn("b", "/v1/models", 100, 100, 0, 0),
        ];
        let by_path = buckets(&turns, |t| t.path.as_str());
        assert_eq!(by_path.len(), 3);
        assert_eq!(by_path[0].key, "/v1/chat/completions", "biggest saver first");
        assert_eq!(by_path[0].requests, 2);
        assert_eq!(by_path[0].body_bytes, 2000);
        assert_eq!(by_path[0].wire_bytes, 30);
        assert_eq!(by_path[0].refs, 10);
        assert_eq!(by_path[0].refs_hit, 7);
        assert_eq!(by_path[0].pushed, 3, "uploads are summed per key");
        assert!((by_path[0].hit_ratio - 70.0).abs() < 0.01);
        assert!((by_path[0].saved_pct - 98.5).abs() < 0.01);
        // A path that never deduplicates shows as zero, which is the number
        // that tells you an endpoint is being passed through.
        let models = by_path.iter().find(|b| b.key == "/v1/models").unwrap();
        assert_eq!(models.saved_bytes(), 0);
        assert_eq!(models.hit_ratio, 0.0);
        let by_profile = buckets(&turns, |t| t.profile.as_str());
        assert_eq!(by_profile.len(), 2);
        assert_eq!(by_profile[0].key, "a");
    }

    #[test]
    fn sparkline_draws_one_point_per_turn() {
        assert!(sparkline(&[], 100, 20, "#fff").contains("<svg"));
        let s = sparkline(&[10.0, 20.0, 5.0], 100, 20, "#0f0");
        assert_eq!(s.matches(',').count(), 3, "three points: {s}");
        assert!(s.contains("stroke=\"#0f0\""));
        // A single turn must still be visible, and must not divide by zero.
        assert!(sparkline(&[3.0], 100, 20, "#0f0").contains("points=\"50.0"), "one point is centred");
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human(512), "512 B");
        assert_eq!(human(2048), "2.0 KiB");
        assert_eq!(human(5 * 1024 * 1024), "5.0 MiB");
        assert!(human(3 * 1024 * 1024 * 1024).ends_with("GiB"));
    }

    #[test]
    fn query_params_are_read_from_the_post_url() {
        assert_eq!(query_param("on=1", "on"), Some("1"));
        assert_eq!(query_param("drop=1&x=2", "drop"), Some("1"));
        assert_eq!(query_param("x=2", "drop"), None);
        assert_eq!(query_param("", "on"), None);
    }

    #[tokio::test]
    async fn the_console_page_renders_real_numbers() {
        let counters = Arc::new(Counters::default());
        counters.body_bytes.fetch_add(100_000, Relaxed);
        counters.wire_bytes.fetch_add(1_000, Relaxed);
        let turns = Arc::new(TurnLog::new(10));
        turns.push(turn("agent-a", "/v1/chat/completions", 50_000, 500, 12, 11));
        let c = Arc::new(Console::new(
            counters,
            Arc::new(Store::new(StoreConfig::default())),
            turns,
        ));
        let page = body_of(call(Method::GET, "/", &c).await).await;
        assert!(page.contains("muka-ai-trim"));
        assert!(page.contains("<svg"), "savings curve missing");
        assert!(page.contains("/v1/chat/completions"), "per-endpoint table missing");
        assert!(page.contains("agent-a"), "per-profile table missing");
        assert!(page.contains("节省 99.00%"), "summary line: {page}");
        assert!(page.contains("切换影子模式"), "the page has to be in Chinese: {page}");
        assert!(!page.contains("{summary}") && !page.contains("{mode}"), "unsubstituted placeholder");
        let stats: serde_json::Value =
            serde_json::from_str(&body_of(call(Method::GET, "/stats", &c).await).await).unwrap();
        assert_eq!(stats["per_path"][0]["key"], "/v1/chat/completions");
        assert_eq!(stats["turns"][0]["profile"], "agent-a");
        assert_eq!(stats["shadow"], false);
        assert_eq!(call(Method::GET, "/nope", &c).await.status(), StatusCode::NOT_FOUND);
        assert_eq!(call(Method::GET, "/healthz", &c).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn actions_are_refused_when_there_is_no_local_end() {
        // The peer process has counters and a store but no listeners: the
        // buttons must not pretend to work there.
        let c = Arc::new(Console::new(
            Arc::new(Counters::default()),
            Arc::new(Store::new(StoreConfig::default())),
            Arc::new(TurnLog::new(4)),
        ));
        assert_eq!(call(Method::POST, "/shadow", &c).await.status(), StatusCode::BAD_REQUEST);
        assert_eq!(call(Method::POST, "/reset?drop=1", &c).await.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn shadow_toggle_and_cache_reset_reach_every_profile() {
        let cfg = Arc::new(Config {
            role: Role::Local,
            pairing_token: Some("0123456789abcdef".into()),
            ..Default::default()
        });
        let hub = Hub::new(cfg).unwrap();
        let a = App::for_profile(
            &hub,
            LocalConfig { name: "a".into(), listen: "127.0.0.1:1".into(), ..Default::default() },
        )
        .unwrap();
        let b = App::for_profile(
            &hub,
            LocalConfig { name: "b".into(), listen: "127.0.0.1:2".into(), ..Default::default() },
        )
        .unwrap();
        let c = Arc::new(
            Console::new(hub.counters.clone(), hub.store.clone(), hub.turns.clone())
                .with_apps(vec![a.clone(), b.clone()]),
        );

        // Something has to be in the cache before a reset can drop it.
        let data = Bytes::from(vec![b'q'; 500]);
        let d = muka_split::digest_of(muka_split::BlockKind::Raw, &data);
        hub.store.insert(muka_split::Block::raw(d, muka_split::BlockKind::Raw, data));
        assert_eq!(hub.store.len(), 1);
        // Profiles sharing a peer share the presence view; both must forget.
        a.link.presence.note_pushed([d]);
        assert!(!a.link.presence.is_empty(), "the optimistic view was empty");
        assert_eq!(a.link.presence.len(), b.link.presence.len(), "same view object");

        let r = body_of(call(Method::POST, "/shadow", &c).await).await;
        assert!(r.contains("\"shadow\": true"), "{r}");
        assert!(hub.shadow(), "one hub, both profiles");
        assert!(b.hub().shadow());

        let r = body_of(call(Method::POST, "/reset?drop=1", &c).await).await;
        assert!(r.contains("\"dropped_blocks\": 1"), "{r}");
        assert_eq!(hub.store.len(), 0, "the shared store was cleared once, for both");
        assert!(a.link.presence.is_empty() && b.link.presence.is_empty(), "next turns re-push");
    }

    #[tokio::test]
    async fn shadow_mode_changes_what_a_request_would_send() {
        let cfg = Arc::new(Config {
            role: Role::Local,
            pairing_token: Some("0123456789abcdef".into()),
            ..Default::default()
        });
        let hub = Hub::new(cfg).unwrap();
        let a = App::for_profile(&hub, LocalConfig::default()).unwrap();
        // Twelve exchanges of real-ish size: big enough that referencing them
        // is a win, which is the case the split exists for.
        let body = Bytes::from(format!(
            "{{\"messages\":[{}]}}",
            (0..12)
                .map(|i| format!("{{\"role\":\"user\",\"content\":\"line {i} {}\"}}", "pad ".repeat(400)))
                .collect::<Vec<_>>()
                .join(",")
        ));
        let off = a.prepare(muka_proto::msg::Kind::ChatCompletions, &a.cfg.policy, &body);
        assert!(off.payload.is_split(), "a big body should be split by default");
        hub.set_shadow(true);
        let on = a.prepare(muka_proto::msg::Kind::ChatCompletions, &a.cfg.policy, &body);
        assert!(!on.payload.is_split(), "shadow mode must send the body whole");
        assert_eq!(on.skip_reason.as_deref(), Some("shadow"));
    }
}
