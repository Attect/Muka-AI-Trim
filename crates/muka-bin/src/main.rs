//! `muka-ai-trim` - the command line for both machines.
//!
//! One folder is one instance: the executable, its `muka-ai-trim.config`, and
//! the block store it writes are all found relative to that folder, so copying
//! the folder gives you a second, fully independent instance.
//!
//! ```text
//! proxy machine   muka-ai-trim remote  --listen 0.0.0.0:18789 --upstream https://api.openai.com
//! laptop          muka-ai-trim local   --listen 127.0.0.1:18788 --peer proxy:18789
//! agent           OPENAI_BASE_URL=http://127.0.0.1:18788/v1
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

mod pair;
mod service;
use muka_gateway::config::{Config, Role};
use muka_gateway::local;

/// Auto-discovered config file, looked for next to the executable.
const CONFIG_NAME: &str = "muka-ai-trim.config";

#[derive(Parser)]
#[command(name = "muka-ai-trim", version, about = "把慢速链路（笔记本↔代理机）上每个 agent 请求里重复的那一半去掉")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// TOML 或 JSON 配置文件；不指定时自动读取运行目录下的 muka-ai-trim.config。
    /// 下面的命令行参数会覆盖它。
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// 日志级别：`trace|debug|info|warn|error`
    #[arg(long, global = true, default_value = "info")]
    log: String,
}

#[derive(Subcommand)]
enum Cmd {
    /// 运行面向 agent 的一端（跑 agent 的那台机器）。
    Local {
        /// 监听地址，例如 127.0.0.1:18788
        #[arg(long)]
        listen: Option<String>,
        /// 对端（代理机）地址，例如 203.0.113.7:18789
        #[arg(long)]
        peer: Option<String>,
        /// 不做去重，退化成纯转发代理。
        #[arg(long)]
        passthrough: bool,
        /// 只计算并记录节省，请求仍整包发送（先用它验证再放行流量）。
        #[arg(long)]
        shadow: bool,
        /// 在本机开控制台与指标端点，例如 127.0.0.1:18790
        #[arg(long)]
        metrics: Option<String>,
        /// 配对令牌，两端必须一致
        #[arg(long)]
        token: Option<String>,
        /// 关闭上传侧的 zstd 压缩。
        #[arg(long)]
        no_compress: bool,
        /// 与对端之间启用 TLS（需配合 --ca）。
        #[arg(long)]
        tls: bool,
        /// 对端的 ca.der，手工拷贝过来。
        #[arg(long)]
        ca: Option<PathBuf>,
        /// 只服务配置文件 [[profiles]] 列表中指定名字的 profile。
        #[arg(long)]
        profile: Option<String>,
    },
    /// 运行面向上游的一端（有快链路的那台代理机）。
    Remote {
        /// 监听地址，例如 0.0.0.0:18789
        #[arg(long)]
        listen: Option<String>,
        /// 真实 API 地址，例如 https://api.openai.com
        #[arg(long)]
        upstream: Option<String>,
        /// 真实 key 只留在这一端：agent 可以随便发占位值。
        #[arg(long, conflicts_with = "api_key_file")]
        api_key: Option<String>,
        /// 从文件读取真实 key（避免出现在命令行/进程列表里）。
        #[arg(long)]
        api_key_file: Option<PathBuf>,
        /// 在本机开控制台与指标端点，例如 127.0.0.1:18791
        #[arg(long)]
        metrics: Option<String>,
        /// 配对令牌，两端必须一致
        #[arg(long)]
        token: Option<String>,
        /// 链路启用 TLS；首次启动生成密钥并打印需要拷到笔记本的 ca.der。
        #[arg(long)]
        tls: bool,
        /// TLS 密钥材料的存放目录。
        #[arg(long)]
        tls_dir: Option<PathBuf>,
    },
    /// 在这台机器上生成配置：问几个值，算出配对令牌，写好 muka-ai-trim.config。
    /// 先在代理端跑一次，再在本地端跑一次并把令牌粘过去。
    Pair {
        /// 只把两段配置片段打印到屏幕上，不写任何文件。
        #[arg(long)]
        print: bool,
        /// 已存在配置文件时直接覆盖，不再询问。
        #[arg(long)]
        yes: bool,
        /// 这台机器是哪一端：remote＝代理端（直连上游），local＝本地端（跑 agent）。
        #[arg(long, value_parser = ["remote", "local"])]
        role: Option<String>,
        /// 配对令牌。本地端要从代理端抄过来；不给就生成一个新的（或交互时粘贴）。
        #[arg(long)]
        token: Option<String>,
        /// 自动生成令牌的长度（字节）
        #[arg(long, default_value_t = 32)]
        bits: u32,
        /// 代理端地址，例如 192.168.1.20:18789（本地端要填）
        #[arg(long)]
        peer: Option<String>,
        /// 真实 API 地址（代理端要填）
        #[arg(long)]
        upstream: Option<String>,
        /// 这一端的监听地址（代理端默认 0.0.0.0:18789，本地端默认 127.0.0.1:18788）
        #[arg(long)]
        listen: Option<String>,
        /// 控制台与指标的监听地址；填 off 就不开这一页
        #[arg(long)]
        metrics: Option<String>,
        /// 真实 API key，写进同目录的 muka-ai-trim.key（只在代理端用；不给就不放 key）
        #[arg(long)]
        key: Option<String>,
    },
    /// 打印（加 --apply 才真正注册）让一端常驻的系统服务。
    ///
    /// unix 用 systemd unit，Windows 用登录时的计划任务；默认只打印命令。
    Service {
        #[command(flatten)]
        args: service::Args,
    },
    /// 检查配置文件、store、split 自检算法与对端可达性。
    Doctor {
        /// 要探测可达性的对端地址。
        #[arg(long)]
        peer: Option<String>,
    },
    /// 拉取运行中一端的计数器并打印摘要。
    Stats {
        /// 目标端的指标地址，例如 127.0.0.1:18790
        #[arg(long, default_value = "127.0.0.1:18790")]
        metrics: String,
    },
    /// 用真实的 splitter 回放抓到的请求体（来自 `muka-ai-trim tee`）。
    ///
    /// 显示在你自己的流量上本可以省下多少，并证明重建逐字节一致——
    /// 在让它接触真实请求之前，先看这个。
    Replay {
        /// 抓包目录
        #[arg(default_value = "./muka-tee")]
        dir: PathBuf,
        /// 详细列出收益最大的前 N 条。
        #[arg(long, default_value_t = 12)]
        top: usize,
        /// 把上传侧的 zstd 也计入节省。
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        compress: bool,
    },
    /// 录制模式：原样转发给上游，并把每个请求体落盘。
    ///
    /// 用来在信任去重之前，拿真实流量做测量和回放（`muka-ai-trim replay`）。
    Tee {
        /// 监听地址
        #[arg(long, default_value = "127.0.0.1:18791")]
        listen: String,
        /// 转发的上游地址
        #[arg(long, default_value = "https://api.openai.com")]
        upstream: String,
        /// 请求体落盘目录
        #[arg(long, default_value = "./muka-tee")]
        dir: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log));
    tracing_subscriber::fmt().with_env_filter(filter).with_target(false).init();

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(run(cli))
}

async fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Service { args } => service::run(args),
        Cmd::Pair { print, yes, role, token, bits, peer, upstream, listen, metrics, key } => {
            let a = pair::Args { yes, role, token, bits, peer, upstream, listen, metrics, key };
            if print {
                return pair::fragments(&a);
            }
            pair::run(&a, &program_dir().join(CONFIG_NAME))
        }

        Cmd::Local { listen, peer, passthrough, shadow, metrics, token, tls, ca, no_compress, profile } => {
            let mut cfg = load_or_default(cli.config.as_deref(), Role::Local)?;
            cfg.role = Role::Local;
            if let Some(l) = listen {
                cfg.local.listen = l;
            }
            if let Some(p) = peer {
                cfg.local.peer = p;
            }
            if let Some(t) = token {
                cfg.pairing_token = Some(t);
            }
            if let Some(m) = metrics {
                cfg.metrics_listen = Some(m);
            }
            if passthrough {
                cfg.policy.enabled = false;
            }
            cfg.local.shadow = cfg.local.shadow || shadow;
            if let Some(name) = profile.as_deref() {
                cfg.local.name = name.into();
                cfg.profiles.retain(|p| p.name == name);
                anyhow::ensure!(
                    !cfg.profiles.is_empty() || cfg.local.name == name,
                    "no profile named {name} in the config"
                );
            }
            if tls {
                cfg.local.tls = true;
                cfg.local.tls_ca_file = ca.clone();
            }
            if no_compress {
                cfg.local.compress = false;
            }
            let cfg = Arc::new(cfg);
            if cfg.local.shadow {
                tracing::warn!("shadow mode: saving is measured, requests still go whole");
            }
            let shutdown = Arc::new(tokio::sync::Notify::new());
            spawn_ctrl_c(shutdown.clone());
            muka_gateway::run_local(cfg, shutdown).await
        }

        Cmd::Remote { listen, upstream, api_key, api_key_file, metrics, token, tls, tls_dir } => {
            let mut cfg = load_or_default(cli.config.as_deref(), Role::Remote)?;
            cfg.role = Role::Remote;
            if let Some(l) = listen {
                cfg.remote.listen = l;
            }
            if let Some(u) = upstream {
                cfg.remote.upstream = u;
            }
            if api_key.is_some() || api_key_file.is_some() {
                cfg.remote.api_key = api_key;
                cfg.remote.api_key_file = api_key_file;
            }
            if let Some(t) = token {
                cfg.pairing_token = Some(t);
            }
            if let Some(m) = metrics {
                cfg.metrics_listen = Some(m);
            }
            if tls {
                cfg.remote.tls = true;
                cfg.remote.tls_dir = tls_dir;
            }
            let shutdown = Arc::new(tokio::sync::Notify::new());
            spawn_ctrl_c(shutdown.clone());
            muka_gateway::run_remote(Arc::new(cfg), shutdown).await
        }

        Cmd::Doctor { peer } => doctor(cli.config.as_deref(), peer.as_deref()).await,

        Cmd::Stats { metrics } => {
            let text = http_get(&metrics).await.context("could not reach the metrics endpoint (set metrics_listen)")?;
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
                println!("{text}");
                return Ok(());
            };
            // The same numbers the page shows, minus the CSS.
            println!("{}", v["summary"].as_str().unwrap_or("(no summary)"));
            println!("影子模式：{}", v["shadow"].as_bool().unwrap_or(false));
            if let Some(s) = v["store"].as_object() {
                println!(
                    "块缓存：{} 块，{} 字节",
                    s["blocks"].as_u64().unwrap_or(0),
                    s["bytes"].as_u64().unwrap_or(0)
                );
            }
            for (label, key) in [("按接口", "per_path"), ("按 profile", "per_profile")] {
                println!("\n{label}:");
                for b in v[key].as_array().into_iter().flatten() {
                    println!(
                        "  {:<28} {:>4} req  {:>10} B body  {:>8} B wire  {:>5.1}% saved  refs {}/{}",
                        b["key"].as_str().unwrap_or("?"),
                        b["requests"].as_u64().unwrap_or(0),
                        b["body_bytes"].as_u64().unwrap_or(0),
                        b["wire_bytes"].as_u64().unwrap_or(0),
                        b["saved_pct"].as_f64().unwrap_or(0.0),
                        b["refs_hit"].as_u64().unwrap_or(0),
                        b["refs"].as_u64().unwrap_or(0),
                    );
                }
            }
            Ok(())
        }

        Cmd::Replay { dir, top, compress } => replay(&dir, top, compress),
        Cmd::Tee { listen, upstream, dir } => tee(listen, upstream, dir).await,
    }
}

fn load_or_default(cli: Option<&std::path::Path>, role: Role) -> Result<Config> {
    let found = match cli {
        Some(p) => Some(p.to_path_buf()),
        None => discovered_config(),
    };
    let mut cfg = match &found {
        Some(p) => Config::load(p).with_context(|| format!("reading {}", p.display()))?,
        None => Config::default(),
    };
    cfg.role = role;
    Ok(cfg)
}

/// Every listener waits on the same notify: a channel would wake only one.
fn spawn_ctrl_c(shutdown: Arc<tokio::sync::Notify>) {
    tokio::spawn(async move {
        loop {
            if tokio::signal::ctrl_c().await.is_err() {
                return;
            }
            tracing::info!("interrupted; shutting down");
            shutdown.notify_waiters();
        }
    });
}

/// The folder an instance lives in: its config is read from here without being
/// named, so a copy of the folder is a separate instance.
fn program_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// `--config` wins; otherwise a config sitting next to the executable (or in
/// the working directory, for a shell that ran it from elsewhere) is picked up
/// without being named. Next-to-exe first, because a scheduled task starts with
/// a working directory the operator did not choose.
fn discovered_config() -> Option<PathBuf> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    [program_dir(), cwd]
        .into_iter()
        .map(|d| d.join(CONFIG_NAME))
        .find(|p| p.is_file())
}

/// Sanity-check everything that can be checked without sending a prompt.
async fn doctor(path: Option<&std::path::Path>, peer: Option<&str>) -> Result<()> {
    let cfg = load_or_default(path, Config::default().role)?;
    println!("role              = {:?}", cfg.role);
    println!("policy enabled    = {}", cfg.policy.enabled);
    println!("min body          = {} B", cfg.policy.min_body_bytes);
    println!("history floor     = {} B", cfg.policy.min_history_block_bytes);
    println!(
        "store             = 内存，上限 {} MiB（LRU + TTL 淘汰，不落盘）",
        cfg.store.max_bytes >> 20
    );

    let store = muka_store::Store::new(cfg.store.clone());
    println!("store blocks      = {}", store.len());

    // The invariant the whole design rests on, on a synthetic multi-turn body.
    let mut msgs: Vec<serde_json::Value> = Vec::new();
    for i in 0..12 {
        msgs.push(serde_json::json!({"role":"user","content":format!("turn {i} {}", "blabla ".repeat(60))}));
        if i % 4 == 0 {
            msgs.push(serde_json::json!({"role":"user","content":[{"type":"image_url","image_url":{"url":format!("data:image/png;base64,{}", "A".repeat(30_000))}}]}));
        }
    }
    let body = serde_json::to_vec(&serde_json::json!({"model":"m","messages":msgs,"tools":[{"function":{"name":"x","description":"d ".repeat(500)}}]})).unwrap();
    let bloom = Arc::new(muka_gateway::SharedBloom::default());
    let presence = Arc::new(muka_split::Optimistic::new(Box::new((*bloom).clone())));
    let ctx = muka_split::Ctx { peer: &*presence, local: &store, policy: &cfg.policy };
    let mut total_split = 0u64;
    for turn in 1..=4usize {
        let b = serde_json::to_vec(&serde_json::json!({"model":"m","messages":&msgs[..turn * 3],"tools":[]})).unwrap();
        match muka_split::split_body(&b, &ctx) {
            muka_split::Action::Split(o) => {
                anyhow::ensure!(muka_split::check_identity(&b, &o, &store), "identity check failed at turn {turn}");
                for blk in &o.to_push {
                    store.insert(blk.clone());
                }
                presence.note_pushed(o.to_push.iter().map(|b| b.digest));
                total_split += o.stats.wire_bytes();
                println!("  turn {turn}: body {:>7} B -> wire {:>6} B  ({} refs, {} hit)", o.stats.body_len, o.stats.wire_bytes(), o.stats.refs, o.stats.refs_hit);
            }
            muka_split::Action::Passthrough(s) => println!("  turn {turn}: passthrough ({})", s.reason()),
        }
    }
    let _ = body;
    println!("rebuild identity  = ok (4 turns replayed)");
    let _ = total_split;

    let target = match (peer, cfg.role) {
        (Some(p), _) => p.to_string(),
        (None, Role::Local) => cfg.local.peer.clone(),
        (None, Role::Remote) => String::new(),
    };
    if !target.is_empty() {
        match tokio::time::timeout(std::time::Duration::from_secs(3), tokio::net::TcpStream::connect(&target)).await {
            Ok(Ok(_)) => println!("peer {target}       = reachable"),
            Ok(Err(e)) => println!("peer {target}       = UNREACHABLE ({e})"),
            Err(_) => println!("peer {target}       = timeout"),
        }
    }
    if cfg.pairing_token.as_deref().map(str::len).unwrap_or(0) < 16 {
        println!("pairing_token       = MISSING or short - run `muka-ai-trim pair`");
    } else {
        println!("pairing_token       = set");
    }
    println!(
        "\nlink transport: {}",
        if cfg.local.tls || cfg.remote.tls {
            "TLS, pinned to the peer's own CA - keep tls = true on both ends"
        } else {
            "plain TCP - set tls = true both sides and pin the peer's ca.der, or run this under an SSH tunnel"
        }
    );
    Ok(())
}

async fn http_get(addr: &str) -> Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut sock = tokio::net::TcpStream::connect(addr).await?;
    sock.write_all(format!("GET /stats HTTP/1.0\r\nHost: {addr}\r\n\r\n").as_bytes()).await?;
    let mut buf = Vec::new();
    sock.read_to_end(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf).to_string();
    Ok(text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or(text))
}

/// M0: forward to a real upstream and record every body, for measurement and
/// for the replay corpus. Nothing about the protocol is involved.
async fn tee(listen: String, upstream: String, dir: PathBuf) -> Result<()> {
    use http_body_util::{combinators::BoxBody, BodyExt, Full};
    use hyper::body::Bytes;

    type TeeBody = BoxBody<Bytes, hyper::Error>;
    fn tb(b: impl Into<Bytes>) -> TeeBody {
        BoxBody::new(Full::new(b.into()).map_err(|e| match e {}))
    }
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    std::fs::create_dir_all(&dir)?;
    let client: Client<_, TeeBody> = Client::builder(TokioExecutor::new()).build_http();
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    println!("recording on http://{listen}/v1 -> {upstream} into {}", dir.display());
    let mut n = 0u64;
    loop {
        let (sock, _) = listener.accept().await?;
        let client = client.clone();
        let upstream = upstream.clone();
        let dir = dir.clone();
        n += 1;
        let seq = n;
        tokio::spawn(async move {
            let io = hyper_util::rt::TokioIo::new(sock);
            let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let client = client.clone();
                let upstream = upstream.clone();
                let dir = dir.clone();
                async move {
                    let path = req.uri().path().to_string();
                    let (parts, body) = req.into_parts();
                    let bytes = body.collect().await.map(|c| c.to_bytes()).unwrap_or_default();
                    let _ = std::fs::write(dir.join(format!("{seq:06}-{path}.json")), &bytes);
                    let mut builder = hyper::Request::builder().method(parts.method).uri(format!("{upstream}{path}"));
                    for (k, v) in parts.headers.iter() {
                        if !local::DROP_REQUEST.contains(&k.as_str().to_ascii_lowercase().as_str()) {
                            builder = builder.header(k.as_str(), v);
                        }
                    }
                    let out = builder.body(tb(bytes)).unwrap();
                    let resp = match client.request(out).await {
                        Ok(resp) => {
                            let (rp, rb) = resp.into_parts();
                            let body = rb.collect().await.map(|c| c.to_bytes()).unwrap_or_default();
                            hyper::Response::from_parts(rp, tb(body))
                        }
                        Err(e) => hyper::Response::builder()
                            .status(hyper::StatusCode::BAD_GATEWAY)
                            .body(tb(format!("{{\"error\":\"tee upstream: {e}\"}}")))
                            .unwrap(),
                    };
                    Ok::<_, std::convert::Infallible>(resp)
                }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, svc).await;
        });
    }
}

/// One captured request.
#[derive(Clone, serde::Serialize)]
struct ReplayRow {
    file: String,
    body_bytes: u64,
    wire_bytes: u64,
    saved_pct: f64,
    refs: u32,
    refs_hit: u32,
    pushed: u32,
    rebuilt_ok: bool,
    reason: Option<String>,
}

impl ReplayRow {
    /// Bytes this capture did not have to send.
    fn saved_bytes(&self) -> u64 {
        self.body_bytes.saturating_sub(self.wire_bytes)
    }
}

/// Walk a `tee` capture directory in time order and run each body through the
/// same code path the local end uses, against a simulated peer that starts empty
/// and keeps whatever it was given. The interesting output is `rebuilt_ok`:
/// false here would mean the tool is unsafe for this traffic.
fn replay(dir: &std::path::Path, top: usize, compress: bool) -> Result<()> {
    let mut files: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    files.sort();
    anyhow::ensure!(!files.is_empty(), "no captured bodies in {}", dir.display());

    let policy = muka_split::Policy::default();
    let store = muka_store::Store::new(muka_store::Config::default());
    let peer = muka_store::Store::new(muka_store::Config::default());
    let bloom = Arc::new(muka_gateway::SharedBloom::default());
    let presence = Arc::new(muka_split::Optimistic::new(Box::new((*bloom).clone())));

    let mut rows = Vec::new();
    let mut tot_body = 0u64;
    let mut tot_wire = 0u64;
    let mut bad = 0u64;
    for path in &files {
        let body = std::fs::read(path)?;
        let ctx = muka_split::Ctx { peer: &*presence, local: &store, policy: &policy };
        let (wire, refs, hits, pushed, rebuilt, reason) = match muka_split::split_body(&body, &ctx) {
            muka_split::Action::Split(out) => {
                let ok = muka_split::check_identity(&body, &out, &store);
                for b in &out.to_push {
                    peer.insert(b.clone());
                    presence.note_pushed([b.digest]);
                }
                // The peer resolves from its own store only: that is the real
                // requirement, not a convenience check.
                let resolved = muka_split::resolve(&peer, &out.instrs, out.stats.body_len as usize + 1, 32)
                    .map(|b| b.as_ref() == &body[..])
                    .unwrap_or(false);
                let wire = wire_of(&out, compress);
                (
                    wire,
                    out.stats.refs,
                    out.stats.refs_hit,
                    out.stats.push_blocks,
                    ok && resolved,
                    None,
                )
            }
            muka_split::Action::Passthrough(sk) => (
                wire_whole(&body, compress),
                0,
                0,
                0,
                true,
                Some(sk.reason().to_string()),
            ),
        };
        if !rebuilt {
            bad += 1;
        }
        tot_body += body.len() as u64;
        tot_wire += wire;
        rows.push(ReplayRow {
            file: path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default(),
            body_bytes: body.len() as u64,
            wire_bytes: wire,
            saved_pct: if body.is_empty() { 0.0 } else { 100.0 - wire as f64 * 100.0 / body.len() as f64 },
            refs,
            refs_hit: hits,
            pushed,
            rebuilt_ok: rebuilt,
            reason,
        });
    }

    let mut ranked = rows.clone();
    // A compressed incompressible payload can cost more than the body, so
    // the saving has to saturate rather than wrap.
    ranked.sort_by(|a, b| b.saved_bytes().cmp(&a.saved_bytes()));
    println!(
        "{:<34} {:>10} {:>9} {:>7} {:>9}  {}",
        "file", "body", "wire", "saved", "hits", "note"
    );
    for r in ranked.iter().take(top) {
        println!(
            "{:<34} {:>10} {:>9} {:>6.1}% {:>9}  {}",
            truncate(&r.file, 34),
            r.body_bytes,
            r.wire_bytes,
            r.saved_pct,
            format!("{}/{}", r.refs_hit, r.refs),
            if r.rebuilt_ok { "".to_string() } else { "*** REBUILD FAILED ***".to_string() }
        );
    }
    println!(
        "
{} captures, {} B total body -> {} B on the link = {:.1}% saved{}{}",
        rows.len(),
        tot_body,
        tot_wire,
        if tot_body > 0 { 100.0 - tot_wire as f64 * 100.0 / tot_body as f64 } else { 0.0 },
        if compress { " (with zstd)" } else { "" },
        if bad > 0 { format!(", {bad} REBUILDS FAILED - do not enable") } else { ", every body rebuilt byte-exact".to_string() },
    );
    anyhow::ensure!(bad == 0, "reconstruction failed for {bad} of {} captures", rows.len());
    Ok(())
}

/// What a split body would really cost on the wire: the same frames the local
/// end builds, encoded and measured, optionally compressed.
fn wire_of(out: &muka_split::SplitOutput, compress: bool) -> u64 {
    let mut w = muka_gateway::session::upload_frame(
        muka_proto::Tag::Program,
        1,
        muka_proto::encode_program(&out.instrs),
        compress,
    )
    .encode()
    .len() as u64;
    for b in &out.to_push {
        w += muka_gateway::session::block_frame(b, 1, compress)
            .encode()
            .len() as u64;
    }
    w
}

/// Same for a verbatim body.
fn wire_whole(body: &[u8], compress: bool) -> u64 {
    body.chunks(muka_gateway::session::RELAY_CHUNK)
        .map(|c| {
            muka_gateway::session::upload_frame(muka_proto::Tag::RequestBody, 1, c.to_vec(), compress)
                .encode()
                .len() as u64
        })
        .sum()
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n { s.to_string() } else { format!("..{}", &s[s.len() - n + 2..]) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture(turn: usize) -> Vec<u8> {
        let msgs: Vec<serde_json::Value> = (0..turn)
            .map(|t| {
                serde_json::json!({"role": "user", "content": format!("turn {t} {}", "a tool result line
".repeat(40))})
            })
            .collect();
        serde_json::to_vec(&serde_json::json!({"model": "m", "messages": msgs})).unwrap()
    }

    #[test]
    fn replay_reports_savings_and_proves_reconstruction() {
        let dir = std::env::temp_dir().join(format!("muka-replay-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for t in 2..=5usize {
            std::fs::write(dir.join(format!("00000{t}-v1-chat-completions.json")), capture(t)).unwrap();
        }
        // Must not panic and must exit 0: a failed rebuild is an error, not a warning.
        replay(&dir, 3, true).expect("replay of a growing conversation");
        replay(&dir, 3, false).expect("replay without compression");

        // A non-JSON capture must be counted as passthrough, not fail the run.
        std::fs::write(dir.join("000099-v1-uploads.json"), vec![b'k'; 9000]).unwrap();
        std::fs::write(dir.join("000100-broken.json"), b"{ not json").unwrap();
        replay(&dir, 3, true).expect("garbage captures degrade, they do not abort");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn saved_bytes_never_wraps_when_compression_loses() {
        let r = ReplayRow {
            file: "x".into(),
            body_bytes: 100,
            wire_bytes: 900,
            saved_pct: -8.0,
            refs: 0,
            refs_hit: 0,
            pushed: 0,
            rebuilt_ok: true,
            reason: Some("too_small".into()),
        };
        assert_eq!(r.saved_bytes(), 0);
    }
}
