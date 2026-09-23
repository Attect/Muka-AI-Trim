//! `muka-ai-trim pair` - one question at a time, ending in a config file that
//! the executable next to it will pick up without being told.
//!
//! There is no shared state to distribute beyond one token: the proxy end
//! generates it, the laptop pastes it. So the wizard is two runs of the same
//! command, and each run only ever writes the one file that machine reads.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use muka_gateway::config::{Config, Role};

const DEFAULT_UPSTREAM: &str = "https://api.openai.com";
const REMOTE_LISTEN: &str = "0.0.0.0:18789";
const LOCAL_LISTEN: &str = "127.0.0.1:18788";
const REMOTE_METRICS: &str = "127.0.0.1:18791";
const LOCAL_METRICS: &str = "127.0.0.1:18790";

#[derive(Clone, Debug)]
pub struct Args {
    pub yes: bool,
    pub role: Option<String>,
    pub token: Option<String>,
    pub bits: u32,
    pub peer: Option<String>,
    pub upstream: Option<String>,
    pub listen: Option<String>,
    pub metrics: Option<String>,
    pub key: Option<String>,
}

/// `--print`: the two fragments on stdout, writing nothing - the way to set up
/// from a machine that is neither end, or over SSH.
pub fn fragments(a: &Args) -> Result<()> {
    let token = a.token.clone().unwrap_or_else(|| new_token(a.bits));
    let upstream = a.upstream.clone().unwrap_or_else(|| DEFAULT_UPSTREAM.into());
    let (remote_listen, local_listen) = match a.role.as_deref() {
        Some("remote") => (a.listen.clone().unwrap_or_else(|| REMOTE_LISTEN.into()), LOCAL_LISTEN.into()),
        Some("local") => (REMOTE_LISTEN.into(), a.listen.clone().unwrap_or_else(|| LOCAL_LISTEN.into())),
        _ => (REMOTE_LISTEN.into(), LOCAL_LISTEN.into()),
    };
    println!(
        "# 两段配置分开存，各自放到那一台机器上 muka-ai-trim.exe 的同一目录，文件名 muka-ai-trim.config。\n\
         # 块缓存只在内存里（上限 200 MiB，LRU 淘汰），不落盘、不用配目录；重启后重新学习一遍。\n\
         # 更省事的做法：在两台机器上各跑一次 `muka-ai-trim pair`，它会问你几个值并把文件写好。\n\
         \n\
         # ==== 代理端（有快链路、能直连上游的那台）====\n\
         role = \"remote\"\n\
         pairing_token = \"{token}\"\n\
         metrics_listen = \"{REMOTE_METRICS}\"\n\
         \n\
         [remote]\n\
         listen = \"{remote_listen}\"\n\
         upstream = \"{upstream}\"\n\
         # 可选：真实 key 只留这一端，agent 随便填占位值。用 `pair` 生成时它会写到\n\
         # 同目录的 muka-ai-trim.key 里，这里给出引用：\n\
         # api_key_file = \"muka-ai-trim.key\"\n\
         \n\
         # ==== 本地端（跑 agent 的那台）====\n\
         role = \"local\"\n\
         pairing_token = \"{token}\"\n\
         metrics_listen = \"{LOCAL_METRICS}\"\n\
         \n\
         [local]\n\
         listen = \"{local_listen}\"\n\
         peer = \"{}\"\n\
         \n\
         # 启动：代理端 `muka-ai-trim remote`，本地端 `muka-ai-trim local`\n\
         # 然后让 agent 走本地端：{} OPENAI_BASE_URL=http://{local_listen}/v1\n",
        a.peer.clone().unwrap_or_else(|| "代理机IP:18789".into()),
        if cfg!(windows) { "set" } else { "export" },
    );
    Ok(())
}

/// Ask for whatever was not already given on the command line, then write it
/// down next to the executable.
pub fn run(a: &Args, out: &Path) -> Result<()> {
    let role = match a.role.as_deref() {
        Some(r) => parse_role(r)?,
        None if std::io::stdin().is_terminal() => ask_role()?,
        None => bail!("要指定这一台是哪一端：加 --role remote 或 --role local（或直接在终端里运行）"),
    };
    let interactive = std::io::stdin().is_terminal() && !a.yes;
    match role {
        Role::Remote => wizard_remote(a, out, interactive),
        Role::Local => wizard_local(a, out, interactive),
    }
}

fn parse_role(s: &str) -> Result<Role> {
    match s {
        "remote" => Ok(Role::Remote),
        "local" => Ok(Role::Local),
        other => bail!("--role 只能是 remote 或 local，收到 {other}"),
    }
}

fn wizard_remote(a: &Args, out: &Path, interactive: bool) -> Result<()> {
    let upstream = resolve(a.upstream.as_deref(), Some(DEFAULT_UPSTREAM), "上游 API 地址", interactive)?;
    let listen = resolve(a.listen.as_deref(), Some(REMOTE_LISTEN), "本机监听地址（笔记本要能连到这里的端口）", interactive)?;
    let metrics = resolve(a.metrics.as_deref(), Some(REMOTE_METRICS), "控制台监听地址（不想开就填 off）", interactive)?;
    let key = match &a.key {
        Some(k) => Some(k.clone()),
        None if interactive => ask_optional("真实 API key（直接回车＝不在这台机器上放 key，agent 自己带）")?,
        None => None,
    };
    let token = a.token.clone().unwrap_or_else(|| new_token(a.bits));
    let key_file = match &key {
        Some(k) => Some(write_key_file(out.parent().unwrap_or(Path::new(".")), k)?),
        None => None,
    };

    let mut text = format!(
        "# 代理端配置：与 muka-ai-trim.exe 放在同一目录就会被自动读取。\n\
         role = \"remote\"\n\
         pairing_token = \"{token}\"\n"
    );
    if metrics != "off" {
        text.push_str(&format!("metrics_listen = \"{metrics}\"\n"));
    }
    text.push_str(&format!("\n[remote]\nlisten = \"{listen}\"\nupstream = \"{upstream}\"\n"));
    if let Some(k) = &key_file {
        text.push_str(&format!("api_key_file = \"{}\"\n", display(k)));
    }
    write_and_check(out, &text, a.yes)?;

    println!(
        "\n把这串配对令牌抄给笔记本那台（两边必须一样）：\n\n    {token}\n\n\
         笔记本上执行 `muka-ai-trim pair`，选本地端，粘贴这个令牌即可。\n\
         这台机器现在可以启动了：muka-ai-trim remote"
    );
    Ok(())
}

fn wizard_local(a: &Args, out: &Path, interactive: bool) -> Result<()> {
    let peer = resolve(a.peer.as_deref(), None, "代理端地址（IP:端口，就是刚才那台监听的端口）", interactive)?;
    let listen = resolve(a.listen.as_deref(), Some(LOCAL_LISTEN), "本地监听地址（agent 的 base_url 指向它）", interactive)?;
    let metrics = resolve(a.metrics.as_deref(), Some(LOCAL_METRICS), "控制台监听地址（不想开就填 off）", interactive)?;
    let token = match &a.token {
        Some(t) => t.clone(),
        None => loop {
            let t = prompt("代理端给出的 pairing_token")?;
            if t.len() >= 16 {
                break t;
            }
            println!("  太短了（{} 个字符）：至少 16 位，否则任何能连上这个端口的人都能借道。", t.len());
            if !interactive {
                bail!("非交互环境请用 --token 提供配对令牌");
            }
        },
    };

    let mut text = format!(
        "# 本地端配置：与 muka-ai-trim.exe 放在同一目录就会被自动读取。\n\
         role = \"local\"\n\
         pairing_token = \"{token}\"\n"
    );
    if metrics != "off" {
        text.push_str(&format!("metrics_listen = \"{metrics}\"\n"));
    }
    text.push_str(&format!("\n[local]\nlisten = \"{listen}\"\npeer = \"{peer}\"\n"));
    write_and_check(out, &text, a.yes)?;

    let page = if metrics == "off" {
        "这一台没开控制台（metrics 填了 off）".to_string()
    } else {
        format!("浏览器打开 http://{metrics}/")
    };
    println!(
        "\n下一步：\n  1. 启动：muka-ai-trim local\n  2. 让 agent 走它：{} OPENAI_BASE_URL=http://{listen}/v1\n  \
         3. 看效果：{page}\n\
         再开一个独立实例：把整个文件夹复制一份，只改上面两个端口。",
        if cfg!(windows) { "set" } else { "export" }
    );
    Ok(())
}

/// The value from the command line, or the default, or - only in a terminal -
/// a question.
fn resolve(given: Option<&str>, fallback: Option<&str>, what: &str, interactive: bool) -> Result<String> {
    if let Some(v) = given {
        return Ok(v.to_string());
    }
    if !interactive {
        return fallback.map(str::to_string).context("非交互环境缺少必要参数，请用命令行给全");
    }
    let asked = prompt(&match fallback {
        Some(d) => format!("{what} [默认 {d}]"),
        None => what.to_string(),
    })?;
    if !asked.is_empty() {
        return Ok(asked);
    }
    fallback.map(str::to_string).with_context(|| format!("{what} 没有默认值，必须填"))
}

fn ask_role() -> Result<Role> {
    loop {
        let a = prompt("这台机器是哪一端？[1] 代理端（有快链路、直连上游） [2] 本地端（跑 agent）")?;
        match a.trim() {
            "1" | "remote" | "r" | "代理" | "代理端" => return Ok(Role::Remote),
            "2" | "local" | "l" | "本地" | "本地端" => return Ok(Role::Local),
            "" => bail!("请输入 1 或 2"),
            other => println!("  没听清：{other}。输入 1（代理端）或 2（本地端）。"),
        }
    }
}

fn ask_optional(what: &str) -> Result<Option<String>> {
    let v = prompt(what)?;
    Ok((!v.is_empty()).then_some(v))
}

fn prompt(what: &str) -> Result<String> {
    print!("{what}：");
    std::io::stdout().flush()?;
    let mut line = String::new();
    let n = std::io::stdin().lock().read_line(&mut line)?;
    if n == 0 {
        bail!("stdin 已关闭，{what} 没拿到答案：非交互环境请用命令行参数给全（--role/--peer/--token/...）");
    }
    Ok(line.trim().to_string())
}

/// The key lives in its own file precisely so it never ends up in a config
/// someone screenshots or commits.
fn write_key_file(dir: &Path, key: &str) -> Result<PathBuf> {
    let path = dir.join("muka-ai-trim.key");
    std::fs::write(&path, key.trim().as_bytes())
        .with_context(|| format!("写入 {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).ok();
    }
    Ok(path)
}

fn write_and_check(out: &Path, text: &str, force: bool) -> Result<()> {
    if out.exists() && !force {
        if !std::io::stdin().is_terminal() {
            bail!("{} 已存在：要覆盖请加 --yes", display(out));
        }
        let answer = ask_optional(&format!("{} 已存在，覆盖吗？[y/N]", display(out)))?;
        if !matches!(answer.as_deref(), Some("y") | Some("Y") | Some("yes")) {
            bail!("没有覆盖，配置未改动");
        }
    }
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(out, text).with_context(|| format!("写入 {}", display(out)))?;
    // Proves the file we just wrote is one the program will accept, before the
    // operator walks to the other machine.
    let cfg = Config::load(out).with_context(|| format!("配置文件读不通：{}", display(out)))?;
    cfg.validate().with_context(|| format!("配置文件不自洽：{}", display(out)))?;
    println!("已写入并自检通过：{}", display(out));
    println!("{}", text.trim_end());
    Ok(())
}

fn new_token(bits: u32) -> String {
    use rand::RngCore;
    let mut v = vec![0u8; (bits / 8).max(8) as usize];
    rand::rng().fill_bytes(&mut v);
    v.iter().map(|b| format!("{b:02x}")).collect()
}

/// Forward slashes: valid in TOML without escaping, and they read the same on
/// both platforms.
fn display(p: &Path) -> String {
    p.display().to_string().replace('\\', "/")
}
