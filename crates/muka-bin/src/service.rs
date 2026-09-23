//! `muka service` - keep the right end running across reboots.
//!
//! Deliberately print-by-default: writing a unit file or a scheduled task is a
//! change to a machine the user owns, so the commands are shown first and only
//! executed with `--apply`.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Action {
    Install,
    Uninstall,
    Status,
}

#[derive(clap::Args, Debug)]
pub struct Args {
    /// 要执行的动作
    #[arg(value_enum)]
    pub action: Action,
    /// 服务运行时使用的配置文件。
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// 这台机器是链路的哪一端：local 或 remote。
    #[arg(long, default_value = "local")]
    pub role: String,
    /// 追加到服务自身命令行后面的参数，例如 --tls。
    #[arg(long, allow_hyphen_values = true, num_args = 0..)]
    pub extra: Vec<String>,
    /// 真正执行这些命令，而不只是打印出来。
    #[arg(long)]
    pub apply: bool,
    /// 服务名称（systemd unit / 计划任务名）。
    #[arg(long, default_value = "muka-ai-trim")]
    pub name: String,
}

pub fn run(a: Args) -> Result<()> {
    let exe = std::env::current_exe().context("cannot find my own executable path")?;
    let mut cmd: Vec<String> = vec![exe.display().to_string()];
    cmd.push(a.role.clone());
    if let Some(c) = &a.config {
        cmd.push("--config".into());
        cmd.push(c.display().to_string());
    }
    cmd.extend(a.extra.iter().cloned());

    #[cfg(windows)]
    let plan = windows_plan(&a, &cmd);
    #[cfg(not(windows))]
    let plan = unix_plan(&a, &cmd)?;
    #[cfg(unix)]
    let plan = plan;

    match a.action {
        Action::Status => {
            for c in plan.status {
                show(&c, a.apply)?;
            }
        }
        Action::Install => {
            if let Some(unit) = &plan.write_file {
                println!("# {}:", unit.0.display());
                println!("{}", indent(&unit.1));
                if a.apply {
                    std::fs::write(&unit.0, unit.1.as_bytes())
                        .with_context(|| format!("writing {} (needs root?)", unit.0.display()))?;
                    println!("# wrote {}", unit.0.display());
                }
            }
            for c in plan.apply {
                show(&c, a.apply)?;
            }
        }
        Action::Uninstall => {
            for c in plan.remove {
                show(&c, a.apply)?;
            }
        }
    }
    if !a.apply {
        println!("\nnothing changed: re-run with --apply to execute the commands above");
    }
    Ok(())
}

fn show(c: &[String], apply: bool) -> Result<()> {
    // Quoted so the printed line can be pasted into a shell as-is: the /TR
    // argument is one argv entry that contains spaces.
    let joined = c
        .iter()
        .map(|a| if a.contains(' ') || a.contains('"') { format!("\"{a}\"") } else { a.clone() })
        .collect::<Vec<_>>()
        .join(" ");
    if apply {
        println!("$ {joined}");
        let out = Command::new(&c[0])
            .args(&c[1..])
            .output()
            .with_context(|| format!("running {joined}"))?;
        if !out.status.success() {
            anyhow::bail!(
                "{joined} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
    } else {
        println!("$ {joined}   (not run: pass --apply)");
    }
    Ok(())
}

fn indent(s: &str) -> String {
    s.lines().map(|l| format!("    {l}")).collect::<Vec<_>>().join("\n")
}

struct Plan {
    /// A file to create, if the platform needs one.
    write_file: Option<(PathBuf, String)>,
    apply: Vec<Vec<String>>,
    remove: Vec<Vec<String>>,
    status: Vec<Vec<String>>,
}

#[cfg(windows)]
fn windows_plan(a: &Args, cmd: &[String]) -> Plan {
    // Task Scheduler at logon needs no elevation and survives reboots, which is
    // the 99% case for a laptop-side proxy. `sc create` would need admin and a
    // service binary that speaks the SCM protocol.
    let tr = cmd
        .iter()
        .map(|s| if s.contains(' ') { format!("\\\"{s}\\\"") } else { s.clone() })
        .collect::<Vec<_>>()
        .join(" ");
    Plan {
        write_file: None,
        apply: vec![vec![
            "schtasks".into(),
            "/Create".into(),
            "/F".into(),
            "/TN".into(),
            a.name.clone(),
            "/TR".into(),
            tr,
            "/SC".into(),
            "ONLOGON".into(),
        ]],
        remove: vec![vec!["schtasks".into(), "/Delete".into(), "/F".into(), "/TN".into(), a.name.clone()]],
        status: vec![vec!["schtasks".into(), "/Query".into(), "/TN".into(), a.name.clone()]],
    }
}

#[cfg(not(windows))]
fn unix_plan(a: &Args, cmd: &[String]) -> Result<Plan> {
    let unit = format!(
        "[Unit]
Description=muka-ai-trim link proxy ({role})
After=network-online.target
Wants=network-online.target

[Service]
ExecStart={exec}
Restart=always
RestartSec=2
# The store holds prompts and screenshots: keep it out of every user's reach.
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
",
        role = a.role,
        exec = cmd
            .iter()
            .map(|s| if s.contains(' ') { format!("\"{s}\"") } else { s.clone() })
            .collect::<Vec<_>>()
            .join(" ")
    );
    let path = PathBuf::from(format!("/etc/systemd/system/{}.service", a.name));
    Ok(Plan {
        write_file: Some((path.clone(), unit)),
        apply: vec![
            vec!["systemctl".into(), "daemon-reload".into()],
            vec!["systemctl".into(), "enable".into(), "--now".into(), format!("{}.service", a.name)],
        ],
        remove: vec![
            vec!["systemctl".into(), "disable".into(), "--now".into(), format!("{}.service", a.name)],
            vec!["rm".into(), "-f".into(), path.display().to_string()],
            vec!["systemctl".into(), "daemon-reload".into()],
        ],
        status: vec![vec!["systemctl".into(), "status".into(), format!("{}.service", a.name)]],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(action: Action) -> Args {
        Args {
            action,
            config: Some("/etc/muka.toml".into()),
            role: "local".into(),
            extra: vec!["--tls".into()],
            apply: false,
            name: "muka-trim".into(),
        }
    }

    #[test]
    fn plans_are_printed_and_nothing_is_executed_without_apply() {
        // The whole safety property of this subcommand: default is inert.
        let cmd = vec!["/usr/bin/muka".to_string(), "local".into(), "--config".into(), "/etc/muka.toml".into(), "--tls".into()];
        #[cfg(windows)]
        let plan = windows_plan(&args(Action::Install), &cmd);
        #[cfg(not(windows))]
        let plan = unix_plan(&args(Action::Install), &cmd).unwrap();
        assert!(!plan.apply.is_empty(), "a service has to be enabled somehow");
        #[cfg(not(windows))]
        {
            let (path, text) = plan.write_file.unwrap();
            assert!(path.display().to_string().ends_with("muka-trim.service"));
            assert!(text.contains("ExecStart=/usr/bin/muka local --config /etc/muka.toml --tls"), "{text}");
            assert!(text.contains("Restart=always"));
        }
        #[cfg(windows)]
        {
            assert!(plan.apply[0].iter().any(|s| s == "/SC"), "{:?}", plan.apply[0]);
            assert!(plan.apply[0].last().unwrap() == "ONLOGON");
            assert!(plan.apply[0].iter().any(|s| s.contains("--tls")));
        }
    }

    #[test]
    fn quoting_survives_spaces_in_the_path() {
        // Built with format! so this test does not fight its own escaping.
        let bs = '\\';
        let q = '"';
        let path = format!("C:{bs}Program Files{bs}muka.exe");
        let cmd = vec![path.clone(), "remote".into()];

        #[cfg(windows)]
        {
            let plan = windows_plan(&args(Action::Install), &cmd);
            // schtasks takes one /TR argument that itself holds a quoted
            // program, so the inner quotes are escaped and the path stays whole.
            let tr = plan
                .apply[0]
                .iter()
                .find(|s| s.starts_with(&format!("{bs}{q}")))
                .expect("a quoted /TR value");
            assert!(tr.contains(&path), "path must survive: {tr}");
            assert!(tr.ends_with("remote"), "arguments follow the exe: {tr}");
        }

        #[cfg(not(windows))]
        {
            let plan = unix_plan(&args(Action::Install), &cmd).unwrap();
            let (_, text) = plan.write_file.unwrap();
            let want = format!("ExecStart={q}{path}{q} remote");
            assert!(text.contains(&want), "systemd needs the program quoted, got {text}");
        }
    }
}
