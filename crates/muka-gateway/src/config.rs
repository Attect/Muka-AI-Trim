//! Configuration shared by both ends.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Which end of the slow link this process is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// Agent side: listens for the agent, splits requests, dials the peer.
    #[default]
    Local,
    /// Proxy side: accepts the link, rebuilds requests, talks to the upstream.
    Remote,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalConfig {
    /// Label shown in the console and the turn log.
    #[serde(default = "default_name")]
    pub name: String,
    /// Where the agent points its base URL.
    pub listen: String,
    /// Peer (remote) address to dial.
    pub peer: String,
    /// Dial-out through a bind address is rarely needed; kept for IPv6 pinning.
    #[serde(default)]
    pub bind: Option<String>,
    #[serde(default = "default_max_conns")]
    pub max_conns: usize,
    /// Requests whose body is smaller than this skip the split machinery.
    #[serde(default = "default_min_body")]
    pub min_body_bytes: usize,
    /// zstd on the upload side of the link. Off only if a peer is CPU-starved,
    /// which on a machine whose job is to sit next to a fast pipe is unlikely.
    #[serde(default = "default_true")]
    pub compress: bool,
    /// TLS on the laptop<->peer hop. Requires `tls_ca_file`: the peer's `ca.der`.
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub tls_ca_file: Option<PathBuf>,
    /// Compute and log the saving, but still send the body whole. The way to
    /// decide whether this tool is worth trusting before letting it touch
    /// traffic.
    #[serde(default)]
    pub shadow: bool,
}

fn default_name() -> String {
    "default".to_string()
}
fn default_max_conns() -> usize {
    8
}
fn default_min_body() -> usize {
    4096
}
fn default_true() -> bool {
    true
}

impl Default for LocalConfig {
    fn default() -> Self {
        LocalConfig {
            name: "default".into(),
            listen: "127.0.0.1:18788".into(),
            peer: "127.0.0.1:18789".into(),
            bind: None,
            max_conns: default_max_conns(),
            min_body_bytes: default_min_body(),
            shadow: false,
            compress: true,
            tls: false,
            tls_ca_file: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct RemoteConfig {
    pub listen: String,
    /// Real API base, e.g. `https://api.openai.com`.
    pub upstream: String,
    /// When set, this key replaces the agent's credential, in whichever header
    /// that API uses (`Authorization: Bearer` for the OpenAI family,
    /// `x-api-key` for the Messages API), so the
    /// real key never crosses the slow link and is never on the laptop.
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub api_key_file: Option<PathBuf>,
    /// TLS on the laptop<->peer hop. Key material is generated into `tls_dir`
    /// on first start; copy the printed `ca.der` to the other machine.
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub tls_dir: Option<PathBuf>,
}

impl Default for RemoteConfig {
    fn default() -> Self {
        RemoteConfig {
            listen: "0.0.0.0:18789".into(),
            upstream: "https://api.openai.com".into(),
            api_key: None,
            api_key_file: None,
            tls: false,
            tls_dir: None,
        }
    }
}

/// The pairing secret plus the store and policy for one process.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub role: Role,
    #[serde(default)]
    pub local: LocalConfig,
    /// Extra listeners in the same process: several agents, several base URLs,
    /// one shared block cache. Content addressing is what makes sharing safe -
    /// the same screenshot two agents use is pushed to the peer once.
    /// When non-empty this *replaces* `local` as the set of listeners.
    #[serde(default)]
    pub profiles: Vec<LocalConfig>,
    #[serde(default)]
    pub remote: RemoteConfig,
    #[serde(default)]
    pub store: muka_store::Config,
    #[serde(default)]
    pub policy: muka_split::Policy,
    /// Shared secret printed by `muka pair`, checked with a salted hash so it
    /// never appears on the wire.
    #[serde(default)]
    pub pairing_token: Option<String>,
    /// `muka-trim local` refuses to serve a peer that has not seen this token.
    #[serde(default = "default_epoch")]
    pub epoch_salt: u64,
    #[serde(default)]
    pub metrics_listen: Option<String>,
    #[serde(default = "default_turnlog")]
    pub turn_log_cap: usize,
    #[serde(default)]
    pub verbose: bool,
}

fn default_epoch() -> u64 {
    1
}
fn default_turnlog() -> usize {
    200
}

impl Default for Config {
    fn default() -> Self {
        Config {
            role: Role::Local,
            local: LocalConfig::default(),
            profiles: Vec::new(),
            remote: RemoteConfig::default(),
            store: muka_store::Config::default(),
            policy: muka_split::Policy::default(),
            pairing_token: None,
            epoch_salt: 1,
            metrics_listen: None,
            turn_log_cap: default_turnlog(),
            verbose: false,
        }
    }
}

impl Config {
    /// Load TOML or JSON by extension.
    pub fn load(path: &std::path::Path) -> anyhow::Result<Config> {
        let text = std::fs::read_to_string(path)?;
        let cfg: Config = match path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("toml")
        {
            "json" => serde_json::from_str(&text)?,
            _ => toml_from_str(&text)?,
        };
        Ok(cfg)
    }

    /// The listeners this process should serve.
    pub fn effective_profiles(&self) -> Vec<LocalConfig> {
        if self.profiles.is_empty() {
            return vec![self.local.clone()];
        }
        self.profiles.clone()
    }

    /// Fail fast on configurations that would silently do something different
    /// from what the user meant.
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.policy.enabled && self.role == Role::Local {
            anyhow::bail!("policy.enabled = false makes the local end a plain proxy; use `--passthrough` instead");
        }
        if self.role == Role::Remote {
            let u = &self.remote.upstream;
            if !(u.starts_with("http://") || u.starts_with("https://")) {
                anyhow::bail!("remote.upstream must start with http:// or https://, got {u}");
            }
        }
        match self.role {
            Role::Local => {
                let mut seen: Vec<String> = Vec::new();
                for pr in self.effective_profiles() {
                    if pr.listen == pr.peer {
                        anyhow::bail!(
                            "profile {:?}: listen and peer are both {} - that loops back onto itself",
                            pr.name,
                            pr.listen
                        );
                    }
                    if pr.tls && pr.tls_ca_file.is_none() {
                        anyhow::bail!("profile {:?}: tls is on but tls_ca_file is unset: copy the peer's ca.der over first", pr.name);
                    }
                    if seen.contains(&pr.listen) {
                        anyhow::bail!("two profiles listen on {}: the second would silently never be reached", pr.listen);
                    }
                    seen.push(pr.listen.clone());
                }
            }
            Role::Remote => {
                if self.remote.tls && self.pairing_token.is_none() {
                    anyhow::bail!("remote.tls without a pairing_token is pointless: the certificate is only worth anything if peers also prove the secret");
                }
            }
        }
        if self.pairing_token.as_deref().unwrap_or("").len() < 16 {
            anyhow::bail!("pairing_token must be at least 16 chars (run `muka pair`)");
        }
        if self.store.max_bytes < self.store.max_block_bytes {
            anyhow::bail!(
                "store.max_block_bytes ({} B) cannot exceed store.max_bytes ({} B): such a block could never be cached",
                self.store.max_block_bytes,
                self.store.max_bytes
            );
        }
        Ok(())
    }
}

fn toml_from_str(s: &str) -> anyhow::Result<Config> {
    Ok(toml::from_str(s)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_coherent() {
        let c = Config::default();
        assert_eq!(c.role, Role::Local);
        assert_eq!(c.local.listen, "127.0.0.1:18788");
        assert!(c.policy.enabled);
        // The cache is bounded to 200 MiB of RAM and a single block has to fit
        // inside it, which is what `validate` enforces.
        assert_eq!(c.store.max_bytes, muka_store::MEMORY_LIMIT_BYTES);
        assert!(c.store.max_bytes >= c.store.max_block_bytes);
    }

    #[test]
    fn profiles_add_listeners_and_are_validated() {
        let mut c = Config::default();
        c.pairing_token = Some("0123456789abcdef".into());
        assert_eq!(c.effective_profiles().len(), 1, "no profiles means just [local]");
        c.profiles = vec![
            LocalConfig { name: "agent-a".into(), listen: "127.0.0.1:18788".into(), ..Default::default() },
            LocalConfig { name: "agent-b".into(), listen: "127.0.0.1:18795".into(), ..Default::default() },
        ];
        assert_eq!(c.effective_profiles().len(), 2);
        c.validate().unwrap();
        c.profiles[1].listen = "127.0.0.1:18788".into();
        assert!(c.validate().unwrap_err().to_string().contains("two profiles"), "duplicate listeners");
        c.profiles[1].listen = "127.0.0.1:18789".into();
        assert!(c.validate().unwrap_err().to_string().contains("loops back"), "listen == peer is a loop");
    }

    #[test]
    fn json_roundtrip_and_validation() {
        let mut c = Config::default();
        c.pairing_token = Some("0123456789abcdef".into());
        let j = serde_json::to_string(&c).unwrap();
        let back: Config = serde_json::from_str(&j).unwrap();
        assert_eq!(back.local.peer, c.local.peer);
        assert_eq!(back.store.ttl_secs, c.store.ttl_secs);
        back.validate().unwrap();
        let mut bad = c.clone();
        bad.remote.upstream = "api.openai.com".into();
        bad.role = Role::Remote;
        assert!(bad.validate().unwrap_err().to_string().contains("http://"));
        let mut weak = c.clone();
        weak.pairing_token = Some("short".into());
        assert!(weak.validate().unwrap_err().to_string().contains("16 chars"));
    }
}
