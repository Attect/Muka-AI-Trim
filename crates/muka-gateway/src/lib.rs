//! `muka-gateway` - the two ends of the slow link.
//!
//! [`local`] runs where the agent runs: it listens on loopback, splits each
//! request into a block program, and pushes only what the peer does not already
//! have. [`remote`] runs on the proxy machine: it rebuilds the request
//! byte-for-byte, checks it against the declared digest, and forwards it to the
//! real API.
//!
//! The link is plain TCP by default and TLS on request ([`tls`]): the peer
//! generates its own CA and the laptop pins it, so neither end has to trust a
//! public hierarchy. Turn it on (`tls = true` both sides plus
//! `local.tls_ca_file`) unless the socket is already inside an SSH tunnel.

use std::sync::Arc;

pub mod config;
pub mod local;
pub mod metrics;
pub mod remote;
pub mod session;
pub mod tls;
pub mod upstream;

pub use config::{Config, LocalConfig, RemoteConfig, Role};
pub use local::{pairing_proof, App, Hub};
pub use metrics::{Bucket, Console, Counters, Turn, TurnLog};
pub use remote::{MockUpstream, Peer};
pub use session::{Conn, Fail, LinkState, Payload, Rebuilt, SessionError, SharedBloom};
pub use upstream::Upstream;

/// Run the agent-side end until `shutdown` fires.
///
/// One process, one cache, and as many listeners as there are profiles: several
/// agents with several base URLs then share the same deduplication instead of
/// each paying for their own copy of the same history.
pub async fn run_local(cfg: Arc<Config>, shutdown: Arc<tokio::sync::Notify>) -> anyhow::Result<()> {
    cfg.validate()?;
    let hub = Hub::new(cfg.clone())?;
    let apps = App::all(&hub)?;
    metrics::spawn_if_configured(
        &cfg,
        Arc::new(
            metrics::Console::new(hub.counters.clone(), hub.store.clone(), hub.turns.clone())
                .with_apps(apps.clone()),
        ),
    );
    // One signal, every listener: `Notify` wakes all waiters, a channel would
    // only deliver to one of them.
    let mut tasks = Vec::new();
    for app in apps {
        let shutdown = shutdown.clone();
        tasks.push(tokio::spawn(async move { local::serve(app, shutdown).await }));
    }
    for t in tasks {
        t.await.map_err(|e| anyhow::anyhow!("listener task: {e}"))??;
    }
    Ok(())
}

/// Run the proxy-machine end until `shutdown` fires.
pub async fn run_remote(cfg: Arc<Config>, shutdown: Arc<tokio::sync::Notify>) -> anyhow::Result<()> {
    cfg.validate()?;
    let peer = Peer::new(cfg.clone())?;
    metrics::spawn_if_configured(
        &cfg,
        Arc::new(metrics::Console::new(peer.counters.clone(), peer.store.clone(), Arc::new(TurnLog::new(256)))),
    );
    peer.serve(shutdown).await
}
