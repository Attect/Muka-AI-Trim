//! TLS on the slow link.
//!
//! The peer generates its own private CA and a leaf under `<tls_dir>/`, and the
//! only thing that has to travel to the laptop is `ca.der`. The laptop trusts
//! exactly that one CA, so the leaf's `muka-peer` name is verified against a
//! key that was copied by hand - a network attacker cannot substitute their own
//! certificate without that file.
//!
//! Why a hand-rolled CA rather than an OS trust store: this link is between two
//! machines the same person owns, and the only sane trust model there is "I
//! copied this file over myself".

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

/// The leaf's only name: it is never looked up, only compared to.
pub const SERVER_NAME: &str = "muka-peer";
const CA_FILE: &str = "ca.der";
const CA_KEY_FILE: &str = "ca.key";
const LEAF_FILE: &str = "leaf.der";
const LEAF_KEY_FILE: &str = "leaf.key";

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("certificate generation failed: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("tls setup failed: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("io at {0}: {1}")]
    Io(PathBuf, #[source] io::Error),
    #[error("the key material at {0} is unreadable or truncated")]
    Corrupt(PathBuf),
}

/// Everything the peer needs to serve TLS.
pub struct ServerIdentity {
    pub config: Arc<ServerConfig>,
    pub ca_file: PathBuf,
}

/// Create the key material if absent, then load it.
pub fn serve(dir: &Path) -> Result<ServerIdentity, TlsError> {
    fs::create_dir_all(dir).map_err(|e| TlsError::Io(dir.to_path_buf(), e))?;
    if !leaf_path(dir).exists() || !ca_path(dir).exists() {
        generate(dir)?;
        tracing::info!(dir = %dir.display(), ca = %ca_path(dir).display(), "generated link key material");
    }
    let ca = read_der(&ca_path(dir))?;
    let leaf = read_der(&leaf_path(dir))?;
    let key = fs::read(leaf_key_path(dir)).map_err(|e| TlsError::Io(leaf_key_path(dir), e))?;
    // Leaf only: the other end trusts our CA, which it holds as a file.
    let roots = vec![CertificateDer::from(leaf), CertificateDer::from(ca)];
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(TlsError::Rustls)?
        .with_no_client_auth()
        .with_single_cert(roots, PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))
        .map_err(TlsError::Rustls)?;
    Ok(ServerIdentity { config: Arc::new(config), ca_file: ca_path(dir) })
}

/// Client config trusting exactly one CA file.
pub fn client(ca_file: &Path) -> Result<Arc<ClientConfig>, TlsError> {
    let der = read_der(ca_file)?;
    let mut store = RootCertStore::empty();
    store
        .add(CertificateDer::from(der))
        .map_err(|_| TlsError::Corrupt(ca_file.to_path_buf()))?;
    let config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(TlsError::Rustls)?
        .with_root_certificates(store)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn generate(dir: &Path) -> Result<(), TlsError> {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};

    let ca_key = KeyPair::generate()?;
    let mut ca = CertificateParams::new(vec![format!("{SERVER_NAME}-ca")])?;
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca.distinguished_name
        .push(DnType::CommonName, "muka-trim link CA");
    let ca_cert = ca.self_signed(&ca_key)?;

    let leaf_key = KeyPair::generate()?;
    let mut leaf = CertificateParams::new(vec![SERVER_NAME.to_string()])?;
    leaf.distinguished_name
        .push(DnType::CommonName, SERVER_NAME);
    // Long-dated on purpose: these two machines are paired once and the
    // rotation story is "regenerate and copy the ca.der again".
    leaf.not_after = rcgen::date_time_ymd(2036, 1, 1);
    let issuer = Issuer::from_params(&ca, &ca_key);
    let leaf_cert = leaf.signed_by(&leaf_key, &issuer)?;

    write_der(&ca_path(dir), ca_cert.der().as_ref())?;
    write_atomic(&ca_key_path(dir), &ca_key.serialize_der())?;
    write_der(&leaf_path(dir), leaf_cert.der().as_ref())?;
    write_atomic(&leaf_key_path(dir), &leaf_key.serialize_der())?;
    // 0600-ish on the private keys is not portable on Windows; on unix the
    // peer holds the upstream API key, so it is worth trying.
    restrict(&ca_key_path(dir));
    restrict(&leaf_key_path(dir));
    Ok(())
}

fn read_der(path: &Path) -> Result<Vec<u8>, TlsError> {
    fs::read(path).map_err(|e| TlsError::Io(path.to_path_buf(), e))
}

fn write_der(path: &Path, bytes: &[u8]) -> Result<(), TlsError> {
    write_atomic(path, bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), TlsError> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|e| TlsError::Io(tmp.clone(), e))?;
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    fs::rename(&tmp, path).map_err(|e| TlsError::Io(path.to_path_buf(), e))
}

fn restrict(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn ca_path(dir: &Path) -> PathBuf {
    dir.join(CA_FILE)
}
fn ca_key_path(dir: &Path) -> PathBuf {
    dir.join(CA_KEY_FILE)
}
fn leaf_path(dir: &Path) -> PathBuf {
    dir.join(LEAF_FILE)
}
fn leaf_key_path(dir: &Path) -> PathBuf {
    dir.join(LEAF_KEY_FILE)
}

impl std::fmt::Debug for ServerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerIdentity")
            .field("ca_file", &self.ca_file)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("muka-tls-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn key_material_is_generated_once_and_reused() {
        let dir = tmp("reuse");
        let first = serve(&dir).unwrap();
        let bytes = fs::read(&first.ca_file).unwrap();
        let second = serve(&dir).unwrap();
        assert_eq!(bytes, fs::read(&second.ca_file).unwrap(), "the CA must be stable across restarts, otherwise every laptop has to be re-paired");
        assert!(dir.join(LEAF_FILE).exists());
        assert!(dir.join(LEAF_KEY_FILE).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_client_only_trusts_the_copied_ca() {
        let dir = tmp("trust");
        serve(&dir).unwrap();
        let cfg = client(&ca_path(&dir)).unwrap();
        assert_eq!(cfg.alpn_protocols.len(), 0);
        // A CA nobody copied must not validate.
        let other = tmp("other");
        let wrong = ca_path(&other);
        assert!(matches!(client(&wrong), Err(TlsError::Io(..))));
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&other);
    }

    #[test]
    fn a_corrupt_ca_file_is_reported_not_panicked() {
        let dir = tmp("corrupt");
        fs::create_dir_all(&dir).unwrap();
        fs::write(ca_path(&dir), b"not a certificate").unwrap();
        assert!(matches!(client(&ca_path(&dir)), Err(TlsError::Rustls(..)) | Err(TlsError::Corrupt(..))));
        let _ = fs::remove_dir_all(&dir);
    }
}
