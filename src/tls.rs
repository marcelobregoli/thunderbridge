//! Self-signed TLS certificate generation/loading and the TlsAcceptor.
//! The certificate is saved in the config directory and stays stable across restarts
//! (trust the certificate once in Thunderbird → permanent).

use std::path::PathBuf;
use std::sync::Arc;

use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

fn config_dir() -> Option<PathBuf> {
    let d = directories::ProjectDirs::from("", "", "thunderbridge")?
        .config_dir()
        .to_path_buf();
    std::fs::create_dir_all(&d).ok()?;
    Some(d)
}

fn load_or_generate() -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let d = config_dir().ok_or_else(|| anyhow::anyhow!("no config directory"))?;
    let cert_path = d.join("tls-cert.der");
    let key_path = d.join("tls-key.der");
    if let (Ok(c), Ok(k)) = (std::fs::read(&cert_path), std::fs::read(&key_path))
        && !c.is_empty() && !k.is_empty() {
            return Ok((c, k));
        }
    let ck = rcgen::generate_simple_self_signed(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])?;
    let cert_der = ck.cert.der().to_vec();
    let key_der = ck.signing_key.serialize_der();
    std::fs::write(&cert_path, &cert_der).ok();
    std::fs::write(&key_path, &key_der).ok();
    Ok((cert_der, key_der))
}

pub fn acceptor() -> anyhow::Result<TlsAcceptor> {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let (cert_der, key_der) = load_or_generate()?;
    let certs = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}
