use mcp_warden_core::error::{Result, WardenError};
use russh::keys::PublicKeyOrCertificate;
use russh::keys::ssh_key;
use std::path::PathBuf;

/// Resolve the path to the user's known_hosts file.
///
/// Honours the preset's explicit setting; otherwise `~/.ssh/known_hosts`.
pub fn known_hosts_path(preset_path: Option<&str>) -> PathBuf {
    if let Some(p) = preset_path {
        return PathBuf::from(p);
    }
    dirs::home_dir()
        .map(|h| h.join(".ssh").join("known_hosts"))
        .unwrap_or_else(|| PathBuf::from("./known_hosts"))
}

/// Returns Ok(true) if the host:port → key triple matches an entry in known_hosts.
/// Returns Ok(false) if the host is known but the key differs (HARD FAIL — caller must reject).
/// Returns Err if known_hosts is missing — refuse to TOFU.
pub fn verify(
    host: &str,
    port: u16,
    key: &ssh_key::PublicKey,
    path: &std::path::Path,
) -> Result<bool> {
    if !path.exists() {
        return Err(WardenError::Executor(format!(
            "known_hosts file '{}' missing — populate via `ssh-keyscan -H -p {port} {host} >> {}`",
            path.display(),
            path.display()
        )));
    }
    russh::keys::check_known_hosts_path(host, port, key, path)
        .map_err(|e| WardenError::Executor(format!("known_hosts check: {e}")))
}

/// [`verify`] for what the server presented: a plain host key or a host
/// certificate. A certificate is judged by the key it certifies, which must
/// be pinned in known_hosts like any other host key. Its CA, principals and
/// validity are not used (`@cert-authority` lines are not supported), so a
/// certificate never makes a key trusted that known_hosts does not list.
/// russh has already checked that the server signed the key exchange with
/// that key.
pub fn verify_presented(
    host: &str,
    port: u16,
    presented: &PublicKeyOrCertificate,
    path: &std::path::Path,
) -> Result<bool> {
    match presented {
        PublicKeyOrCertificate::PublicKey { key, .. } => verify(host, port, key, path),
        PublicKeyOrCertificate::Certificate(cert) => {
            let key = ssh_key::PublicKey::from(cert.public_key().clone());
            verify(host, port, &key, path)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::ssh_key::certificate::{Builder, CertType};
    use russh::keys::ssh_key::private::Ed25519Keypair;
    use russh::keys::ssh_key::{Certificate, PrivateKey};

    fn key(seed: u8) -> PrivateKey {
        PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
    }

    fn host_cert(host_key: &PrivateKey, ca: &PrivateKey) -> Certificate {
        let mut builder = Builder::new(
            [7u8; 16],
            host_key.public_key().key_data().clone(),
            0,
            u64::MAX,
        )
        .unwrap();
        builder.cert_type(CertType::Host).unwrap();
        builder.valid_principal("127.0.0.1").unwrap();
        builder.sign(ca).unwrap()
    }

    fn pinned(host_key: &PrivateKey) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let line = format!(
            "[127.0.0.1]:2222 {}\n",
            host_key.public_key().to_openssh().unwrap()
        );
        std::fs::write(&path, line).unwrap();
        (dir, path)
    }

    #[test]
    fn a_certificate_counts_only_for_the_key_known_hosts_pins() {
        let (host, other, ca) = (key(1), key(2), key(3));
        let (_dir, path) = pinned(&host);
        let plain = PublicKeyOrCertificate::PublicKey {
            key: host.public_key().clone(),
            hash_alg: None,
        };
        assert!(verify_presented("127.0.0.1", 2222, &plain, &path).unwrap());

        let cert = PublicKeyOrCertificate::Certificate(host_cert(&host, &ca));
        assert!(verify_presented("127.0.0.1", 2222, &cert, &path).unwrap());

        // A valid certificate for a key known_hosts does not list is not
        // trusted, whoever signed it.
        let stranger = PublicKeyOrCertificate::Certificate(host_cert(&other, &ca));
        assert!(!matches!(
            verify_presented("127.0.0.1", 2222, &stranger, &path),
            Ok(true)
        ));
    }
}
