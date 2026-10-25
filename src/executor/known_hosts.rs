use mcp_warden_core::error::{Result, WardenError};
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
