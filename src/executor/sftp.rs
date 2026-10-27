use crate::executor::ActionExecutor;
use mcp_warden_core::audit::AuditOutcome;
use mcp_warden_core::config::Preset;
use mcp_warden_core::error::{Result, WardenError};
use russh::client::{self, Handler};
use russh::keys::ssh_key;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, serde::Deserialize, rmcp::schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SftpDirection {
    Get,
    Put,
}

#[derive(Debug, serde::Serialize, rmcp::schemars::JsonSchema)]
pub struct SftpTransferResponse {
    pub bytes: u64,
    pub direction: String,
    pub remote: String,
    pub local: String,
}

pub fn validate_remote_path(preset: &Preset, path: &str) -> Result<()> {
    if !path.starts_with('/') {
        return Err(WardenError::Validation(format!(
            "remote path '{path}' must be absolute"
        )));
    }
    if path.contains("..") {
        return Err(WardenError::Validation(format!(
            "remote path '{path}' contains traversal"
        )));
    }
    if preset.sftp_allowed_paths.is_empty() {
        return Err(WardenError::Validation(
            "sftp_allowed_paths is empty — refusing".into(),
        ));
    }
    // Path::starts_with compares whole components: `/srv/app` allows
    // `/srv/app/x` but not `/srv/app-secrets/x`.
    let remote = std::path::Path::new(path);
    if !preset
        .sftp_allowed_paths
        .iter()
        .any(|prefix| remote.starts_with(prefix))
    {
        return Err(WardenError::Validation(format!(
            "remote path '{path}' not allowed by preset '{}'",
            preset.name
        )));
    }
    Ok(())
}

pub fn validate_local_path(_preset: &Preset, path: &str) -> Result<()> {
    use std::path::{Component, Path, PathBuf};

    let p = Path::new(path);
    if !p.is_absolute() {
        return Err(WardenError::Validation(format!(
            "local path '{path}' must be absolute"
        )));
    }
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(WardenError::Validation(format!(
            "local path '{path}' contains traversal"
        )));
    }
    // The file itself must not be a symlink: `get` would write through it
    // and `put` would read whatever it points at.
    if std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(WardenError::Validation(format!(
            "local path '{path}' is a symlink — refusing"
        )));
    }
    let outside = || {
        WardenError::Validation(format!(
            "local path '{path}' must be in an existing directory under $HOME or /tmp"
        ))
    };
    // Resolve symlinks in the parent so a link under an allowed root cannot
    // point outside it, then compare whole components against the
    // (also resolved — /tmp is /private/tmp on macOS) allowed roots.
    let (Some(parent), Some(name)) = (p.parent(), p.file_name()) else {
        return Err(outside());
    };
    let resolved = std::fs::canonicalize(parent)
        .map_err(|_| outside())?
        .join(name);
    let mut roots = dirs::home_dir()
        .into_iter()
        .chain(["/tmp", "/var/tmp"].map(PathBuf::from))
        .filter_map(|r| std::fs::canonicalize(r).ok());
    if roots.any(|root| resolved.starts_with(&root)) {
        Ok(())
    } else {
        Err(outside())
    }
}

/// Open the local side of a transfer. Called after approval — which can take
/// minutes — right after re-running `validate_local_path`, and with
/// `O_NOFOLLOW`, so a symlink planted at the path since the first check is
/// refused rather than followed. New files are created `0600`.
async fn open_local_nofollow(path: &Path, direction: &SftpDirection) -> Result<tokio::fs::File> {
    let mut opts = tokio::fs::OpenOptions::new();
    match direction {
        SftpDirection::Get => opts.write(true).create(true).truncate(true),
        SftpDirection::Put => opts.read(true),
    };
    #[cfg(unix)]
    opts.custom_flags(libc::O_NOFOLLOW).mode(0o600);
    opts.open(path).await.map_err(|e| {
        WardenError::Validation(format!("cannot open local path '{}': {e}", path.display()))
    })
}

struct WardenSftpHandler {
    host: String,
    port: u16,
    known_hosts: std::path::PathBuf,
}

impl Handler for WardenSftpHandler {
    type Error = WardenError;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        crate::executor::known_hosts::verify(
            &self.host,
            self.port,
            server_public_key,
            &self.known_hosts,
        )
    }
}

pub(crate) fn validate_transfer(preset: &Preset, remote: &str, local: &str) -> Result<()> {
    if !preset.allow_sftp {
        return Err(WardenError::Validation(format!(
            "preset '{}' does not have allow_sftp = true",
            preset.name
        )));
    }
    validate_remote_path(preset, remote)?;
    validate_local_path(preset, local)
}

pub async fn run(
    actx: &ActionExecutor,
    preset: &Preset,
    direction: SftpDirection,
    remote: String,
    local: String,
) -> Result<SftpTransferResponse> {
    let dir_str = match direction {
        SftpDirection::Get => "get",
        SftpDirection::Put => "put",
    };
    let summary = super::summary::sftp(dir_str, &remote, &local);
    let request = super::policy::Request::Sftp {
        remote: &remote,
        local: &local,
    };
    super::policy::check_request(preset, &request)
        .inspect_err(|e| actx.record_refused(&preset.name, "sftp_transfer", &summary, e))?;
    let event_id = actx
        .authorise(preset, "sftp_transfer", &summary, false)
        .await?;

    let bytes = transfer_inner(actx, preset, &direction, &remote, &local)
        .await
        .inspect_err(|e| {
            let _ = actx.audit.record_outcome(
                event_id,
                AuditOutcome::Err {
                    message: e.to_string(),
                },
            );
        })?;

    actx.audit
        .record_outcome(event_id, AuditOutcome::Ok { status: 200 })?;
    Ok(SftpTransferResponse {
        bytes,
        direction: dir_str.into(),
        remote,
        local,
    })
}

async fn transfer_inner(
    actx: &ActionExecutor,
    preset: &Preset,
    direction: &SftpDirection,
    remote: &str,
    local: &str,
) -> Result<u64> {
    let key_secret = actx
        .keychain
        .get(preset.secret.as_deref().unwrap_or(""))?
        .ok_or_else(|| WardenError::MissingSecret {
            preset: preset.name.clone(),
            secret: preset.secret.clone().unwrap_or_default(),
        })?;
    let host = preset
        .host
        .clone()
        .ok_or_else(|| WardenError::Validation("sftp: no host".into()))?;
    let user = preset
        .user
        .clone()
        .ok_or_else(|| WardenError::Validation("sftp: no user".into()))?;
    let port = preset.port.unwrap_or(22);
    let known_hosts = crate::executor::known_hosts::known_hosts_path(preset.known_hosts.as_deref());

    let private_key = ssh_key::PrivateKey::from_openssh(key_secret.expose())
        .map_err(|e| WardenError::Executor(format!("parse private key: {e}")))?;
    drop(key_secret);

    let config = Arc::new(client::Config::default());
    let handler = WardenSftpHandler {
        host: host.clone(),
        port,
        known_hosts,
    };
    let mut session = client::connect(config, (host.as_str(), port), handler)
        .await
        .map_err(|e| WardenError::Executor(format!("connect: {e}")))?;
    let auth = session
        .authenticate_publickey(
            &user,
            russh::keys::PrivateKeyWithHashAlg::new(Arc::new(private_key), None),
        )
        .await
        .map_err(|e| WardenError::Executor(format!("auth: {e}")))?;
    if !auth.success() {
        return Err(WardenError::Executor("ssh auth failed".into()));
    }

    let channel = session
        .channel_open_session()
        .await
        .map_err(|e| WardenError::Executor(format!("channel: {e}")))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| WardenError::Executor(format!("subsystem: {e}")))?;
    let stream = channel.into_stream();
    let sftp = russh_sftp::client::SftpSession::new(stream)
        .await
        .map_err(|e| WardenError::Executor(format!("sftp init: {e}")))?;

    let bytes = match direction {
        SftpDirection::Get => {
            let mut remote_file = sftp
                .open(remote)
                .await
                .map_err(|e| WardenError::Executor(format!("sftp open remote: {e}")))?;
            validate_local_path(preset, local)?;
            let mut local_file = open_local_nofollow(Path::new(local), direction).await?;
            tokio::io::copy(&mut remote_file, &mut local_file)
                .await
                .map_err(WardenError::Io)?
        }
        SftpDirection::Put => {
            validate_local_path(preset, local)?;
            let mut local_file = open_local_nofollow(Path::new(local), direction).await?;
            let mut remote_file = sftp
                .create(remote)
                .await
                .map_err(|e| WardenError::Executor(format!("sftp create remote: {e}")))?;
            tokio::io::copy(&mut local_file, &mut remote_file)
                .await
                .map_err(WardenError::Io)?
        }
    };

    sftp.close()
        .await
        .map_err(|e| WardenError::Executor(format!("sftp close: {e}")))?;
    session
        .disconnect(russh::Disconnect::ByApplication, "done", "en")
        .await
        .ok();
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_warden_core::config::{ApprovalPolicy, Preset, PresetType};

    fn p() -> Preset {
        Preset {
            name: "deploy".into(),
            preset_type: PresetType::Ssh,
            description: "x".into(),
            host: Some("h".into()),
            user: Some("u".into()),
            port: Some(22),
            secret: Some("k".into()),
            allowed_commands: vec![],
            allow_sftp: true,
            sftp_allowed_paths: vec!["/srv/app/".into(), "/var/log/".into()],
            approval: ApprovalPolicy::Auto,
            approval_window_seconds: None,
            base_url: None,
            auth: None,
            allowed_paths: vec![],
            allowed_methods: vec![],
            timeout_seconds: None,
            known_hosts: None,
            database: None,
            queries: vec![],
            expires_at: None,
            max_response_bytes: None,
            response_fields: vec![],
        }
    }

    #[test]
    fn rejects_remote_path_outside_allow_list() {
        let err = validate_remote_path(&p(), "/etc/passwd").unwrap_err();
        assert!(err.to_string().contains("not allowed"));
    }
    #[test]
    fn rejects_relative_remote_path() {
        let err = validate_remote_path(&p(), "../etc/passwd").unwrap_err();
        assert!(err.to_string().contains("absolute"));
    }
    #[test]
    fn rejects_traversal() {
        let err = validate_remote_path(&p(), "/srv/app/../../etc/passwd").unwrap_err();
        assert!(err.to_string().contains("traversal"));
    }
    #[test]
    fn accepts_path_inside_prefix() {
        validate_remote_path(&p(), "/srv/app/logs/today.log").unwrap();
        validate_remote_path(&p(), "/var/log/syslog").unwrap();
    }
    #[test]
    fn local_path_must_be_in_user_home_or_tmp() {
        validate_local_path(&p(), "/tmp/x.log").unwrap();
        let err = validate_local_path(&p(), "/etc/shadow").unwrap_err();
        assert!(err.to_string().contains("$HOME or /tmp"));
    }

    #[test]
    fn local_path_rejects_traversal_out_of_home() {
        let home = dirs::home_dir().unwrap();
        let evil = format!("{}/../../etc/passwd", home.display());
        assert!(validate_local_path(&p(), &evil).is_err());
        assert!(validate_local_path(&p(), "/tmp/../etc/passwd").is_err());
    }

    #[test]
    fn local_path_rejects_sibling_of_home_with_same_prefix() {
        let home = dirs::home_dir().unwrap();
        let sibling = format!("{}-evil/x.log", home.display());
        assert!(validate_local_path(&p(), &sibling).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn local_path_rejects_symlink_escaping_allowed_roots() {
        let dir = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
        let link = dir.path().join("etc-link");
        std::os::unix::fs::symlink("/etc", &link).unwrap();
        let evil = link.join("passwd");
        assert!(validate_local_path(&p(), evil.to_str().unwrap()).is_err());

        let file_link = dir.path().join("file-link");
        std::os::unix::fs::symlink("/etc/hosts", &file_link).unwrap();
        assert!(validate_local_path(&p(), file_link.to_str().unwrap()).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn local_open_never_follows_a_symlink_planted_after_validation() {
        let dir = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
        let target = dir.path().join("target.txt");
        std::fs::write(&target, "original").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        // The raw openers are what run after approval — even if a symlink
        // appeared after validate_local_path, they must refuse it.
        assert!(
            open_local_nofollow(&link, &SftpDirection::Get)
                .await
                .is_err()
        );
        assert!(
            open_local_nofollow(&link, &SftpDirection::Put)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "original");

        assert!(
            open_local_nofollow(&target, &SftpDirection::Put)
                .await
                .is_ok()
        );
        let fresh = dir.path().join("fresh.txt");
        open_local_nofollow(&fresh, &SftpDirection::Get)
            .await
            .unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn remote_prefix_matches_whole_components() {
        let mut q = p();
        q.sftp_allowed_paths = vec!["/srv/app".into()];
        validate_remote_path(&q, "/srv/app/x.log").unwrap();
        assert!(validate_remote_path(&q, "/srv/app-secrets/key").is_err());
    }
}
