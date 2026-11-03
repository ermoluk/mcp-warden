use crate::executor::ActionExecutor;
use mcp_warden_core::audit::AuditOutcome;
use mcp_warden_core::config::Preset;
use mcp_warden_core::error::{Result, WardenError};
use russh::client::{self, Handler};
use russh::keys::ssh_key;
use std::path::{Path, PathBuf};
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

/// Places under `$HOME` that hold credentials or run code later. `put`
/// would upload them; `get` would overwrite them — a shell startup file, an
/// `authorized_keys`, a git config with `core.sshCommand`, an agent's own
/// settings with hooks. Matched against the path with symlinks resolved,
/// as whole components, ignoring case on macOS and Windows (whose file
/// systems usually do).
const SENSITIVE_UNDER_HOME: &[&str] = &[
    // Credentials.
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".docker",
    ".config/gcloud",
    ".azure",
    ".netrc",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".password-store",
    "Library/Keychains",
    // Code that runs later.
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".zlogout",
    ".cshrc",
    ".tcshrc",
    ".kshrc",
    ".config/fish",
    ".gitconfig",
    ".config/git",
    "Library/LaunchAgents",
    ".config/autostart",
    ".config/systemd",
    // AI agents' own configuration: hooks and MCP servers run commands.
    ".claude",
    ".claude.json",
    ".cursor",
    "Library/Application Support/Claude",
    ".config/Claude",
    // mcp-warden's default config dirs (the active one is checked too).
    ".config/mcp-warden",
    "Library/Application Support/io.mcp-warden.mcp-warden",
];

/// Check a local `sftp_transfer` path and return it with its parent's
/// symlinks resolved — the file that will really be read or written.
pub fn validate_local_path(preset: &Preset, path: &str) -> Result<PathBuf> {
    check_local_path(
        preset,
        path,
        dirs::home_dir().as_deref(),
        &crate::cli::config_dir_for_env(),
    )
}

fn check_local_path(
    preset: &Preset,
    path: &str,
    home: Option<&Path>,
    config_dir: &Path,
) -> Result<PathBuf> {
    use std::path::Component;

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
    let home = home.and_then(|h| std::fs::canonicalize(h).ok());
    let mut roots = home.clone().into_iter().chain(
        ["/tmp", "/var/tmp"]
            .map(PathBuf::from)
            .into_iter()
            .filter_map(|r| std::fs::canonicalize(r).ok()),
    );
    if !roots.any(|root| resolved.starts_with(&root)) {
        return Err(outside());
    }
    let sensitive = |what: &str| {
        WardenError::Validation(format!(
            "local path '{path}' ({}) is {what} — refusing",
            resolved.display()
        ))
    };
    if let Some(home) = &home
        && SENSITIVE_UNDER_HOME
            .iter()
            .any(|entry| within(&resolved, &under(home, entry)))
    {
        return Err(sensitive(
            "a sensitive location (credentials, shell or agent configuration)",
        ));
    }
    if std::fs::canonicalize(config_dir).is_ok_and(|dir| within(&resolved, &dir)) {
        return Err(sensitive("inside mcp-warden's own config dir"));
    }
    if !preset.allowed_local_paths.is_empty()
        && !preset
            .allowed_local_paths
            .iter()
            .filter_map(|dir| std::fs::canonicalize(dir).ok())
            .any(|dir| within(&resolved, &dir))
    {
        return Err(WardenError::Validation(format!(
            "local path '{path}' ({}) is not under preset '{}' allowed_local_paths",
            resolved.display(),
            preset.name
        )));
    }
    Ok(resolved)
}

/// `rel` (components separated by `/`) below `dir`. Joined one component at
/// a time: on Windows `canonicalize` returns `\\?\` paths, in which `/` is
/// not a separator.
fn under(dir: &Path, rel: &str) -> PathBuf {
    rel.split('/').fold(dir.to_path_buf(), |p, c| p.join(c))
}

/// `path` is `dir` or below it, by whole components — ignoring case where
/// file systems usually do (macOS, Windows).
fn within(path: &Path, dir: &Path) -> bool {
    if cfg!(any(target_os = "macos", windows)) {
        let fold = |p: &Path| PathBuf::from(p.to_string_lossy().to_lowercase());
        fold(path).starts_with(fold(dir))
    } else {
        path.starts_with(dir)
    }
}

/// Open the local side of a transfer. Called after approval — which can take
/// minutes — right after re-running `validate_local_path`, and with
/// `O_NOFOLLOW`, so a symlink planted at the path since the first check is
/// refused rather than followed. New files are created `0600`.
async fn open_local_nofollow(path: &Path, direction: &SftpDirection) -> Result<tokio::fs::File> {
    let mut opts = tokio::fs::OpenOptions::new();
    match direction {
        // Not truncated here: a file with other names must be refused
        // before anything is written to it.
        SftpDirection::Get => opts.write(true).create(true).truncate(false),
        SftpDirection::Put => opts.read(true),
    };
    #[cfg(unix)]
    opts.custom_flags(libc::O_NOFOLLOW).mode(0o600);
    let file = opts.open(path).await.map_err(|e| {
        WardenError::Validation(format!("cannot open local path '{}': {e}", path.display()))
    })?;
    // A hard link has no path to resolve: `/tmp/x` linked to
    // `~/.ssh/id_ed25519` is that key under another name, which no path
    // check can see. Refuse any file with more than one name.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file.metadata().await.map_err(WardenError::Io)?;
        if meta.nlink() > 1 {
            return Err(WardenError::Validation(format!(
                "local path '{}' has other names (hard links) — refusing",
                path.display()
            )));
        }
    }
    if let SftpDirection::Get = direction {
        file.set_len(0).await.map_err(WardenError::Io)?;
    }
    Ok(file)
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
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        crate::executor::known_hosts::verify_presented(
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
    validate_local_path(preset, local).map(drop)
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
    let request = super::policy::Request::Sftp {
        remote: &remote,
        local: &local,
    };
    super::policy::check_request(preset, &request).inspect_err(|e| {
        let summary = super::summary::sftp(dir_str, &remote, &local);
        actx.record_refused(&preset.name, "sftp_transfer", &summary, e)
    })?;
    // The prompt names the file that will really be read or written: the
    // path with its parent's symlinks resolved, and as given if that differs.
    let resolved = validate_local_path(preset, &local)?;
    let shown = if resolved == Path::new(&local) {
        local.clone()
    } else {
        format!("{} (given as {local})", resolved.display())
    };
    let summary = super::summary::sftp(dir_str, &remote, &shown);
    let event_id = actx
        .authorise(preset, "sftp_transfer", &summary, false)
        .await?;

    // The timeout covers the whole transfer, connecting and authenticating
    // included, so a host that stalls at any step cannot hold the call.
    let timeout = std::time::Duration::from_secs(
        preset
            .timeout_seconds
            .unwrap_or(super::limits::DEFAULT_SFTP_TIMEOUT_SECS),
    );
    let bytes = tokio::time::timeout(
        timeout,
        transfer_inner(actx, preset, &direction, &remote, &local),
    )
    .await
    .unwrap_or_else(|_| Err(WardenError::Executor("sftp timeout".into())))
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
    let key = super::ssh::signing_key(&session, private_key).await?;
    let auth = session
        .authenticate_publickey(&user, key)
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
pub(crate) mod tests {
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
            allowed_local_paths: vec![],
            max_output_bytes: None,
            expose_as_tools: false,
            commands: vec![],
        }
    }

    /// The whole transfer — connecting and authenticating included — is
    /// bounded by the preset's timeout, so a host that stalls ends the call.
    #[tokio::test]
    async fn a_host_that_stalls_after_authentication_times_out() {
        use crate::executor::test_ssh::{Behaviour, TestSshServer};
        use crate::testutil::{CountingApproval, CountingKeychain};
        let server = TestSshServer::start(Behaviour::HangAfterAuth).await;
        let dir = tempfile::tempdir().unwrap();
        let exec = ActionExecutor::new(
            CountingKeychain::with(&[("k", &server.client_key)]),
            CountingApproval::new(mcp_warden_core::approval::ApprovalDecision::Approved),
            None,
            Arc::new(
                mcp_warden_core::audit::sqlite_sink::LocalSqlite::open(
                    &dir.path().join("audit.db"),
                )
                .unwrap(),
            ),
        );
        let mut preset = p();
        preset.host = Some("127.0.0.1".into());
        preset.port = Some(server.port);
        preset.known_hosts = Some(server.known_hosts.display().to_string());
        preset.timeout_seconds = Some(1);
        let local = allowed_local("stall.log");
        let call = run(
            &exec,
            &preset,
            SftpDirection::Get,
            "/srv/app/x".into(),
            local,
        );
        let res = tokio::time::timeout(std::time::Duration::from_secs(10), call)
            .await
            .expect("sftp_transfer hung past its own timeout");
        let err = res.expect_err("must fail").to_string();
        assert!(err.contains("timeout"), "{err}");
    }

    /// A temporary home with `entries` created as files, and the roots and
    /// config dir `check_local_path` is given for it.
    fn fake_home(entries: &[&str]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(dir.path()).unwrap();
        for entry in entries {
            let path = under(&home, entry);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "x").unwrap();
        }
        (dir, home)
    }

    fn check_in(preset: &Preset, path: &Path, home: &Path) -> Result<PathBuf> {
        check_local_path(
            preset,
            &path.display().to_string(),
            Some(home),
            &home.join("not-the-config-dir"),
        )
    }

    #[test]
    fn hostile_corpus_local_paths_are_refused_under_home() {
        let entries = crate::testutil::corpus(include_str!("../../tests/corpus/local-paths.txt"));
        let names: Vec<&str> = entries.iter().map(|(_, e, _)| e.as_str()).collect();
        let (_dir, home) = fake_home(&names);
        // An ordinary file in the same home is fine.
        std::fs::write(home.join("notes.txt"), "x").unwrap();
        check_in(&p(), &home.join("notes.txt"), &home).unwrap();
        let allowed: Vec<String> = entries
            .iter()
            .filter(|(_, entry, _)| check_in(&p(), &under(&home, entry), &home).is_ok())
            .map(|(line, entry, note)| {
                format!("  tests/corpus/local-paths.txt:{line}: {entry} — {note}")
            })
            .collect();
        assert!(allowed.is_empty(), "allowed:\n{}", allowed.join("\n"));
        assert!(entries.len() >= 30, "{}", entries.len());
    }

    /// The check runs on the path with its parent's symlinks resolved, so a
    /// link that leads into ~/.ssh is refused like ~/.ssh itself — and the
    /// prompt shows where the file really is.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_parent_into_a_sensitive_location_is_refused() {
        let (_dir, home) = fake_home(&[".ssh/id_ed25519", "work/keep"]);
        std::os::unix::fs::symlink(home.join(".ssh"), home.join("work/backup")).unwrap();
        let err = check_in(&p(), &home.join("work/backup/id_ed25519"), &home)
            .unwrap_err()
            .to_string();
        assert!(err.contains("sensitive"), "{err}");
        // Case does not help on a case-insensitive file system either.
        if cfg!(target_os = "macos") {
            assert!(check_in(&p(), &home.join(".SSH/id_ed25519"), &home).is_err());
        }
    }

    #[test]
    fn the_config_dir_is_refused() {
        let (_dir, home) = fake_home(&["state/config.toml"]);
        let err = check_local_path(
            &p(),
            &under(&home, "state/config.toml").display().to_string(),
            Some(&home),
            &home.join("state"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("mcp-warden's own"), "{err}");
    }

    #[test]
    fn allowed_local_paths_narrows_the_roots() {
        let (_dir, home) = fake_home(&["work/in.log", "other/out.log"]);
        let mut preset = p();
        preset.allowed_local_paths = vec![home.join("work").display().to_string()];
        check_in(&preset, &under(&home, "work/in.log"), &home).unwrap();
        let err = check_in(&preset, &under(&home, "other/out.log"), &home)
            .unwrap_err()
            .to_string();
        assert!(err.contains("allowed_local_paths"), "{err}");
    }

    /// A hard link has no path to resolve: /tmp/x linked to ~/.ssh/id_* is
    /// that key under another name. Files with more than one name are
    /// refused, and `get` does not truncate one before checking.
    #[cfg(unix)]
    #[tokio::test]
    async fn hard_linked_files_are_refused() {
        let (_dir, home) = fake_home(&[".ssh/id_ed25519", ".zshrc"]);
        std::fs::hard_link(home.join(".ssh/id_ed25519"), home.join("key-copy")).unwrap();
        std::fs::hard_link(home.join(".zshrc"), home.join("rc-copy")).unwrap();
        let err = open_local_nofollow(&home.join("key-copy"), &SftpDirection::Put)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("hard link"), "{err}");
        let err = open_local_nofollow(&home.join("rc-copy"), &SftpDirection::Get)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("hard link"), "{err}");
        assert_eq!(std::fs::read_to_string(home.join(".zshrc")).unwrap(), "x");
    }

    /// The prompt names the file that will really be read or written.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_prompt_shows_the_resolved_local_path() {
        use crate::testutil::{CountingApproval, CountingKeychain};
        let dir = tempfile::tempdir().unwrap();
        let approval = CountingApproval::new(mcp_warden_core::approval::ApprovalDecision::Denied);
        let exec = ActionExecutor::new(
            CountingKeychain::with(&[]),
            approval.clone(),
            None,
            Arc::new(
                mcp_warden_core::audit::sqlite_sink::LocalSqlite::open(
                    &dir.path().join("audit.db"),
                )
                .unwrap(),
            ),
        );
        let mut preset = p();
        preset.approval = ApprovalPolicy::Prompt;
        let target = tempfile::tempdir_in("/tmp").unwrap();
        let real = std::fs::canonicalize(target.path()).unwrap();
        let link = target.path().join("link");
        std::fs::create_dir(real.join("data")).unwrap();
        std::os::unix::fs::symlink(real.join("data"), &link).unwrap();
        let given = link.join("x.log").display().to_string();
        let _ = run(
            &exec,
            &preset,
            SftpDirection::Get,
            "/srv/app/x".into(),
            given.clone(),
        )
        .await;
        let summary = approval.shown.lock().unwrap()[0].summary.clone();
        let resolved = real.join("data/x.log").display().to_string();
        assert!(summary.contains(&format!("↔ {resolved}")), "{summary}");
        assert!(summary.contains(&given), "{summary}");
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
    /// A local path the SFTP rules allow on this OS: under /tmp on unix,
    /// under the temp dir (inside the user's profile) on Windows.
    pub(crate) fn allowed_local(name: &str) -> String {
        if cfg!(windows) {
            std::env::temp_dir().join(name).display().to_string()
        } else {
            format!("/tmp/{name}")
        }
    }

    #[test]
    fn local_path_must_be_in_user_home_or_tmp() {
        validate_local_path(&p(), &allowed_local("x.log")).unwrap();
        let outside = if cfg!(windows) {
            r"C:\Windows\System32\drivers\etc\hosts"
        } else {
            "/etc/shadow"
        };
        let err = validate_local_path(&p(), outside).unwrap_err();
        assert!(err.to_string().contains("$HOME or /tmp"), "{err}");
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
