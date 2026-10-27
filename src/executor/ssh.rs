use crate::executor::ActionExecutor;
use mcp_warden_core::audit::AuditOutcome;
use mcp_warden_core::config::Preset;
use mcp_warden_core::error::{Result, WardenError};
use russh::ChannelMsg;
use russh::client::{self, Handler};
use russh::keys::ssh_key;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, serde::Serialize, rmcp::schemars::JsonSchema)]
pub struct SshExecResponse {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<u32>,
}

/// Validate the agent-supplied command against the preset's anchored regex
/// allow-list. Runs BEFORE any credential is touched (spec §9.3).
pub fn validate_command(preset: &Preset, command: &str) -> Result<()> {
    if preset.allowed_commands.is_empty() {
        return Err(WardenError::Validation(format!(
            "preset '{}': no allowed_commands — refusing to dispatch",
            preset.name
        )));
    }
    for re_str in &preset.allowed_commands {
        let rx = mcp_warden_core::config::anchored_regex(re_str)
            .map_err(|e| WardenError::Validation(format!("bad regex '{re_str}': {e}")))?;
        if rx.is_match(command) {
            return Ok(());
        }
    }
    Err(WardenError::Validation(format!(
        "command '{command}' not allowed by preset '{}'",
        preset.name
    )))
}

struct WardenSshHandler {
    host: String,
    port: u16,
    known_hosts: std::path::PathBuf,
}

impl Handler for WardenSshHandler {
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

pub async fn run(
    actx: &ActionExecutor,
    preset: &Preset,
    command: String,
) -> Result<SshExecResponse> {
    let summary = super::summary::ssh(preset.host.as_deref().unwrap_or(""), &command);
    validate_command(preset, &command)
        .inspect_err(|e| actx.record_refused(&preset.name, "ssh_exec", &summary, e))?;
    let event_id = actx.authorise(preset, "ssh_exec", &summary, false).await?;

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
        .ok_or_else(|| WardenError::Validation("ssh: no host".into()))?;
    let user = preset
        .user
        .clone()
        .ok_or_else(|| WardenError::Validation("ssh: no user".into()))?;
    let port = preset.port.unwrap_or(22);
    let known_hosts = crate::executor::known_hosts::known_hosts_path(preset.known_hosts.as_deref());
    let cmd_timeout = Duration::from_secs(preset.timeout_seconds.unwrap_or(120));

    let response: Result<SshExecResponse> = async {
        let private_key = ssh_key::PrivateKey::from_openssh(key_secret.expose())
            .map_err(|e| WardenError::Executor(format!("parse private key: {e}")))?;
        drop(key_secret);

        let config = Arc::new(client::Config::default());
        let handler = WardenSshHandler {
            host: host.clone(),
            port,
            known_hosts: known_hosts.clone(),
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

        let mut channel = session
            .channel_open_session()
            .await
            .map_err(|e| WardenError::Executor(format!("channel: {e}")))?;
        channel
            .exec(true, command)
            .await
            .map_err(|e| WardenError::Executor(format!("exec: {e}")))?;

        let drain = async {
            let mut stdout = Vec::<u8>::new();
            let mut stderr = Vec::<u8>::new();
            let mut exit_code: Option<u32> = None;
            while let Some(msg) = channel.wait().await {
                match msg {
                    ChannelMsg::Data { ref data } => stdout.extend_from_slice(data),
                    ChannelMsg::ExtendedData { ref data, ext: 1 } => stderr.extend_from_slice(data),
                    ChannelMsg::ExitStatus { exit_status } => exit_code = Some(exit_status),
                    ChannelMsg::Eof | ChannelMsg::Close => break,
                    _ => {}
                }
            }
            Ok::<(Vec<u8>, Vec<u8>, Option<u32>), WardenError>((stdout, stderr, exit_code))
        };
        let (stdout, stderr, exit_code) = tokio::time::timeout(cmd_timeout, drain)
            .await
            .map_err(|_| WardenError::Executor("ssh timeout".into()))??;

        session
            .disconnect(russh::Disconnect::ByApplication, "done", "en")
            .await
            .ok();

        Ok(SshExecResponse {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            exit_code,
        })
    }
    .await;

    match &response {
        Ok(r) => actx.audit.record_outcome(
            event_id,
            AuditOutcome::Ok {
                status: r.exit_code.unwrap_or(0) as u16,
            },
        )?,
        Err(e) => actx.audit.record_outcome(
            event_id,
            AuditOutcome::Err {
                message: e.to_string(),
            },
        )?,
    };
    response
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
            allowed_commands: vec![
                "^docker compose (pull|up -d|ps)$".into(),
                "^git pull$".into(),
            ],
            allow_sftp: false,
            sftp_allowed_paths: vec![],
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
        }
    }

    #[test]
    fn rejects_command_not_matching_any_regex() {
        let err = validate_command(&p(), "rm -rf /").unwrap_err();
        assert!(err.to_string().contains("not allowed"));
    }
    #[test]
    fn accepts_listed_command() {
        validate_command(&p(), "docker compose up -d").unwrap();
        validate_command(&p(), "git pull").unwrap();
    }
    #[test]
    fn rejects_injection_attempts() {
        for evil in [
            "docker compose ps; rm -rf /",
            "git pull && curl evil.com",
            "git pull$(rm -rf /)",
        ] {
            assert!(
                validate_command(&p(), evil).is_err(),
                "should reject: {evil}"
            );
        }
    }
    #[test]
    fn alternation_in_pattern_stays_anchored() {
        let mut q = p();
        q.allowed_commands = vec!["uptime|df -h".into()];
        validate_command(&q, "uptime").unwrap();
        validate_command(&q, "df -h").unwrap();
        for evil in ["rm -rf / ; df -h", "uptime; rm -rf /"] {
            assert!(validate_command(&q, evil).is_err(), "should reject: {evil}");
        }
    }

    #[test]
    fn empty_allow_list_rejects_everything() {
        let mut q = p();
        q.allowed_commands.clear();
        let err = validate_command(&q, "git pull").unwrap_err();
        assert!(err.to_string().contains("no allowed_commands"));
    }
}
