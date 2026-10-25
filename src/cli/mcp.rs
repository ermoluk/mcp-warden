use crate::approval::{desktop::DesktopApproval, telegram::TelegramApproval, tui::TuiApproval};
use crate::executor::ActionExecutor;
use crate::mcp::server::WardenServer;
use mcp_warden_core::approval::ApprovalTransport;
use mcp_warden_core::audit::{AuditSink, sqlite_sink::LocalSqlite};
use mcp_warden_core::config::Config;
use mcp_warden_core::error::{Result, WardenError};
use mcp_warden_core::keychain::KeychainStore;
use mcp_warden_core::presets::toml_source::TomlSource;
use rmcp::{ServiceExt, transport::stdio};
use std::path::Path;
use std::sync::Arc;

/// Run the MCP server over stdio.
///
/// **stdout is the JSON-RPC channel**: every log call must go to stderr.
pub async fn cmd(config_dir: &Path) -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config_path = config_dir.join("config.toml");
    let audit_path = config_dir.join("audit.db");
    std::fs::create_dir_all(config_dir).map_err(WardenError::Io)?;
    if !config_path.exists() {
        std::fs::write(&config_path, "").map_err(WardenError::Io)?;
    }

    let keychain: Arc<dyn KeychainStore> = crate::cli::keychain_for_env();
    // Spec §9.10 — refuse to start if any preset references a missing secret.
    let cfg = Config::load_and_validate(&config_path, keychain.as_ref())?;

    let presets: Arc<dyn mcp_warden_core::presets::PresetSource> =
        Arc::new(TomlSource::new(config_path.clone()));
    let (approval, approval_fallback) = build_approval(&cfg, keychain.as_ref())?;
    let audit: Arc<dyn AuditSink> = Arc::new(LocalSqlite::open(&audit_path)?);

    let executor = Arc::new(ActionExecutor::new(
        keychain,
        approval,
        approval_fallback,
        audit,
    ));
    let server = WardenServer::new(presets, executor);

    let running = server
        .serve(stdio())
        .await
        .map_err(|e| WardenError::Executor(format!("serve: {e}")))?;
    running
        .waiting()
        .await
        .map_err(|e| WardenError::Executor(format!("waiting: {e}")))?;
    Ok(())
}

/// Primary approval transport plus an optional fallback.
type ApprovalTransports = (
    Arc<dyn ApprovalTransport>,
    Option<Arc<dyn ApprovalTransport>>,
);

/// Construct the active approval transport + optional fallback based on:
///
/// 1. Explicit env override `MCP_WARDEN_APPROVAL_TRANSPORT` (values:
///    `telegram` / `desktop` / `tui`). Wins over everything else.
/// 2. `[approval.telegram]` block in the config — if present, Telegram is
///    primary and TUI is the fallback.
/// 3. Default: `DesktopApproval` primary + `TuiApproval` fallback (the
///    behaviour from earlier versions).
fn build_approval(cfg: &Config, kc: &dyn KeychainStore) -> Result<ApprovalTransports> {
    let env_choice = std::env::var("MCP_WARDEN_APPROVAL_TRANSPORT").ok();
    let env_choice = env_choice.as_deref().map(str::trim).map(str::to_lowercase);

    if env_choice.as_deref() == Some("desktop") {
        return Ok((
            Arc::new(DesktopApproval),
            Some(Arc::new(TuiApproval::from_stderr())),
        ));
    }
    if env_choice.as_deref() == Some("tui") {
        return Ok((Arc::new(TuiApproval::from_stderr()), None));
    }

    let want_telegram = env_choice.as_deref() == Some("telegram")
        || (env_choice.is_none()
            && cfg
                .approval
                .as_ref()
                .and_then(|a| a.telegram.as_ref())
                .is_some());

    if want_telegram {
        let tg_cfg = cfg
            .approval
            .as_ref()
            .and_then(|a| a.telegram.as_ref())
            .ok_or_else(|| {
                WardenError::Validation(
                    "MCP_WARDEN_APPROVAL_TRANSPORT=telegram set but [approval.telegram] missing in config"
                        .into(),
                )
            })?;
        let token = kc.get(&tg_cfg.bot_token_secret)?.ok_or_else(|| {
            WardenError::Validation(format!(
                "approval.telegram.bot_token_secret '{}' not in keychain",
                tg_cfg.bot_token_secret
            ))
        })?;
        let tg = TelegramApproval::new(token, tg_cfg.chat_id).with_timeout(tg_cfg.timeout_seconds);
        // TUI fallback covers the case where the agent is invoked while the
        // Telegram bot/chat is unreachable.
        return Ok((Arc::new(tg), Some(Arc::new(TuiApproval::from_stderr()))));
    }

    Ok((
        Arc::new(DesktopApproval),
        Some(Arc::new(TuiApproval::from_stderr())),
    ))
}
