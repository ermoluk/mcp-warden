use crate::approval::{
    desktop::DesktopApproval, osascript::OsascriptApproval, telegram::TelegramApproval,
    tui::TuiApproval,
};
use crate::executor::ActionExecutor;
use crate::mcp::server::WardenServer;
use is_terminal::IsTerminal;
use mcp_warden_core::approval::ApprovalTransport;
use mcp_warden_core::audit::{AuditSink, sqlite_sink::LocalSqlite};
use mcp_warden_core::config::{Config, TelegramConfig};
use mcp_warden_core::error::{Result, WardenError};
use mcp_warden_core::keychain::KeychainStore;
use mcp_warden_core::presets::frozen::FrozenSource;
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

    // Serve exactly the presets validated above; the file is never re-read,
    // so edits made after startup need a restart (and pass validation then).
    let presets: Arc<dyn mcp_warden_core::presets::PresetSource> =
        Arc::new(FrozenSource::new(cfg.preset.clone()));
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

/// Which transport fills a slot; `build_approval` turns it into an instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Telegram,
    /// The native desktop prompt: a dialog on macOS, a notification elsewhere.
    Desktop,
    Tui,
}

/// Construct the active approval transport + optional fallback. See
/// `plan_transports` for how they are chosen.
fn build_approval(cfg: &Config, kc: &dyn KeychainStore) -> Result<ApprovalTransports> {
    let env_choice = std::env::var("MCP_WARDEN_APPROVAL_TRANSPORT").ok();
    let env_choice = env_choice.as_deref().map(str::trim).map(str::to_lowercase);
    let telegram = cfg.approval.as_ref().and_then(|a| a.telegram.as_ref());
    let (primary, fallback) = plan_transports(
        env_choice.as_deref(),
        telegram.is_some(),
        cfg!(target_os = "macos"),
        std::io::stderr().is_terminal(),
    );
    let build = |kind| -> Result<Arc<dyn ApprovalTransport>> {
        Ok(match kind {
            Kind::Telegram => telegram_transport(telegram, kc)?,
            Kind::Desktop => desktop_transport(),
            Kind::Tui => Arc::new(TuiApproval::from_stderr()),
        })
    };
    Ok((build(primary)?, fallback.map(build).transpose()?))
}

/// Pick the primary approval transport and its fallback:
///
/// 1. Explicit env override `MCP_WARDEN_APPROVAL_TRANSPORT` (values:
///    `telegram` / `desktop` / `tui`). Wins over everything else.
/// 2. `[approval.telegram]` block in the config — Telegram is primary.
/// 3. Default: the native desktop prompt.
///
/// The fallback is asked only when the primary times out, so it must be a
/// prompt the user can actually see. On macOS that is the native dialog,
/// behind Telegram. Elsewhere it is the TUI, and only when stderr is a
/// terminal: an MCP client captures the server's stderr, so a TUI drawn
/// there is invisible (and on macOS it cannot read keys at all while stdin
/// is the JSON-RPC pipe). An explicit `tui` choice is honoured as is.
fn plan_transports(
    env_choice: Option<&str>,
    has_telegram: bool,
    is_macos: bool,
    stderr_is_tty: bool,
) -> (Kind, Option<Kind>) {
    let primary = match env_choice {
        Some("tui") => return (Kind::Tui, None),
        Some("telegram") => Kind::Telegram,
        Some(_) => Kind::Desktop,
        None if has_telegram => Kind::Telegram,
        None => Kind::Desktop,
    };
    let fallback = if is_macos {
        (primary == Kind::Telegram).then_some(Kind::Desktop)
    } else {
        stderr_is_tty.then_some(Kind::Tui)
    };
    (primary, fallback)
}

fn telegram_transport(
    tg_cfg: Option<&TelegramConfig>,
    kc: &dyn KeychainStore,
) -> Result<Arc<dyn ApprovalTransport>> {
    let tg_cfg = tg_cfg.ok_or_else(|| {
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
    Ok(Arc::new(
        TelegramApproval::new(token, tg_cfg.chat_id).with_timeout(tg_cfg.timeout_seconds),
    ))
}

/// The native desktop prompt: a dialog on macOS, where notifications have no
/// buttons, and a notification with Approve / Deny actions elsewhere.
fn desktop_transport() -> Arc<dyn ApprovalTransport> {
    if cfg!(target_os = "macos") {
        Arc::new(OsascriptApproval::new())
    } else {
        Arc::new(DesktopApproval)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: bool = true;
    const LINUX: bool = false;
    const TTY: bool = true;
    const PIPE: bool = false;

    #[test]
    fn macos_uses_the_dialog_without_a_tui_fallback() {
        let plan = (Kind::Desktop, None);
        assert_eq!(plan_transports(None, false, MAC, PIPE), plan);
        assert_eq!(plan_transports(None, false, MAC, TTY), plan);
        assert_eq!(plan_transports(Some("desktop"), true, MAC, PIPE), plan);
    }

    #[test]
    fn macos_falls_back_from_telegram_to_the_dialog() {
        let plan = (Kind::Telegram, Some(Kind::Desktop));
        assert_eq!(plan_transports(None, true, MAC, PIPE), plan);
        assert_eq!(plan_transports(Some("telegram"), true, MAC, TTY), plan);
    }

    #[test]
    fn elsewhere_the_tui_falls_back_only_on_a_terminal() {
        assert_eq!(
            plan_transports(None, false, LINUX, TTY),
            (Kind::Desktop, Some(Kind::Tui))
        );
        assert_eq!(
            plan_transports(None, false, LINUX, PIPE),
            (Kind::Desktop, None)
        );
        assert_eq!(
            plan_transports(None, true, LINUX, TTY),
            (Kind::Telegram, Some(Kind::Tui))
        );
        assert_eq!(
            plan_transports(None, true, LINUX, PIPE),
            (Kind::Telegram, None)
        );
    }

    #[test]
    fn explicit_tui_is_honoured_everywhere() {
        for (is_macos, stderr_is_tty) in [(MAC, PIPE), (LINUX, PIPE), (LINUX, TTY)] {
            assert_eq!(
                plan_transports(Some("tui"), true, is_macos, stderr_is_tty),
                (Kind::Tui, None)
            );
        }
    }

    #[test]
    fn unknown_env_value_means_desktop_even_with_telegram_configured() {
        assert_eq!(
            plan_transports(Some("pigeon"), true, MAC, PIPE),
            (Kind::Desktop, None)
        );
    }
}
