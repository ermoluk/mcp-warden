use crate::approval::{
    desktop::DesktopApproval,
    osascript::OsascriptApproval,
    powershell::PowerShellApproval,
    telegram::{TelegramApproval, TelegramBot},
    tui::TuiApproval,
};
use crate::executor::ActionExecutor;
use crate::mcp::server::WardenServer;
use is_terminal::IsTerminal;
use mcp_warden_core::approval::{ApprovalDecision, ApprovalTransport};
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
    // `auto` holds only for presets a human confirmed in this exact form.
    let (served, warnings) = presets_to_serve(&cfg, keychain.as_ref());
    for w in warnings {
        tracing::warn!("{w}");
    }
    let presets: Arc<dyn mcp_warden_core::presets::PresetSource> =
        Arc::new(FrozenSource::new(served));
    let transports = build_approval(&cfg, keychain.as_ref(), config_dir)?;
    // With Telegram configured, listen for `/lock` (and deliver button
    // presses) for as long as the server runs; servers take turns polling.
    if let Some(bot) = transports.telegram.clone() {
        tokio::spawn(bot.listen());
    }
    let audit: Arc<dyn AuditSink> = Arc::new(LocalSqlite::open(&audit_path)?);
    // One id per server process — one per client connection — so a
    // session's calls group together in the log; the client's name and
    // version are added once it introduces itself (`initialize`).
    audit.set_session(&session_id());

    let executor = Arc::new(
        ActionExecutor::new(keychain, transports.primary, transports.fallback, audit)
            .with_lock(config_dir.join(crate::executor::lock::LOCK_FILE)),
    );
    // `get_secret_for_env` may reveal the secrets of these presets and
    // wrapped servers, but never the Telegram bot token.
    let telegram_token = cfg
        .approval
        .as_ref()
        .and_then(|a| a.telegram.as_ref())
        .map(|t| t.bot_token_secret.clone());
    let revealable = cfg
        .preset
        .iter()
        .filter_map(crate::mcp::server::preset_secret)
        .chain(
            cfg.server
                .iter()
                .flat_map(|s| s.env.iter().map(|var| s.secret_name(var))),
        )
        .filter(|name| Some(name) != telegram_token.as_ref());
    // Latch a lock within a second of `mcp-warden lock`, call or no call.
    let _lock_watch = executor
        .clone()
        .watch_lock(std::time::Duration::from_secs(1));
    let server = WardenServer::new(presets, executor).with_revealable(revealable);

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

/// The presets the server serves: the config's, with every `auto` preset
/// that no human confirmed in its current form run as `prompt` (an agent
/// may have edited the file, or pointed `MCP_WARDEN_CONFIG_DIR` at its own),
/// and a warning for each.
fn presets_to_serve(
    cfg: &Config,
    kc: &dyn KeychainStore,
) -> (Vec<mcp_warden_core::config::Preset>, Vec<String>) {
    let mut presets = cfg.preset.clone();
    let warnings = mcp_warden_core::stamp::demote_unconfirmed_auto(&mut presets, kc);
    (presets, warnings)
}

/// A short random id for this server process (not a secret).
fn session_id() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default(),
    );
    h.write_u32(std::process::id());
    format!("{:012x}", h.finish() & 0xffff_ffff_ffff)
}

/// The approval transports to use, plus the Telegram bot (when
/// configured) whose `/lock` listener the MCP server runs.
pub(crate) struct ApprovalTransports {
    pub primary: Arc<dyn ApprovalTransport>,
    pub fallback: Option<Arc<dyn ApprovalTransport>>,
    pub telegram: Option<Arc<TelegramBot>>,
}

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
pub(crate) fn build_approval(
    cfg: &Config,
    kc: &dyn KeychainStore,
    config_dir: &Path,
) -> Result<ApprovalTransports> {
    let env_choice = std::env::var("MCP_WARDEN_APPROVAL_TRANSPORT").ok();
    let env_choice = env_choice.as_deref().map(str::trim).map(str::to_lowercase);
    // Debug builds only, and only with the in-memory keychain (which holds
    // no real secret): a fixed answer, so CLI tests never put a dialog on
    // the developer's screen.
    #[cfg(debug_assertions)]
    if std::env::var("MCP_WARDEN_BACKEND").as_deref() == Ok("memory") {
        let fixed = match env_choice.as_deref() {
            Some("test-approve") => Some(ApprovalDecision::Approved),
            Some("test-deny") => Some(ApprovalDecision::Denied),
            _ => None,
        };
        if let Some(decision) = fixed {
            return Ok(ApprovalTransports {
                primary: Arc::new(crate::approval::always_deny::Fixed(decision)),
                fallback: None,
                telegram: None,
            });
        }
    }
    let telegram = cfg.approval.as_ref().and_then(|a| a.telegram.as_ref());
    let (primary, fallback) = plan_transports(
        env_choice.as_deref(),
        telegram.map(|t| t.desktop_fallback),
        cfg!(any(target_os = "macos", windows)),
        std::io::stderr().is_terminal(),
    )?;
    let bot = telegram
        .map(|tg| telegram_bot(tg, kc, config_dir))
        .transpose()?;
    let build = |kind| -> Result<Arc<dyn ApprovalTransport>> {
        Ok(match kind {
            Kind::Telegram => {
                let (bot, tg) = bot.clone().zip(telegram).ok_or_else(|| {
                    WardenError::Validation(
                        "MCP_WARDEN_APPROVAL_TRANSPORT=telegram set but [approval.telegram] \
                         missing in config"
                            .into(),
                    )
                })?;
                Arc::new(TelegramApproval::new(bot).with_timeout(tg.timeout_seconds))
            }
            Kind::Desktop => desktop_transport(),
            Kind::Tui => Arc::new(TuiApproval::from_stderr()),
        })
    };
    Ok(ApprovalTransports {
        primary: build(primary)?,
        fallback: fallback.map(build).transpose()?,
        telegram: bot,
    })
}

/// Pick the primary approval transport and its fallback. `telegram` is
/// `Some(desktop_fallback)` when `[approval.telegram]` is configured.
///
/// 1. `[approval.telegram]` in the config: Telegram, and nothing else
///    unless `desktop_fallback = true`. Users pick Telegram when the agent
///    can drive the screen (threat model, R1); a local dialog shown after a
///    Telegram timeout would be one the agent can click. The environment
///    (`MCP_WARDEN_APPROVAL_TRANSPORT`) comes from the MCP client's config,
///    which the agent may be able to edit, so it may only say `telegram`
///    here; anything else refuses to start.
/// 2. Without Telegram, the env override (`desktop` / `tui`), else the
///    native desktop prompt.
///
/// A fallback is asked only when the primary times out, so it must be a
/// prompt the user can actually see. Where there is a native dialog (macOS,
/// Windows) that is the dialog. Elsewhere it is the TUI, and only when
/// stderr is a terminal: an MCP client captures the server's stderr, so a
/// TUI drawn there is invisible (and on macOS it cannot read keys at all
/// while stdin is the JSON-RPC pipe). An explicit `tui` choice is honoured
/// as is.
fn plan_transports(
    env_choice: Option<&str>,
    telegram: Option<bool>,
    has_native_dialog: bool,
    stderr_is_tty: bool,
) -> Result<(Kind, Option<Kind>)> {
    let local_fallback = || {
        if has_native_dialog {
            Some(Kind::Desktop)
        } else {
            stderr_is_tty.then_some(Kind::Tui)
        }
    };
    if let Some(desktop_fallback) = telegram {
        if env_choice.is_some_and(|e| e != "telegram") {
            return Err(WardenError::Validation(format!(
                "MCP_WARDEN_APPROVAL_TRANSPORT={} conflicts with [approval.telegram] in the \
                 config: with Telegram configured, approvals go only to Telegram (set \
                 `desktop_fallback = true` there to allow a local prompt after a timeout)",
                env_choice.unwrap_or_default()
            )));
        }
        return Ok((
            Kind::Telegram,
            desktop_fallback.then(local_fallback).flatten(),
        ));
    }
    Ok(match env_choice {
        Some("tui") => (Kind::Tui, None),
        _ => (
            Kind::Desktop,
            (!has_native_dialog).then(local_fallback).flatten(),
        ),
    })
}

/// The bot for `[approval.telegram]`, with its token from the keychain.
pub(crate) fn telegram_bot(
    tg_cfg: &TelegramConfig,
    kc: &dyn KeychainStore,
    config_dir: &Path,
) -> Result<Arc<TelegramBot>> {
    let token = kc.get(&tg_cfg.bot_token_secret)?.ok_or_else(|| {
        WardenError::Validation(format!(
            "approval.telegram.bot_token_secret '{}' not in keychain",
            tg_cfg.bot_token_secret
        ))
    })?;
    Ok(Arc::new(TelegramBot::new(
        token,
        tg_cfg.chat_id,
        config_dir,
    )))
}

/// The native desktop prompt: a dialog on macOS and Windows, where
/// notifications have no buttons, and a notification with Approve / Deny
/// actions on Linux.
fn desktop_transport() -> Arc<dyn ApprovalTransport> {
    if cfg!(target_os = "macos") {
        Arc::new(OsascriptApproval::new())
    } else if cfg!(windows) {
        Arc::new(PowerShellApproval::new())
    } else {
        Arc::new(DesktopApproval)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// macOS or Windows: a native dialog exists.
    const MAC: bool = true;
    const LINUX: bool = false;
    const TTY: bool = true;
    const PIPE: bool = false;

    fn plan(
        env: Option<&str>,
        telegram: Option<bool>,
        native_dialog: bool,
        tty: bool,
    ) -> (Kind, Option<Kind>) {
        plan_transports(env, telegram, native_dialog, tty).unwrap()
    }

    /// The A10 attack end to end: a config whose `auto` preset nobody
    /// confirmed — written by the agent, or pointed to with
    /// MCP_WARDEN_CONFIG_DIR — is served as `prompt`.
    #[test]
    fn unconfirmed_auto_presets_are_served_as_prompt() {
        use mcp_warden_core::config::ApprovalPolicy;
        let kc = mcp_warden_core::keychain::memory::InMemoryKeychain::new();
        let cfg: Config = toml::from_str(
            r#"
            [[preset]]
            name = "gh"
            type = "http"
            description = "x"
            base_url = "https://attacker.example"
            auth = { type = "bearer", secret = "gh_pat" }
            allowed_methods = ["GET"]
            approval = "auto"
            "#,
        )
        .unwrap();
        let (served, warnings) = presets_to_serve(&cfg, &kc);
        assert_eq!(served[0].approval, ApprovalPolicy::Prompt);
        assert_eq!(warnings.len(), 1);
        mcp_warden_core::stamp::record(
            &kc,
            &mcp_warden_core::stamp::preset_stamp_name("gh"),
            &mcp_warden_core::stamp::preset_fingerprint(&cfg.preset[0]),
        )
        .unwrap();
        let (served, warnings) = presets_to_serve(&cfg, &kc);
        assert_eq!(served[0].approval, ApprovalPolicy::Auto);
        assert!(warnings.is_empty());
    }

    #[test]
    fn macos_uses_the_dialog_without_a_tui_fallback() {
        let dialog = (Kind::Desktop, None);
        assert_eq!(plan(None, None, MAC, PIPE), dialog);
        assert_eq!(plan(None, None, MAC, TTY), dialog);
        assert_eq!(plan(Some("desktop"), None, MAC, PIPE), dialog);
    }

    /// Telegram is chosen because the agent may control the screen (R1), so
    /// a timed-out Telegram prompt must not reappear as a dialog the agent
    /// could click — unless the user opted in.
    #[test]
    fn telegram_has_no_local_fallback_unless_opted_in() {
        for (native, tty) in [(MAC, PIPE), (MAC, TTY), (LINUX, PIPE), (LINUX, TTY)] {
            assert_eq!(plan(None, Some(false), native, tty), (Kind::Telegram, None));
            assert_eq!(
                plan(Some("telegram"), Some(false), native, tty),
                (Kind::Telegram, None)
            );
        }
        assert_eq!(
            plan(None, Some(true), MAC, PIPE),
            (Kind::Telegram, Some(Kind::Desktop))
        );
        assert_eq!(
            plan(None, Some(true), LINUX, TTY),
            (Kind::Telegram, Some(Kind::Tui))
        );
        assert_eq!(plan(None, Some(true), LINUX, PIPE), (Kind::Telegram, None));
    }

    /// The environment comes from the MCP client's config, which an agent
    /// may be able to edit: it cannot swap Telegram for a local prompt.
    #[test]
    fn the_environment_cannot_replace_telegram_with_a_local_prompt() {
        for env in ["desktop", "tui", "pigeon", ""] {
            let err = plan_transports(Some(env), Some(false), MAC, PIPE)
                .unwrap_err()
                .to_string();
            assert!(err.contains("[approval.telegram]"), "{env}: {err}");
        }
    }

    #[test]
    fn elsewhere_the_tui_falls_back_only_on_a_terminal() {
        assert_eq!(
            plan(None, None, LINUX, TTY),
            (Kind::Desktop, Some(Kind::Tui))
        );
        assert_eq!(plan(None, None, LINUX, PIPE), (Kind::Desktop, None));
    }

    #[test]
    fn explicit_tui_is_honoured_without_telegram() {
        for (native_dialog, stderr_is_tty) in [(MAC, PIPE), (LINUX, PIPE), (LINUX, TTY)] {
            assert_eq!(
                plan(Some("tui"), None, native_dialog, stderr_is_tty),
                (Kind::Tui, None)
            );
        }
    }

    #[test]
    fn unknown_env_value_means_desktop_without_telegram() {
        assert_eq!(plan(Some("pigeon"), None, MAC, PIPE), (Kind::Desktop, None));
    }
}
