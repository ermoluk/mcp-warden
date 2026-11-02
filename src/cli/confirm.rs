//! Confirmations a human gives through the approval transport and that are
//! kept as stamps in the keychain (`mcp_warden_core::stamp`): an `auto`
//! preset is honoured only in the form a human confirmed, and a wrapped
//! server gets its keys only as the command a human confirmed.
//!
//! The CLI cannot tell a human from an agent at the keyboard — an agent
//! with a shell can pass `--confirm-auto` too — so every confirmation is a
//! prompt in the dialog / Telegram, like `mcp-warden unlock`.

use crate::executor::ActionExecutor;
use mcp_warden_core::audit::AuditOutcome;
use mcp_warden_core::audit::sqlite_sink::LocalSqlite;
use mcp_warden_core::config::{ApprovalPolicy, Auth, Config, Preset, WrappedServer};
use mcp_warden_core::error::{Result, WardenError};
use mcp_warden_core::keychain::KeychainStore;
use mcp_warden_core::stamp::{self, Confirmation};
use std::path::Path;
use std::sync::Arc;

/// An executor that asks through the configured approval transport and
/// records in the audit log, for confirmations made from the CLI.
pub fn executor(
    config_dir: &Path,
    cfg: &Config,
    store: Arc<dyn KeychainStore>,
) -> Result<ActionExecutor> {
    let transports = crate::cli::mcp::build_approval(cfg, store.as_ref(), config_dir)?;
    std::fs::create_dir_all(config_dir).map_err(WardenError::Io)?;
    let audit = Arc::new(LocalSqlite::open(&config_dir.join("audit.db"))?);
    Ok(ActionExecutor::new(
        store,
        transports.primary,
        transports.fallback,
        audit,
    ))
}

/// Ask a human to confirm `p` as it is now, then stamp it. Denied, timed
/// out or failed: no stamp, and the error says so.
pub async fn confirm_preset(exec: &ActionExecutor, p: &Preset) -> Result<()> {
    let summary = format!("Confirm preset '{}': {}", p.name, describe(p));
    let event = exec
        .authorise(&prompt_preset(), "confirm_preset", &summary, true)
        .await?;
    stamp::record(
        exec.keychain.as_ref(),
        &stamp::preset_stamp_name(&p.name),
        &stamp::preset_fingerprint(p),
    )?;
    exec.audit
        .record_outcome(event, AuditOutcome::Ok { status: 200 })?;
    Ok(())
}

/// A wrapped server gets its keys only as the command a human confirmed:
/// the first launch, and the first after any edit to its entry, asks.
pub async fn ensure_server_confirmed(exec: &ActionExecutor, s: &WrappedServer) -> Result<()> {
    let entry = stamp::server_stamp_name(&s.name);
    let fingerprint = stamp::server_fingerprint(s);
    let why = match stamp::check(exec.keychain.as_ref(), &entry, &fingerprint)? {
        Confirmation::Confirmed => return Ok(()),
        Confirmation::Missing => "first launch",
        Confirmation::Changed => "its entry changed since it was confirmed",
    };
    let keys: Vec<String> = s.env.iter().map(|v| s.secret_name(v)).collect();
    let summary = format!(
        "Start wrapped server '{}' ({why}): {} — with keys {}",
        s.name,
        std::iter::once(s.command.as_str())
            .chain(s.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" "),
        if keys.is_empty() {
            "none".to_string()
        } else {
            keys.join(", ")
        }
    );
    let event = exec
        .authorise(&prompt_preset(), "confirm_server", &summary, true)
        .await?;
    stamp::record(exec.keychain.as_ref(), &entry, &fingerprint)?;
    exec.audit
        .record_outcome(event, AuditOutcome::Ok { status: 200 })?;
    Ok(())
}

/// `mcp-warden preset confirm [NAME]...`: confirm the named presets, or
/// every `auto` preset that is not confirmed in its current form.
pub async fn confirm_cmd(
    names: Vec<String>,
    config_path: &Path,
    store: Arc<dyn KeychainStore>,
) -> Result<()> {
    let raw = std::fs::read_to_string(config_path).map_err(WardenError::Io)?;
    let cfg: Config = toml::from_str(&raw).map_err(|e| WardenError::Config(e.to_string()))?;
    let wanted: Vec<&Preset> = if names.is_empty() {
        cfg.preset
            .iter()
            .filter(|p| p.approval == ApprovalPolicy::Auto && !is_confirmed(store.as_ref(), p))
            .collect()
    } else {
        names
            .iter()
            .map(|n| {
                cfg.find(n)
                    .ok_or_else(|| WardenError::PresetNotFound(n.clone()))
            })
            .collect::<Result<_>>()?
    };
    if wanted.is_empty() {
        eprintln!("Every auto preset is confirmed.");
        return Ok(());
    }
    let config_dir = config_path.parent().unwrap_or(Path::new("."));
    let exec = executor(config_dir, &cfg, store)?;
    for p in wanted {
        match confirm_preset(&exec, p).await {
            Ok(()) => eprintln!("Confirmed '{}'.", p.name),
            Err(e) => {
                eprintln!("Not confirmed '{}': {e}", p.name);
                return Err(e);
            }
        }
    }
    eprintln!("Restart the MCP server for it to take effect.");
    Ok(())
}

/// After a CLI command changed `name` in the config: if it is `auto`, ask a
/// human to confirm it as it now is.
pub async fn confirm_if_auto(
    name: &str,
    config_path: &Path,
    store: Arc<dyn KeychainStore>,
) -> Result<()> {
    let raw = std::fs::read_to_string(config_path).map_err(WardenError::Io)?;
    let cfg: Config = toml::from_str(&raw).map_err(|e| WardenError::Config(e.to_string()))?;
    let Some(p) = cfg
        .find(name)
        .filter(|p| p.approval == ApprovalPolicy::Auto)
    else {
        return Ok(());
    };
    let config_dir = config_path.parent().unwrap_or(Path::new("."));
    let exec = executor(config_dir, &cfg, store)?;
    confirm_preset(&exec, p).await.map_err(|e| {
        WardenError::Validation(format!(
            "'{name}' is saved but not confirmed ({e}); until `mcp-warden preset confirm \
             {name}` succeeds, every call asks for approval"
        ))
    })
}

/// Whether `p` is confirmed in its current form.
pub fn is_confirmed(kc: &dyn KeychainStore, p: &Preset) -> bool {
    stamp::check(
        kc,
        &stamp::preset_stamp_name(&p.name),
        &stamp::preset_fingerprint(p),
    )
    .is_ok_and(|c| c == Confirmation::Confirmed)
}

/// What a confirmation prompt says about a preset: its policy, where its
/// credential goes and what it allows.
fn describe(p: &Preset) -> String {
    let policy = match p.approval {
        ApprovalPolicy::Auto => "auto (no prompt)",
        ApprovalPolicy::Prompt => "prompt",
        ApprovalPolicy::Deny => "deny",
    };
    let secret = match &p.auth {
        Some(
            Auth::Bearer { secret } | Auth::Header { secret, .. } | Auth::Basic { secret, .. },
        ) => Some(secret.as_str()),
        None => p.secret.as_deref(),
    }
    .unwrap_or("none");
    let destination = p
        .base_url
        .clone()
        .or_else(|| {
            p.host.as_ref().map(|h| match &p.user {
                Some(u) => format!("{u}@{h}"),
                None => h.clone(),
            })
        })
        .unwrap_or_default();
    let allows = if !p.allowed_paths.is_empty() || !p.allowed_methods.is_empty() {
        format!(
            "{} {}",
            p.allowed_methods.join("/"),
            if p.allowed_paths.is_empty() {
                "every path".to_string()
            } else {
                p.allowed_paths.join(", ")
            }
        )
    } else if !p.allowed_commands.is_empty() {
        p.allowed_commands.join(", ")
    } else {
        p.queries
            .iter()
            .map(|q| q.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let until = p
        .expires_at
        .map(|t| {
            format!(
                ", until {}",
                t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            )
        })
        .unwrap_or_default();
    format!("{policy}, secret {secret} → {destination}, allows {allows}{until}")
}

/// The prompt reads "confirm_preset → mcp-warden" / "confirm_server → mcp-warden".
fn prompt_preset() -> Preset {
    toml::from_str(
        r#"
        name = "mcp-warden"
        type = "http"
        description = "confirmation"
        approval = "prompt"
        "#,
    )
    .expect("static preset parses")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{CountingApproval, CountingKeychain};
    use mcp_warden_core::approval::ApprovalDecision;

    fn exec(
        decision: ApprovalDecision,
    ) -> (ActionExecutor, Arc<CountingApproval>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let approval = CountingApproval::new(decision);
        let exec = ActionExecutor::new(
            CountingKeychain::with(&[]),
            approval.clone(),
            None,
            Arc::new(LocalSqlite::open(&dir.path().join("audit.db")).unwrap()),
        );
        (exec, approval, dir)
    }

    fn auto_preset() -> Preset {
        toml::from_str(
            r#"
            name = "gh"
            type = "http"
            description = "GitHub"
            base_url = "https://api.github.com"
            auth = { type = "bearer", secret = "gh_pat" }
            allowed_methods = ["GET"]
            allowed_paths = ["/user/repos"]
            approval = "auto"
            "#,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn confirming_asks_shows_the_destination_and_stamps() {
        let (exec, approval, _dir) = exec(ApprovalDecision::Approved);
        let p = auto_preset();
        assert!(!is_confirmed(exec.keychain.as_ref(), &p));
        confirm_preset(&exec, &p).await.unwrap();
        assert!(is_confirmed(exec.keychain.as_ref(), &p));
        let shown = approval.shown.lock().unwrap();
        assert_eq!(
            shown[0].summary,
            "Confirm preset 'gh': auto (no prompt), secret gh_pat → https://api.github.com, \
             allows GET /user/repos"
        );
    }

    #[tokio::test]
    async fn a_denied_confirmation_stamps_nothing() {
        let (exec, _approval, _dir) = exec(ApprovalDecision::Denied);
        let p = auto_preset();
        assert!(confirm_preset(&exec, &p).await.is_err());
        assert!(!is_confirmed(exec.keychain.as_ref(), &p));
    }

    #[tokio::test]
    async fn a_wrapped_server_asks_once_and_again_after_an_edit() {
        let (exec, approval, _dir) = exec(ApprovalDecision::Approved);
        let mut s = WrappedServer {
            name: "github".into(),
            command: "npx".into(),
            args: vec!["-y".into(), "@github/mcp".into()],
            env: vec!["GITHUB_TOKEN".into()],
        };
        ensure_server_confirmed(&exec, &s).await.unwrap();
        ensure_server_confirmed(&exec, &s).await.unwrap();
        assert_eq!(approval.calls(), 1);
        // The agent swaps the command: the key would go to `sh -c env`.
        s.command = "sh".into();
        s.args = vec!["-c".into(), "env > /tmp/x".into()];
        ensure_server_confirmed(&exec, &s).await.unwrap();
        assert_eq!(approval.calls(), 2);
        let summary = approval.shown.lock().unwrap()[1].summary.clone();
        assert!(
            summary.contains("changed since it was confirmed"),
            "{summary}"
        );
        assert!(summary.contains("sh -c env > /tmp/x"), "{summary}");
        assert!(summary.contains("server/github/GITHUB_TOKEN"), "{summary}");

        let (denying, _, _dir2) = super::tests::exec(ApprovalDecision::Denied);
        assert!(ensure_server_confirmed(&denying, &s).await.is_err());
    }
}
