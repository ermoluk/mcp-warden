use crate::executor::ActionExecutor;
use crate::executor::lock::{self, LockInfo};
use chrono::SubsecRound;
use mcp_warden_core::audit::{AuditDecision, AuditOutcome, AuditSink, sqlite_sink::LocalSqlite};
use mcp_warden_core::config::{Config, Preset};
use mcp_warden_core::error::{Result, WardenError};
use mcp_warden_core::keychain::KeychainStore;
use std::path::Path;
use std::sync::Arc;

/// `mcp-warden lock`: write the lock file. Every MCP server refuses every
/// call from its next one on and drops its approval windows.
pub fn lock(config_dir: &Path, reason: Option<String>, audit: &dyn AuditSink) -> Result<()> {
    std::fs::create_dir_all(config_dir).map_err(WardenError::Io)?;
    let path = config_dir.join(lock::LOCK_FILE);
    if let Some(existing) = lock::read(&path) {
        eprintln!("mcp-warden is already {}.", existing.describe());
        return Ok(());
    }
    let info = LockInfo {
        since: chrono::Utc::now().trunc_subsecs(0),
        reason,
    };
    lock::write(&path, &info)?;
    let id = audit.record_pending("*", "lock", &info.describe())?;
    audit.record_decision(id, AuditDecision::Auto)?;
    eprintln!(
        "mcp-warden is {}. Every MCP server refuses every call from its next one on.\n\
         Undo with `mcp-warden unlock` (it asks for approval); servers that saw the lock \
         stay locked until they restart.",
        info.describe()
    );
    Ok(())
}

/// `mcp-warden unlock` as the CLI runs it: ask through the configured
/// approval transports, then remove the lock file.
pub async fn unlock_cmd(
    config_dir: &Path,
    kc: Arc<dyn KeychainStore>,
    audit_db: &Path,
) -> Result<()> {
    let config_path = config_dir.join("config.toml");
    let cfg: Config = match std::fs::read_to_string(&config_path) {
        Ok(raw) => toml::from_str(&raw).map_err(|e| WardenError::Config(e.to_string()))?,
        Err(_) => Config::default(),
    };
    let transports = crate::cli::mcp::build_approval(&cfg, kc.as_ref(), config_dir)?;
    std::fs::create_dir_all(config_dir).map_err(WardenError::Io)?;
    let audit = Arc::new(LocalSqlite::open(audit_db)?);
    // No lock state on this executor: unlocking must not be refused by the
    // very lock it removes.
    let exec = ActionExecutor::new(kc, transports.primary, transports.fallback, audit);
    unlock(config_dir, &exec).await
}

/// Ask a human (never the agent: it cannot answer the dialog or Telegram),
/// then remove the lock file. Denied, timed out or failed: stay locked.
pub async fn unlock(config_dir: &Path, exec: &ActionExecutor) -> Result<()> {
    let path = config_dir.join(lock::LOCK_FILE);
    let Some(info) = lock::read(&path) else {
        eprintln!("mcp-warden is not locked.");
        return Ok(());
    };
    let summary = format!("Unlock mcp-warden ({})", info.describe());
    let event_id = exec
        .authorise(&unlock_preset(), "unlock", &summary, true)
        .await
        .inspect_err(|_| eprintln!("Still locked."))?;
    std::fs::remove_file(&path).map_err(WardenError::Io)?;
    exec.audit
        .record_outcome(event_id, AuditOutcome::Ok { status: 200 })?;
    eprintln!("Unlocked. MCP servers that saw the lock stay locked until they restart.");
    Ok(())
}

/// The prompt shown for `unlock` reads "unlock → mcp-warden".
fn unlock_preset() -> Preset {
    toml::from_str(
        r#"
        name = "mcp-warden"
        type = "http"
        description = "kill switch"
        approval = "prompt"
        "#,
    )
    .expect("static preset parses")
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use mcp_warden_core::approval::{ApprovalDecision, ApprovalRequest, ApprovalTransport};
    use mcp_warden_core::keychain::memory::InMemoryKeychain;

    struct Answer(Result<ApprovalDecision>);

    #[async_trait]
    impl ApprovalTransport for Answer {
        async fn request(&self, _r: ApprovalRequest) -> Result<ApprovalDecision> {
            match &self.0 {
                Ok(d) => Ok(*d),
                Err(e) => Err(WardenError::Executor(e.to_string())),
            }
        }
    }

    fn exec(dir: &Path, answer: Result<ApprovalDecision>) -> ActionExecutor {
        ActionExecutor::new(
            Arc::new(InMemoryKeychain::new()),
            Arc::new(Answer(answer)),
            None,
            Arc::new(LocalSqlite::open(&dir.join("audit.db")).unwrap()),
        )
    }

    fn locked_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let audit = LocalSqlite::open(&dir.path().join("audit.db")).unwrap();
        lock(dir.path(), Some("test".into()), &audit).unwrap();
        dir
    }

    #[test]
    fn lock_writes_the_file_and_audits() {
        let dir = locked_dir();
        let info = lock::read(&dir.path().join(lock::LOCK_FILE)).unwrap();
        assert_eq!(info.reason.as_deref(), Some("test"));
        let audit = LocalSqlite::open(&dir.path().join("audit.db")).unwrap();
        let e = &audit.recent(1).unwrap()[0];
        assert_eq!((e.preset.as_str(), e.action.as_str()), ("*", "lock"));
        assert_eq!(e.decision, Some(AuditDecision::Auto));
    }

    #[tokio::test]
    async fn approved_unlock_removes_the_lock() {
        let dir = locked_dir();
        let exec = exec(dir.path(), Ok(ApprovalDecision::Approved));
        unlock(dir.path(), &exec).await.unwrap();
        assert!(!lock::is_present(&dir.path().join(lock::LOCK_FILE)));
        let e = &exec.audit.recent(1).unwrap()[0];
        assert_eq!(e.action, "unlock");
        assert_eq!(e.decision, Some(AuditDecision::Approved));
    }

    #[tokio::test]
    async fn denied_timed_out_or_failed_unlock_keeps_the_lock() {
        let answers: [Result<ApprovalDecision>; 3] = [
            Ok(ApprovalDecision::Denied),
            Ok(ApprovalDecision::Timeout),
            Err(WardenError::Executor("no display".into())),
        ];
        for answer in answers {
            let dir = locked_dir();
            let exec = exec(dir.path(), answer);
            assert!(unlock(dir.path(), &exec).await.is_err());
            assert!(lock::is_present(&dir.path().join(lock::LOCK_FILE)));
        }
    }

    #[tokio::test]
    async fn unlock_without_a_lock_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let exec = exec(dir.path(), Ok(ApprovalDecision::Denied));
        unlock(dir.path(), &exec).await.unwrap();
    }
}
