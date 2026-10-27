use mcp_warden_core::approval::{ApprovalDecision, ApprovalRequest, ApprovalTransport};
use mcp_warden_core::audit::{AuditDecision, AuditOutcome, AuditSink, clip};
use mcp_warden_core::config::{ApprovalPolicy, Preset};
use mcp_warden_core::error::{Result, WardenError};
use mcp_warden_core::keychain::KeychainStore;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub mod db;
pub mod http;
pub mod known_hosts;
pub mod policy;
pub mod sftp;
pub mod ssh;
pub mod summary;

/// Longest agent-supplied text (preset name, summary, error) kept in a
/// `refused` audit event. Refusals are recorded without a human in the
/// loop, so this bounds how much a single call can write to the log.
pub const MAX_REFUSED_TEXT: usize = 1024;

/// Source of "now" for time-boxed approval windows. Production uses
/// `Instant::now`; tests substitute a controllable clock to advance time
/// without sleeping.
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Composition root for executing actions through a preset.
///
/// Holds references (Arc) to all the pluggable abstractions. The executor
/// decides whether the call may proceed (auto / prompt / deny + force-prompt
/// override for `get_secret_for_env`), records the decision in audit, and
/// returns either an authorised event-id or a structured error.
///
/// `approval_windows` is an in-process cache of active time-boxed approvals.
/// Each entry maps `(preset_name, action)` to its expiry instant. The cache
/// is intentionally **never** persisted: a process restart clears every
/// window, by design (spec: time-boxed approvals).
pub struct ActionExecutor {
    pub keychain: Arc<dyn KeychainStore>,
    pub approval: Arc<dyn ApprovalTransport>,
    pub approval_fallback: Option<Arc<dyn ApprovalTransport>>,
    pub audit: Arc<dyn AuditSink>,
    pub clock: Arc<dyn Clock>,
    approval_windows: tokio::sync::Mutex<HashMap<(String, String), Instant>>,
}

impl ActionExecutor {
    pub fn new(
        keychain: Arc<dyn KeychainStore>,
        approval: Arc<dyn ApprovalTransport>,
        approval_fallback: Option<Arc<dyn ApprovalTransport>>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self::with_clock(
            keychain,
            approval,
            approval_fallback,
            audit,
            Arc::new(SystemClock),
        )
    }

    pub fn with_clock(
        keychain: Arc<dyn KeychainStore>,
        approval: Arc<dyn ApprovalTransport>,
        approval_fallback: Option<Arc<dyn ApprovalTransport>>,
        audit: Arc<dyn AuditSink>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            keychain,
            approval,
            approval_fallback,
            audit,
            clock,
            approval_windows: tokio::sync::Mutex::new(HashMap::new()),
        }
    }
}

impl ActionExecutor {
    /// Decide whether the call may proceed; record the decision in audit.
    /// Returns the audit event id on success.
    ///
    /// `force_prompt = true` is used by `get_secret_for_env` to override the
    /// preset's policy — that tool always prompts (spec §6) and is never
    /// satisfied by an existing approval window.
    ///
    /// Time-boxed approvals: when `force_prompt = false` and the preset's
    /// policy is `prompt`, the executor first checks the in-process window
    /// cache for an active `(preset, action)` entry. If found, the call is
    /// authorised without re-prompting and recorded as `AuditDecision::Windowed`.
    /// If the user chooses `ApprovedForWindow` in the prompt, a new entry is
    /// inserted with `now + preset.approval_window_seconds`.
    pub async fn authorise(
        &self,
        preset: &Preset,
        action: &str,
        summary: &str,
        force_prompt: bool,
    ) -> Result<i64> {
        let event_id = self.audit.record_pending(&preset.name, action, summary)?;

        // Active window short-circuit (only for non-forced prompt-policy calls).
        if !force_prompt
            && preset.approval == ApprovalPolicy::Prompt
            && self.window_is_active(&preset.name, action).await
        {
            self.audit
                .record_decision(event_id, AuditDecision::Windowed)?;
            return Ok(event_id);
        }

        let decision = if force_prompt {
            self.prompt(preset, action, summary, /* offer_window = */ false)
                .await
        } else {
            match preset.approval {
                ApprovalPolicy::Auto => Ok(ApprovalDecision::Approved),
                ApprovalPolicy::Deny => Ok(ApprovalDecision::Denied),
                ApprovalPolicy::Prompt => {
                    let offer_window = preset.approval_window_seconds.is_some_and(|n| n > 0);
                    self.prompt(preset, action, summary, offer_window).await
                }
            }
        };
        let decision = match decision {
            Ok(d) => d,
            Err(e) => return Err(self.prompt_failed(event_id, e)?),
        };

        // If the user approved for the window, register it BEFORE recording
        // audit so a race that observed audit decided=approved can already
        // see the window. force_prompt callers never register a window.
        if !force_prompt && matches!(decision, ApprovalDecision::ApprovedForWindow) {
            if let Some(cap) = preset.approval_window_seconds.filter(|n| *n > 0) {
                self.register_window(&preset.name, action, cap).await;
            }
        }

        let audit_label = if !force_prompt && preset.approval == ApprovalPolicy::Auto {
            AuditDecision::Auto
        } else {
            match decision {
                // Both "Approved" and "ApprovedForWindow" represent a fresh
                // user-driven approval at this moment — audit them as
                // Approved. Windowed is reserved for *re-use* of a prior
                // window without a fresh prompt.
                ApprovalDecision::Approved | ApprovalDecision::ApprovedForWindow => {
                    AuditDecision::Approved
                }
                ApprovalDecision::Denied => AuditDecision::Denied,
                ApprovalDecision::Timeout => AuditDecision::Timeout,
            }
        };
        self.audit.record_decision(event_id, audit_label)?;

        match decision {
            ApprovalDecision::Approved | ApprovalDecision::ApprovedForWindow => Ok(event_id),
            ApprovalDecision::Denied => {
                self.audit.record_outcome(
                    event_id,
                    AuditOutcome::Err {
                        message: "denied".into(),
                    },
                )?;
                Err(WardenError::ApprovalDenied)
            }
            ApprovalDecision::Timeout => {
                self.audit.record_outcome(
                    event_id,
                    AuditOutcome::Err {
                        message: "approval timeout".into(),
                    },
                )?;
                Err(WardenError::ApprovalTimeout)
            }
        }
    }

    /// Record a prompt the transport could not show and build the error the
    /// agent gets. Nobody approved, so the call is refused: errors fail closed
    /// and never become approvals. The transport error holds no secret —
    /// credentials are only read after authorisation (invariant 1).
    fn prompt_failed(&self, event_id: i64, err: WardenError) -> Result<WardenError> {
        let message = clip(&err.to_string(), MAX_REFUSED_TEXT);
        self.audit
            .record_decision(event_id, AuditDecision::Failed)?;
        self.audit.record_outcome(
            event_id,
            AuditOutcome::Err {
                message: message.clone(),
            },
        )?;
        Ok(WardenError::Executor(format!(
            "approval prompt could not be shown ({message}); the action did not run"
        )))
    }

    /// Record a request refused before `authorise` — it failed validation,
    /// so nobody was prompted, no credential was read and the upstream was
    /// never called. `preset` is the name the agent asked for (it may not
    /// exist), `summary` what it asked for, `err` why it was refused. None of
    /// them can hold a secret value: credentials are only read after
    /// authorisation (invariant 1).
    ///
    /// Best effort: the request is refused either way, so an audit write
    /// failure is logged to stderr rather than replacing the validation
    /// error the agent needs to see.
    pub fn record_refused(&self, preset: &str, action: &str, summary: &str, err: &WardenError) {
        let recorded = self
            .audit
            .record_pending(
                &clip(preset, MAX_REFUSED_TEXT),
                action,
                &clip(summary, MAX_REFUSED_TEXT),
            )
            .and_then(|id| {
                self.audit.record_decision(id, AuditDecision::Refused)?;
                self.audit.record_outcome(
                    id,
                    AuditOutcome::Err {
                        message: clip(&err.to_string(), MAX_REFUSED_TEXT),
                    },
                )
            });
        if let Err(e) = recorded {
            tracing::warn!("could not audit refused {action} call: {e}");
        }
    }

    /// Check whether a non-expired window exists for `(preset, action)`.
    /// Opportunistically GCs expired entries while the lock is held.
    async fn window_is_active(&self, preset: &str, action: &str) -> bool {
        let now = self.clock.now();
        let mut guard = self.approval_windows.lock().await;
        guard.retain(|_, expires| *expires > now);
        guard
            .get(&(preset.to_string(), action.to_string()))
            .is_some_and(|expires| *expires > now)
    }

    async fn register_window(&self, preset: &str, action: &str, window_seconds: u64) {
        let expires = self.clock.now() + Duration::from_secs(window_seconds);
        self.approval_windows
            .lock()
            .await
            .insert((preset.to_string(), action.to_string()), expires);
    }

    async fn prompt(
        &self,
        preset: &Preset,
        action: &str,
        summary: &str,
        offer_window: bool,
    ) -> Result<ApprovalDecision> {
        let window_seconds = if offer_window {
            preset.approval_window_seconds.filter(|n| *n > 0)
        } else {
            None
        };
        let req = ApprovalRequest::new(preset.name.clone(), action.into(), summary.into())
            .with_window(window_seconds);
        let primary = self.approval.request(req.clone()).await?;
        let result = match (&primary, self.approval_fallback.as_ref()) {
            (ApprovalDecision::Timeout, Some(fb)) => fb.request(req).await?,
            _ => primary,
        };
        // Defence-in-depth: if the transport returns ApprovedForWindow but
        // the preset didn't offer windowing (e.g. a buggy / malicious
        // transport), demote it to a one-shot Approved.
        if matches!(result, ApprovalDecision::ApprovedForWindow) && !offer_window {
            return Ok(ApprovalDecision::Approved);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use mcp_warden_core::approval::{ApprovalDecision, ApprovalRequest, ApprovalTransport};
    use mcp_warden_core::audit::sqlite_sink::LocalSqlite;
    use mcp_warden_core::config::{ApprovalPolicy, Auth, Preset, PresetType};
    use mcp_warden_core::keychain::memory::InMemoryKeychain;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingApproval {
        decision: ApprovalDecision,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl ApprovalTransport for CountingApproval {
        async fn request(
            &self,
            _r: ApprovalRequest,
        ) -> mcp_warden_core::error::Result<ApprovalDecision> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.decision)
        }
    }

    fn preset(policy: ApprovalPolicy) -> Preset {
        Preset {
            name: "p".into(),
            preset_type: PresetType::Http,
            description: "x".into(),
            base_url: Some("https://api.example.com".into()),
            auth: Some(Auth::Bearer { secret: "k".into() }),
            allowed_paths: vec!["/users".into()],
            allowed_methods: vec!["GET".into()],
            approval: policy,
            approval_window_seconds: None,
            host: None,
            user: None,
            port: None,
            secret: None,
            allowed_commands: vec![],
            timeout_seconds: None,
            known_hosts: None,
            allow_sftp: false,
            sftp_allowed_paths: vec![],
            database: None,
            queries: vec![],
        }
    }

    fn exec_with(
        primary: Arc<dyn ApprovalTransport>,
        fallback: Option<Arc<dyn ApprovalTransport>>,
    ) -> (ActionExecutor, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let exec = ActionExecutor::new(
            Arc::new(InMemoryKeychain::new()),
            primary,
            fallback,
            Arc::new(LocalSqlite::open(&dir.path().join("audit.db")).unwrap()),
        );
        (exec, dir)
    }

    fn exec_with_clock(
        primary: Arc<dyn ApprovalTransport>,
        clock: Arc<dyn Clock>,
    ) -> (ActionExecutor, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let exec = ActionExecutor::with_clock(
            Arc::new(InMemoryKeychain::new()),
            primary,
            None,
            Arc::new(LocalSqlite::open(&dir.path().join("audit.db")).unwrap()),
            clock,
        );
        (exec, dir)
    }

    /// Test clock whose `now()` returns whatever the inner Instant says.
    /// Advance with `advance(d)`.
    struct FakeClock {
        inner: std::sync::Mutex<Instant>,
    }
    impl FakeClock {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: std::sync::Mutex::new(Instant::now()),
            })
        }
        fn advance(&self, d: Duration) {
            let mut g = self.inner.lock().unwrap();
            *g += d;
        }
    }
    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            *self.inner.lock().unwrap()
        }
    }

    fn preset_with_window(window: Option<u64>) -> Preset {
        Preset {
            approval_window_seconds: window,
            ..preset(ApprovalPolicy::Prompt)
        }
    }

    struct DecidingApproval {
        decision: ApprovalDecision,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl ApprovalTransport for DecidingApproval {
        async fn request(
            &self,
            _r: ApprovalRequest,
        ) -> mcp_warden_core::error::Result<ApprovalDecision> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.decision)
        }
    }

    #[tokio::test]
    async fn auto_does_not_call_approval() {
        let counter = Arc::new(CountingApproval {
            decision: ApprovalDecision::Approved,
            calls: AtomicUsize::new(0),
        });
        let (exec, _dir) = exec_with(counter.clone(), None);
        let id = exec
            .authorise(
                &preset(ApprovalPolicy::Auto),
                "proxy_http",
                "GET /users",
                false,
            )
            .await
            .unwrap();
        assert!(id > 0);
        assert_eq!(counter.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn prompt_calls_approval_and_proceeds_when_approved() {
        let counter = Arc::new(CountingApproval {
            decision: ApprovalDecision::Approved,
            calls: AtomicUsize::new(0),
        });
        let (exec, _dir) = exec_with(counter.clone(), None);
        let id = exec
            .authorise(
                &preset(ApprovalPolicy::Prompt),
                "proxy_http",
                "GET /users",
                false,
            )
            .await
            .unwrap();
        assert!(id > 0);
        assert_eq!(counter.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn deny_policy_short_circuits_without_calling_approval() {
        let counter = Arc::new(CountingApproval {
            decision: ApprovalDecision::Approved,
            calls: AtomicUsize::new(0),
        });
        let (exec, _dir) = exec_with(counter.clone(), None);
        let err = exec
            .authorise(
                &preset(ApprovalPolicy::Deny),
                "proxy_http",
                "GET /users",
                false,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, WardenError::ApprovalDenied));
        assert_eq!(counter.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn primary_timeout_falls_through_to_fallback() {
        let primary = Arc::new(CountingApproval {
            decision: ApprovalDecision::Timeout,
            calls: AtomicUsize::new(0),
        });
        let fallback = Arc::new(CountingApproval {
            decision: ApprovalDecision::Approved,
            calls: AtomicUsize::new(0),
        });
        let (exec, _dir) = exec_with(primary.clone(), Some(fallback.clone()));
        exec.authorise(
            &preset(ApprovalPolicy::Prompt),
            "proxy_http",
            "GET /users",
            false,
        )
        .await
        .unwrap();
        assert_eq!(primary.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn force_prompt_overrides_auto_policy() {
        let counter = Arc::new(CountingApproval {
            decision: ApprovalDecision::Approved,
            calls: AtomicUsize::new(0),
        });
        let (exec, _dir) = exec_with(counter.clone(), None);
        exec.authorise(
            &preset(ApprovalPolicy::Auto),
            "get_secret_for_env",
            "reveal foo",
            true,
        )
        .await
        .unwrap();
        assert_eq!(
            counter.calls.load(Ordering::SeqCst),
            1,
            "force_prompt must call approval even for Auto presets"
        );
    }

    // -------- time-boxed approvals --------

    #[tokio::test]
    async fn windowed_call_skips_approval_within_ttl() {
        let counter = Arc::new(DecidingApproval {
            decision: ApprovalDecision::ApprovedForWindow,
            calls: AtomicUsize::new(0),
        });
        let (exec, _dir) = exec_with(counter.clone(), None);
        let p = preset_with_window(Some(600));

        exec.authorise(&p, "proxy_http", "GET /a", false)
            .await
            .unwrap();
        exec.authorise(&p, "proxy_http", "GET /b", false)
            .await
            .unwrap();

        assert_eq!(
            counter.calls.load(Ordering::SeqCst),
            1,
            "second call must reuse the window, not re-prompt"
        );
        let recent = exec.audit.recent(10).unwrap();
        // Events come back newest-first.
        assert_eq!(recent[0].decision, Some(AuditDecision::Windowed));
        assert_eq!(recent[1].decision, Some(AuditDecision::Approved));
    }

    #[tokio::test]
    async fn window_expires_after_ttl() {
        let counter = Arc::new(DecidingApproval {
            decision: ApprovalDecision::ApprovedForWindow,
            calls: AtomicUsize::new(0),
        });
        let clock = FakeClock::new();
        let (exec, _dir) = exec_with_clock(counter.clone(), clock.clone());
        let p = preset_with_window(Some(60));

        exec.authorise(&p, "proxy_http", "first", false)
            .await
            .unwrap();
        clock.advance(Duration::from_secs(61));
        exec.authorise(&p, "proxy_http", "second", false)
            .await
            .unwrap();

        assert_eq!(
            counter.calls.load(Ordering::SeqCst),
            2,
            "expired window must trigger a fresh prompt"
        );
    }

    #[tokio::test]
    async fn window_keyed_per_action() {
        let counter = Arc::new(DecidingApproval {
            decision: ApprovalDecision::ApprovedForWindow,
            calls: AtomicUsize::new(0),
        });
        let (exec, _dir) = exec_with(counter.clone(), None);
        let p = preset_with_window(Some(600));

        exec.authorise(&p, "proxy_http", "x", false).await.unwrap();
        exec.authorise(&p, "ssh_exec", "y", false).await.unwrap();

        assert_eq!(
            counter.calls.load(Ordering::SeqCst),
            2,
            "approve-for-window on proxy_http must NOT cover ssh_exec"
        );
    }

    #[tokio::test]
    async fn force_prompt_ignores_existing_window() {
        let counter = Arc::new(DecidingApproval {
            decision: ApprovalDecision::ApprovedForWindow,
            calls: AtomicUsize::new(0),
        });
        let (exec, _dir) = exec_with(counter.clone(), None);
        let p = preset_with_window(Some(600));

        exec.authorise(&p, "proxy_http", "x", false).await.unwrap();
        exec.authorise(&p, "proxy_http", "x", true).await.unwrap();

        assert_eq!(
            counter.calls.load(Ordering::SeqCst),
            2,
            "force_prompt must always re-prompt even with an active window"
        );
    }

    #[tokio::test]
    async fn force_prompt_does_not_create_window() {
        let counter = Arc::new(DecidingApproval {
            decision: ApprovalDecision::ApprovedForWindow,
            calls: AtomicUsize::new(0),
        });
        let (exec, _dir) = exec_with(counter.clone(), None);
        let p = preset_with_window(Some(600));

        // force_prompt=true on first call — must be demoted, no window registered.
        exec.authorise(&p, "proxy_http", "x", true).await.unwrap();
        // Subsequent normal call must STILL prompt.
        exec.authorise(&p, "proxy_http", "x", false).await.unwrap();

        assert_eq!(counter.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn auto_policy_ignores_window_field() {
        let counter = Arc::new(DecidingApproval {
            decision: ApprovalDecision::ApprovedForWindow,
            calls: AtomicUsize::new(0),
        });
        let (exec, _dir) = exec_with(counter.clone(), None);
        let p = Preset {
            approval_window_seconds: Some(600),
            ..preset(ApprovalPolicy::Auto)
        };

        exec.authorise(&p, "proxy_http", "x", false).await.unwrap();
        exec.authorise(&p, "proxy_http", "y", false).await.unwrap();

        assert_eq!(
            counter.calls.load(Ordering::SeqCst),
            0,
            "auto presets must not invoke approval, window field is moot"
        );
        let recent = exec.audit.recent(10).unwrap();
        assert!(
            recent
                .iter()
                .all(|e| e.decision == Some(AuditDecision::Auto)),
            "auto-policy calls must audit as Auto, never Windowed"
        );
    }

    // -------- refused requests --------

    fn never_called() -> Arc<CountingApproval> {
        Arc::new(CountingApproval {
            decision: ApprovalDecision::Approved,
            calls: AtomicUsize::new(0),
        })
    }

    /// The newest audit event must be a `refused` record of exactly what the
    /// agent asked for, with the validation error as its outcome.
    fn assert_refused(
        exec: &ActionExecutor,
        preset: &str,
        action: &str,
        summary: &str,
        err: &WardenError,
    ) {
        let recent = exec.audit.recent(10).unwrap();
        assert_eq!(recent.len(), 1, "exactly one event per refused call");
        let e = &recent[0];
        assert_eq!(e.preset, preset);
        assert_eq!(e.action, action);
        assert_eq!(e.summary, summary);
        assert_eq!(e.decision, Some(AuditDecision::Refused));
        assert_eq!(
            e.outcome,
            Some(AuditOutcome::Err {
                message: err.to_string()
            })
        );
    }

    fn ssh_preset() -> Preset {
        Preset {
            name: "deploy".into(),
            preset_type: PresetType::Ssh,
            host: Some("h".into()),
            user: Some("u".into()),
            port: Some(22),
            secret: Some("k".into()),
            allowed_commands: vec!["^git pull$".into()],
            allow_sftp: true,
            sftp_allowed_paths: vec!["/srv/app".into()],
            base_url: None,
            auth: None,
            allowed_paths: vec![],
            allowed_methods: vec![],
            ..preset(ApprovalPolicy::Prompt)
        }
    }

    #[tokio::test]
    async fn refused_http_call_is_audited_with_raw_path() {
        let approval = never_called();
        let (exec, _dir) = exec_with(approval.clone(), None);
        let req = http::HttpRequest {
            preset_name: "p".into(),
            path: "/admin/keys".into(),
            method: "get".into(),
            body: None,
            query: None,
        };
        let err = http::execute(&exec, &preset(ApprovalPolicy::Prompt), req)
            .await
            .unwrap_err();
        assert!(matches!(err, WardenError::Validation(_)));
        assert_eq!(approval.calls.load(Ordering::SeqCst), 0);
        assert_refused(&exec, "p", "proxy_http", "GET /admin/keys", &err);
    }

    #[tokio::test]
    async fn refused_ssh_call_is_audited_with_raw_command() {
        let approval = never_called();
        let (exec, _dir) = exec_with(approval.clone(), None);
        let err = ssh::run(&exec, &ssh_preset(), "rm -rf /".into())
            .await
            .unwrap_err();
        assert!(matches!(err, WardenError::Validation(_)));
        assert_eq!(approval.calls.load(Ordering::SeqCst), 0);
        assert_refused(&exec, "deploy", "ssh_exec", "ssh h -- rm -rf /", &err);
    }

    #[tokio::test]
    async fn refused_sftp_call_is_audited_with_raw_paths() {
        let approval = never_called();
        let (exec, _dir) = exec_with(approval.clone(), None);
        let err = sftp::run(
            &exec,
            &ssh_preset(),
            sftp::SftpDirection::Get,
            "/etc/passwd".into(),
            "/tmp/passwd".into(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, WardenError::Validation(_)));
        assert_eq!(approval.calls.load(Ordering::SeqCst), 0);
        assert_refused(
            &exec,
            "deploy",
            "sftp_transfer",
            "sftp get /etc/passwd ↔ /tmp/passwd",
            &err,
        );
    }

    #[tokio::test]
    async fn refused_db_query_is_audited_with_requested_query_name() {
        let approval = never_called();
        let (exec, _dir) = exec_with(approval.clone(), None);
        let pg = Preset {
            name: "pg".into(),
            preset_type: PresetType::Postgres,
            ..preset(ApprovalPolicy::Prompt)
        };
        let err = db::run(&exec, &pg, "drop_users".into(), vec![])
            .await
            .unwrap_err();
        assert!(matches!(err, WardenError::Validation(_)));
        assert_eq!(approval.calls.load(Ordering::SeqCst), 0);
        assert_refused(
            &exec,
            "pg",
            "db_query",
            "db postgres → drop_users (0 param)",
            &err,
        );
    }

    #[tokio::test]
    async fn refused_record_caps_agent_supplied_text() {
        // Refusals are written without any human in the loop, so a single
        // call must not be able to grow the audit log without bound.
        let (exec, _dir) = exec_with(never_called(), None);
        let long = format!("/{}", "a".repeat(10_000));
        let err = WardenError::Validation(format!("path '{long}' not allowed"));
        exec.record_refused(&long, "proxy_http", &long, &err);
        let e = &exec.audit.recent(1).unwrap()[0];
        for field in [&e.preset, &e.summary] {
            assert!(field.chars().count() <= MAX_REFUSED_TEXT);
            assert!(field.ends_with('…'));
        }
        let Some(AuditOutcome::Err { message }) = &e.outcome else {
            panic!("refused event must carry the validation error");
        };
        assert!(message.chars().count() <= MAX_REFUSED_TEXT);
    }

    #[tokio::test]
    async fn approve_for_window_is_demoted_when_window_not_offered() {
        // Window field absent → executor must not register a window,
        // even if the transport (buggy) returns ApprovedForWindow.
        let counter = Arc::new(DecidingApproval {
            decision: ApprovalDecision::ApprovedForWindow,
            calls: AtomicUsize::new(0),
        });
        let (exec, _dir) = exec_with(counter.clone(), None);
        let p = preset_with_window(None);

        exec.authorise(&p, "proxy_http", "x", false).await.unwrap();
        exec.authorise(&p, "proxy_http", "x", false).await.unwrap();

        assert_eq!(
            counter.calls.load(Ordering::SeqCst),
            2,
            "no window must be cached when the preset disables windowing"
        );
    }

    /// A transport that cannot show its prompt at all (no display, no tty, …).
    struct FailingApproval;

    #[async_trait]
    impl ApprovalTransport for FailingApproval {
        async fn request(
            &self,
            _r: ApprovalRequest,
        ) -> mcp_warden_core::error::Result<ApprovalDecision> {
            Err(WardenError::Io(std::io::Error::other(
                "Device not configured",
            )))
        }
    }

    /// The newest audit event must be a `failed` record whose outcome names
    /// the transport error, and the agent must get an error that says the
    /// action did not run.
    fn assert_failed(exec: &ActionExecutor, err: &WardenError) {
        let msg = err.to_string();
        assert!(matches!(err, WardenError::Executor(_)), "{err:?}");
        assert!(msg.contains("approval prompt could not be shown"), "{msg}");
        assert!(msg.contains("Device not configured"), "{msg}");
        let recent = exec.audit.recent(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].decision, Some(AuditDecision::Failed));
        match &recent[0].outcome {
            Some(AuditOutcome::Err { message }) => {
                assert!(message.contains("Device not configured"), "{message}")
            }
            other => panic!("expected an Err outcome, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn transport_error_is_audited_as_failed() {
        let (exec, _dir) = exec_with(Arc::new(FailingApproval), None);
        let err = exec
            .authorise(
                &preset(ApprovalPolicy::Prompt),
                "proxy_http",
                "GET /users",
                false,
            )
            .await
            .unwrap_err();
        assert_failed(&exec, &err);
    }

    #[tokio::test]
    async fn fallback_error_after_primary_timeout_is_audited_as_failed() {
        let primary = Arc::new(CountingApproval {
            decision: ApprovalDecision::Timeout,
            calls: AtomicUsize::new(0),
        });
        let (exec, _dir) = exec_with(primary.clone(), Some(Arc::new(FailingApproval)));
        let err = exec
            .authorise(
                &preset(ApprovalPolicy::Prompt),
                "proxy_http",
                "GET /users",
                false,
            )
            .await
            .unwrap_err();
        assert_eq!(primary.calls.load(Ordering::SeqCst), 1);
        assert_failed(&exec, &err);
    }

    #[tokio::test]
    async fn forced_prompt_transport_error_is_audited_as_failed() {
        let (exec, _dir) = exec_with(Arc::new(FailingApproval), None);
        let err = exec
            .authorise(
                &preset(ApprovalPolicy::Auto),
                "get_secret_for_env",
                "reveal k",
                true,
            )
            .await
            .unwrap_err();
        assert_failed(&exec, &err);
    }
}
