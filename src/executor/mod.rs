use mcp_warden_core::approval::{ApprovalDecision, ApprovalRequest, ApprovalTransport};
use mcp_warden_core::audit::{AuditDecision, AuditOutcome, AuditSink};
use mcp_warden_core::config::{ApprovalPolicy, Preset};
use mcp_warden_core::error::{Result, WardenError};
use mcp_warden_core::keychain::KeychainStore;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub mod db;
pub mod http;
pub mod known_hosts;
pub mod sftp;
pub mod ssh;

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
                .await?
        } else {
            match preset.approval {
                ApprovalPolicy::Auto => ApprovalDecision::Approved,
                ApprovalPolicy::Deny => ApprovalDecision::Denied,
                ApprovalPolicy::Prompt => {
                    let offer_window = preset.approval_window_seconds.is_some_and(|n| n > 0);
                    self.prompt(preset, action, summary, offer_window).await?
                }
            }
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
}
