use crate::error::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub mod sqlite_sink;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub preset: String,
    pub action: String,
    pub summary: String,
    pub decision: Option<AuditDecision>,
    pub outcome: Option<AuditOutcome>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuditDecision {
    Approved,
    Denied,
    Auto,
    Timeout,
    /// Authorised by an active time-boxed approval window — the user did
    /// not see a fresh prompt for this call (spec: time-boxed approvals).
    Windowed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum AuditOutcome {
    Ok { status: u16 },
    Err { message: String },
}

/// Append-only audit log surface. There is intentionally no `delete`,
/// `clear`, or `truncate` method — the trait surface enforces append-only
/// (spec §9.7).
pub trait AuditSink: Send + Sync {
    fn record_pending(&self, preset: &str, action: &str, summary: &str) -> Result<i64>;
    fn record_decision(&self, event_id: i64, decision: AuditDecision) -> Result<()>;
    fn record_outcome(&self, event_id: i64, outcome: AuditOutcome) -> Result<()>;
    fn recent(&self, limit: usize) -> Result<Vec<AuditEvent>>;
    fn since(&self, ts: DateTime<Utc>) -> Result<Vec<AuditEvent>>;
}

/// Replace any of `secrets` that appear in `input` with `***`.
///
/// Used by audit-record helpers to keep secret values out of summaries.
#[allow(dead_code)]
pub fn redact(input: &str, secrets: &[&str]) -> String {
    let mut out = input.to_string();
    for s in secrets {
        if !s.is_empty() {
            out = out.replace(s, "***");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn round_trip_event() {
        let dir = tempdir().unwrap();
        let sink = sqlite_sink::LocalSqlite::open(&dir.path().join("audit.db")).unwrap();
        let id = sink
            .record_pending("preset", "proxy_http", "GET /users")
            .unwrap();
        sink.record_decision(id, AuditDecision::Approved).unwrap();
        sink.record_outcome(id, AuditOutcome::Ok { status: 200 })
            .unwrap();
        let recent = sink.recent(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].preset, "preset");
        assert_eq!(recent[0].decision, Some(AuditDecision::Approved));
        assert_eq!(recent[0].outcome, Some(AuditOutcome::Ok { status: 200 }));
    }

    #[test]
    fn round_trip_windowed_decision() {
        let dir = tempdir().unwrap();
        let sink = sqlite_sink::LocalSqlite::open(&dir.path().join("audit.db")).unwrap();
        let id = sink
            .record_pending("preset", "proxy_http", "GET /users")
            .unwrap();
        sink.record_decision(id, AuditDecision::Windowed).unwrap();
        let recent = sink.recent(10).unwrap();
        assert_eq!(recent[0].decision, Some(AuditDecision::Windowed));
    }

    #[test]
    fn redacts_known_secret_from_summary() {
        let secret = "ghp_supersecret123";
        let summary = redact(&format!("Authorization: Bearer {secret}"), &[secret]);
        assert!(!summary.contains("supersecret"));
        assert!(summary.contains("***"));
    }

    // The append-only invariant (spec §9.7) is enforced by the trait
    // surface itself: `AuditSink` exposes no destructive method, and any
    // PR that adds one would surface in code review. We do not enforce it
    // via a source-scanning test because such a test would falsely match
    // its own forbidden-strings list.
}
