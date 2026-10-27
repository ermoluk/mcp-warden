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
    /// The MCP client that made the call (`name version`), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// Id of the `mcp-warden mcp` process (one per client connection) that
    /// recorded the event, so calls from one agent session group together.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
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
    /// Refused before authorisation: the request failed validation (unknown
    /// preset, path / command / query outside the allow-list, …). Nobody was
    /// prompted, no credential was read and the upstream was never called.
    Refused,
    /// The approval prompt could not be shown (the transport returned an
    /// error). Nobody approved or denied; the call was refused — errors fail
    /// closed and never become approvals.
    Failed,
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
    /// Tag events recorded from now on with this session id. Sinks that
    /// don't store sessions may ignore it.
    fn set_session(&self, _id: &str) {}
    /// Tag events recorded from now on with the MCP client (`name version`)
    /// once it has introduced itself. Sinks may ignore it.
    fn set_client(&self, _client: &str) {}
}

/// Cap `input` at `max_chars` characters, replacing the tail with `…` when
/// it is cut (the `…` counts toward the cap). Counts characters, not bytes.
pub fn clip(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    let mut out: String = input.chars().take(max_chars.saturating_sub(1)).collect();
    if max_chars > 0 {
        out.push('…');
    }
    out
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
    fn round_trip_refused_decision() {
        let dir = tempdir().unwrap();
        let sink = sqlite_sink::LocalSqlite::open(&dir.path().join("audit.db")).unwrap();
        let id = sink
            .record_pending("preset", "proxy_http", "DELETE /admin")
            .unwrap();
        sink.record_decision(id, AuditDecision::Refused).unwrap();
        let recent = sink.recent(10).unwrap();
        assert_eq!(recent[0].decision, Some(AuditDecision::Refused));
    }

    #[test]
    fn refused_serialises_as_lowercase() {
        assert_eq!(
            serde_json::to_string(&AuditDecision::Refused).unwrap(),
            "\"refused\""
        );
    }

    #[test]
    fn events_carry_the_session_and_client() {
        let dir = tempdir().unwrap();
        let sink = sqlite_sink::LocalSqlite::open(&dir.path().join("audit.db")).unwrap();
        sink.record_pending("p", "proxy_http", "before").unwrap();
        sink.set_session("a1b2c3");
        sink.record_pending("p", "proxy_http", "no client yet")
            .unwrap();
        sink.set_client("claude-code 2.1.0");
        sink.record_pending("p", "proxy_http", "with client")
            .unwrap();
        let got: Vec<(Option<String>, Option<String>)> = sink
            .recent(10)
            .unwrap()
            .into_iter()
            .rev()
            .map(|e| (e.session, e.client))
            .collect();
        assert_eq!(
            got,
            [
                (None, None),
                (Some("a1b2c3".into()), None),
                (Some("a1b2c3".into()), Some("claude-code 2.1.0".into())),
            ]
        );
    }

    #[test]
    fn databases_from_before_sessions_are_migrated() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.db");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    preset TEXT NOT NULL,
                    action TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    decision TEXT,
                    outcome_kind TEXT,
                    outcome_data TEXT
                );
                INSERT INTO events (created_at, preset, action, summary, decision)
                VALUES ('2026-10-01T00:00:00Z', 'old', 'proxy_http', 'GET /x', 'approved');",
            )
            .unwrap();
        }
        let sink = sqlite_sink::LocalSqlite::open(&path).unwrap();
        sink.set_session("s1");
        sink.record_pending("new", "proxy_http", "GET /y").unwrap();
        let events = sink.recent(10).unwrap();
        assert_eq!(events.len(), 2, "old rows are kept");
        assert_eq!(events[1].preset, "old");
        assert_eq!(events[1].session, None);
        assert_eq!(events[0].session.as_deref(), Some("s1"));
        // Opening again is a no-op.
        sqlite_sink::LocalSqlite::open(&path).unwrap();
    }

    #[test]
    fn round_trip_failed_decision() {
        let dir = tempdir().unwrap();
        let sink = sqlite_sink::LocalSqlite::open(&dir.path().join("audit.db")).unwrap();
        let id = sink
            .record_pending("preset", "proxy_http", "GET /users")
            .unwrap();
        sink.record_decision(id, AuditDecision::Failed).unwrap();
        let recent = sink.recent(10).unwrap();
        assert_eq!(recent[0].decision, Some(AuditDecision::Failed));
    }

    #[test]
    fn failed_serialises_as_lowercase() {
        assert_eq!(
            serde_json::to_string(&AuditDecision::Failed).unwrap(),
            "\"failed\""
        );
    }

    #[test]
    fn clip_keeps_short_text_and_marks_cuts() {
        assert_eq!(clip("GET /users", 20), "GET /users");
        assert_eq!(clip("abcdef", 6), "abcdef");
        assert_eq!(clip("abcdefg", 6), "abcde…");
        // Counts characters, not bytes, so multi-byte text is never split.
        assert_eq!(clip("ééééé", 3), "éé…");
        assert_eq!(clip("abc", 0), "");
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
