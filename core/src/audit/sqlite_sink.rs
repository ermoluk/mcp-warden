use crate::audit::{AuditDecision, AuditEvent, AuditOutcome, AuditSink};
use crate::error::{Result, WardenError};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::Mutex;

pub struct LocalSqlite {
    conn: Mutex<Connection>,
    /// (session id, client) stamped on events recorded from now on.
    session: Mutex<(Option<String>, Option<String>)>,
}

impl LocalSqlite {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(WardenError::Io)?;
        }
        if path.exists() {
            let meta = std::fs::symlink_metadata(path).map_err(WardenError::Io)?;
            if meta.file_type().is_symlink() {
                return Err(WardenError::Audit("audit db path is a symlink".into()));
            }
        }
        let conn = Connection::open(path).map_err(|e| WardenError::Audit(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                preset TEXT NOT NULL,
                action TEXT NOT NULL,
                summary TEXT NOT NULL,
                decision TEXT,
                outcome_kind TEXT,
                outcome_data TEXT,
                client TEXT,
                session TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);",
        )
        .map_err(|e| WardenError::Audit(e.to_string()))?;
        add_missing_columns(&conn)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(Self {
            conn: Mutex::new(conn),
            session: Mutex::new((None, None)),
        })
    }
}

/// Databases created before sessions were recorded lack the `client` and
/// `session` columns. Adding a column keeps every existing row (the log
/// stays append-only, invariant 7).
fn add_missing_columns(conn: &Connection) -> Result<()> {
    let audit = |e: rusqlite::Error| WardenError::Audit(e.to_string());
    let mut stmt = conn.prepare("PRAGMA table_info(events)").map_err(audit)?;
    let columns: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(audit)?
        .collect::<std::result::Result<_, _>>()
        .map_err(audit)?;
    for column in ["client", "session"] {
        if !columns.iter().any(|c| c == column) {
            conn.execute_batch(&format!("ALTER TABLE events ADD COLUMN {column} TEXT"))
                .map_err(audit)?;
        }
    }
    Ok(())
}

impl AuditSink for LocalSqlite {
    fn record_pending(&self, preset: &str, action: &str, summary: &str) -> Result<i64> {
        let (session, client) = self.session.lock().unwrap().clone();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO events (created_at, preset, action, summary, client, session) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                Utc::now().to_rfc3339(),
                preset,
                action,
                summary,
                client,
                session
            ],
        )
        .map_err(|e| WardenError::Audit(e.to_string()))?;
        Ok(conn.last_insert_rowid())
    }

    fn record_decision(&self, id: i64, d: AuditDecision) -> Result<()> {
        let label = match d {
            AuditDecision::Approved => "approved",
            AuditDecision::Denied => "denied",
            AuditDecision::Auto => "auto",
            AuditDecision::Timeout => "timeout",
            AuditDecision::Windowed => "windowed",
            AuditDecision::Refused => "refused",
            AuditDecision::Failed => "failed",
        };
        self.conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE events SET decision = ?1 WHERE id = ?2",
                params![label, id],
            )
            .map_err(|e| WardenError::Audit(e.to_string()))?;
        Ok(())
    }

    fn record_outcome(&self, id: i64, o: AuditOutcome) -> Result<()> {
        let (kind, data) = match &o {
            AuditOutcome::Ok { status } => ("ok", status.to_string()),
            AuditOutcome::Err { message } => ("err", message.clone()),
        };
        self.conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE events SET outcome_kind = ?1, outcome_data = ?2 WHERE id = ?3",
                params![kind, data, id],
            )
            .map_err(|e| WardenError::Audit(e.to_string()))?;
        Ok(())
    }

    fn recent(&self, limit: usize) -> Result<Vec<AuditEvent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, created_at, preset, action, summary, decision, outcome_kind, outcome_data, \
                 client, session FROM events ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| WardenError::Audit(e.to_string()))?;
        let rows = stmt
            .query_map(params![limit as i64], row_to_event)
            .map_err(|e| WardenError::Audit(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| WardenError::Audit(e.to_string()))
    }

    fn since(&self, ts: DateTime<Utc>) -> Result<Vec<AuditEvent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, created_at, preset, action, summary, decision, outcome_kind, outcome_data, \
                 client, session FROM events WHERE created_at >= ?1 ORDER BY id DESC",
            )
            .map_err(|e| WardenError::Audit(e.to_string()))?;
        let rows = stmt
            .query_map(params![ts.to_rfc3339()], row_to_event)
            .map_err(|e| WardenError::Audit(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| WardenError::Audit(e.to_string()))
    }

    fn set_session(&self, id: &str) {
        self.session.lock().unwrap().0 = Some(id.to_string());
    }

    fn set_client(&self, client: &str) {
        self.session.lock().unwrap().1 = Some(client.to_string());
    }
}

fn row_to_event(row: &rusqlite::Row) -> rusqlite::Result<AuditEvent> {
    let created: String = row.get(1)?;
    let decision: Option<String> = row.get(5)?;
    let outcome_kind: Option<String> = row.get(6)?;
    let outcome_data: Option<String> = row.get(7)?;
    Ok(AuditEvent {
        id: row.get(0)?,
        created_at: DateTime::parse_from_rfc3339(&created)
            .unwrap_or_else(|_| chrono::DateTime::<chrono::FixedOffset>::from(Utc::now()))
            .with_timezone(&Utc),
        preset: row.get(2)?,
        action: row.get(3)?,
        summary: row.get(4)?,
        decision: decision.as_deref().map(|d| match d {
            "approved" => AuditDecision::Approved,
            "denied" => AuditDecision::Denied,
            "auto" => AuditDecision::Auto,
            "windowed" => AuditDecision::Windowed,
            "refused" => AuditDecision::Refused,
            "failed" => AuditDecision::Failed,
            _ => AuditDecision::Timeout,
        }),
        outcome: match (outcome_kind.as_deref(), outcome_data) {
            (Some("ok"), Some(s)) => Some(AuditOutcome::Ok {
                status: s.parse().unwrap_or(0),
            }),
            (Some("err"), Some(s)) => Some(AuditOutcome::Err { message: s }),
            _ => None,
        },
        client: row.get(8)?,
        session: row.get(9)?,
    })
}
