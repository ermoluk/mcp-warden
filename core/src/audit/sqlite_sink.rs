use crate::audit::{AuditDecision, AuditEvent, AuditFilter, AuditOutcome, AuditSink};
use crate::error::{Result, WardenError};
use chrono::{DateTime, Utc};
use rusqlite::types::Value;
use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::Mutex;

/// The columns `row_to_event` reads, in its order.
const COLUMNS: &str = "id, created_at, preset, action, summary, decision, outcome_kind, outcome_data, client, session";

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
        let label = d.as_str();
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
        self.query(&AuditFilter {
            limit: Some(limit),
            ..Default::default()
        })
    }

    fn since(&self, ts: DateTime<Utc>) -> Result<Vec<AuditEvent>> {
        self.query(&AuditFilter {
            since: Some(ts),
            ..Default::default()
        })
    }

    /// Filters in SQL. Every value is a bound parameter; only the number of
    /// `?` placeholders depends on the filter.
    fn query(&self, filter: &AuditFilter) -> Result<Vec<AuditEvent>> {
        let mut clauses = Vec::new();
        let mut args: Vec<Value> = Vec::new();
        if !filter.decisions.is_empty() {
            let marks = vec!["?"; filter.decisions.len()].join(", ");
            clauses.push(format!("decision IN ({marks})"));
            args.extend(
                filter
                    .decisions
                    .iter()
                    .map(|d| Value::Text(d.as_str().into())),
            );
        }
        if let Some(ts) = filter.since {
            clauses.push("created_at >= ?".into());
            args.push(Value::Text(ts.to_rfc3339()));
        }
        let mut sql = format!("SELECT {COLUMNS} FROM events");
        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        sql.push_str(" ORDER BY id DESC");
        if let Some(limit) = filter.limit {
            sql.push_str(" LIMIT ?");
            args.push(Value::Integer(i64::try_from(limit).unwrap_or(i64::MAX)));
        }
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| WardenError::Audit(e.to_string()))?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(args), row_to_event)
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
        decision: decision
            .as_deref()
            .map(|d| AuditDecision::from_name(d).unwrap_or(AuditDecision::Timeout)),
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
