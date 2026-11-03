use crate::audit::chain::{self, Record};
use crate::audit::{AuditDecision, AuditEvent, AuditFilter, AuditOutcome, AuditSink, ChainReport};
use crate::error::{Result, WardenError};
use chrono::{DateTime, Utc};
use rusqlite::types::Value;
use rusqlite::{Connection, TransactionBehavior, params};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

/// How long a write waits for other processes holding the database. SQLite
/// does not queue waiters, so under many writers on a slow disk (Windows
/// CI) one can wait several seconds.
const BUSY_TIMEOUT: Duration = Duration::from_secs(10);

/// The columns `row_to_event` reads, in its order.
pub(crate) const COLUMNS: &str = "id, created_at, preset, action, summary, decision, outcome_kind, \
                       outcome_data, client, session, via_event";

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
        // SQLite follows a symlink planted at the database or at a file it
        // keeps next to it (the rollback journal, the WAL and its shared
        // memory) and would write pages into whatever it names. Refuse all
        // four, and open the database itself with SQLITE_OPEN_NOFOLLOW so a
        // link swapped in after this check is refused too.
        for suffix in ["", "-journal", "-wal", "-shm"] {
            let mut file = path.as_os_str().to_owned();
            file.push(suffix);
            if std::fs::symlink_metadata(&file).is_ok_and(|m| m.file_type().is_symlink()) {
                return Err(WardenError::Audit(format!(
                    "{} is a symlink — refusing to open the audit log",
                    std::path::Path::new(&file).display()
                )));
            }
        }
        // NOFOLLOW refuses a symlink anywhere in the path, so resolve the
        // directories first (on macOS /var and /tmp are links themselves).
        // Unix only: on Windows the resolved form is a `\\?\` path and the
        // symlink checks above are what applies.
        #[cfg(unix)]
        let conn = {
            let resolved = match (path.parent(), path.file_name()) {
                (Some(dir), Some(name)) if !dir.as_os_str().is_empty() => {
                    std::fs::canonicalize(dir)
                        .map_err(WardenError::Io)?
                        .join(name)
                }
                _ => path.to_path_buf(),
            };
            Connection::open_with_flags(
                &resolved,
                rusqlite::OpenFlags::default() | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )
        };
        #[cfg(not(unix))]
        let conn = Connection::open(path);
        let mut conn = conn.map_err(|e| WardenError::Audit(e.to_string()))?;
        // Every mcp-warden process and the CLI write this file: a writer
        // waits for another rather than failing.
        conn.busy_timeout(BUSY_TIMEOUT)
            .map_err(|e| WardenError::Audit(e.to_string()))?;
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
                session TEXT,
                via_event INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);",
        )
        .map_err(|e| WardenError::Audit(e.to_string()))?;
        add_missing_columns(&conn)?;
        conn.execute_batch(chain::SCHEMA)
            .map_err(|e| WardenError::Audit(e.to_string()))?;
        chain::ensure_genesis(&mut conn)?;
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

/// Older databases lack columns added since: `client` and `session` (0.5.0),
/// `via_event` (0.5.3). Adding a column keeps every existing row (the log
/// stays append-only, invariant 7).
fn add_missing_columns(conn: &Connection) -> Result<()> {
    let audit = |e: rusqlite::Error| WardenError::Audit(e.to_string());
    let mut stmt = conn.prepare("PRAGMA table_info(events)").map_err(audit)?;
    let columns: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(audit)?
        .collect::<std::result::Result<_, _>>()
        .map_err(audit)?;
    for (column, kind) in [
        ("client", "TEXT"),
        ("session", "TEXT"),
        ("via_event", "INTEGER"),
    ] {
        if !columns.iter().any(|c| c == column) {
            conn.execute_batch(&format!("ALTER TABLE events ADD COLUMN {column} {kind}"))
                .map_err(audit)?;
        }
    }
    Ok(())
}

impl AuditSink for LocalSqlite {
    fn record_pending(&self, preset: &str, action: &str, summary: &str) -> Result<i64> {
        let (session, client) = self.session.lock().unwrap().clone();
        let at = Utc::now().to_rfc3339();
        self.write(|tx| {
            tx.execute(
                "INSERT INTO events (created_at, preset, action, summary, client, session) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![at, preset, action, summary, client, session],
            )?;
            let event = tx.last_insert_rowid();
            let record = Record::Pending {
                event,
                at: at.clone(),
                preset: preset.into(),
                action: action.into(),
                summary: summary.into(),
                client: client.clone(),
                session: session.clone(),
            };
            Ok((event, record))
        })
    }

    fn record_decision(&self, id: i64, d: AuditDecision) -> Result<()> {
        let label = d.as_str();
        self.write(|tx| {
            changed(tx.execute(
                "UPDATE events SET decision = ?1 WHERE id = ?2",
                params![label, id],
            )?)?;
            Ok((
                id,
                Record::Decision {
                    event: id,
                    decision: label.into(),
                },
            ))
        })
        .map(drop)
    }

    fn record_outcome(&self, id: i64, o: AuditOutcome) -> Result<()> {
        let (kind, data) = match &o {
            AuditOutcome::Ok { status } => ("ok", status.to_string()),
            AuditOutcome::Err { message } => ("err", message.clone()),
        };
        self.write(|tx| {
            changed(tx.execute(
                "UPDATE events SET outcome_kind = ?1, outcome_data = ?2 WHERE id = ?3",
                params![kind, data, id],
            )?)?;
            Ok((
                id,
                Record::Outcome {
                    event: id,
                    outcome_kind: kind.into(),
                    outcome_data: data.clone(),
                },
            ))
        })
        .map(drop)
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
        if let Some(id) = filter.window {
            clauses.push("(id = ? OR via_event = ?)".into());
            args.extend([Value::Integer(id), Value::Integer(id)]);
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

    fn record_windowed(&self, id: i64, via_event_id: i64) -> Result<()> {
        self.write(|tx| {
            changed(tx.execute(
                "UPDATE events SET decision = ?1, via_event = ?2 WHERE id = ?3",
                params![AuditDecision::Windowed.as_str(), via_event_id, id],
            )?)?;
            Ok((
                id,
                Record::Windowed {
                    event: id,
                    via_event: via_event_id,
                },
            ))
        })
        .map(drop)
    }

    fn chain_tip(&self) -> Result<Option<(i64, String)>> {
        chain::tip(&self.conn.lock().unwrap())
    }

    fn chain_hash_at(&self, seq: i64) -> Result<Option<String>> {
        chain::hash_at(&self.conn.lock().unwrap(), seq)
    }

    fn chain_links_from(&self, seq: i64, hash: &str) -> Result<bool> {
        chain::links_from(&self.conn.lock().unwrap(), seq, hash)
    }

    fn chain_id(&self) -> Result<Option<String>> {
        chain::chain_id(&self.conn.lock().unwrap())
    }

    fn verify_chain(&self) -> Result<ChainReport> {
        chain::verify(&self.conn.lock().unwrap())
    }

    fn set_session(&self, id: &str) {
        self.session.lock().unwrap().0 = Some(id.to_string());
    }

    fn set_client(&self, client: &str) {
        self.session.lock().unwrap().1 = Some(client.to_string());
    }
}

impl LocalSqlite {
    /// One write: the change to `events` and its chain record, in one
    /// transaction that takes the write lock up front (`BEGIN IMMEDIATE`),
    /// so processes writing at once queue and the chain stays linear.
    /// Returns the event id.
    fn write(
        &self,
        change: impl FnOnce(&rusqlite::Transaction) -> std::result::Result<(i64, Record), WriteError>,
    ) -> Result<i64> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| WardenError::Audit(e.to_string()))?;
        let (event, record) = change(&tx).map_err(|e| match e {
            WriteError::Sql(e) => WardenError::Audit(e.to_string()),
            WriteError::NoSuchEvent => WardenError::Audit("no such audit event".into()),
        })?;
        chain::append(&tx, event, &record)?;
        tx.commit().map_err(|e| WardenError::Audit(e.to_string()))?;
        Ok(event)
    }
}

enum WriteError {
    Sql(rusqlite::Error),
    NoSuchEvent,
}

impl From<rusqlite::Error> for WriteError {
    fn from(e: rusqlite::Error) -> Self {
        WriteError::Sql(e)
    }
}

/// An update must fill in an existing row.
fn changed(rows: usize) -> std::result::Result<(), WriteError> {
    if rows == 0 {
        return Err(WriteError::NoSuchEvent);
    }
    Ok(())
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
        via_event: row.get(10)?,
    })
}
