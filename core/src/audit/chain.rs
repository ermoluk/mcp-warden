//! The hash chain beside the `events` table (docs/design/audit-hash-chain.md).
//!
//! `events` rows are filled in after they are inserted (the decision, the
//! outcome), so they cannot be chained themselves. Instead every write to
//! `events` appends one record to `chain`, in the same transaction:
//!
//! ```text
//! hash(seq) = SHA-256("mcp-warden-audit-v1\n" ‖ hash(seq-1) ‖ "\n" ‖ seq ‖ "\n" ‖ record)
//! ```
//!
//! The record is canonical JSON of exactly what was stored. `verify`
//! recomputes the links and checks every `events` row against its records,
//! so an edit made with `sqlite3` shows. A chain alone can be recomputed by
//! whoever edits the file; the keychain anchor (`anchor`) is what catches
//! that.

use crate::audit::ChainReport;
use crate::error::{Result, WardenError};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The hash before the first record.
pub const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The most problems `verify` lists; it says when there were more.
const MAX_PROBLEMS: usize = 20;

/// The chain table, its index and the triggers that keep it, and `events`,
/// append-only. An attacker with `sqlite3` can drop the triggers; the chain
/// then shows what they changed.
pub(crate) const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS chain (
        seq INTEGER PRIMARY KEY,
        event_id INTEGER NOT NULL,
        record TEXT NOT NULL,
        hash TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_chain_event ON chain(event_id);
    CREATE TRIGGER IF NOT EXISTS chain_no_update BEFORE UPDATE ON chain
        BEGIN SELECT RAISE(ABORT, 'audit chain is append-only'); END;
    CREATE TRIGGER IF NOT EXISTS chain_no_delete BEFORE DELETE ON chain
        BEGIN SELECT RAISE(ABORT, 'audit chain is append-only'); END;
    CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
        BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
";

/// One chain record: what one write stored, as it was stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum Record {
    /// The first record. Rows up to `legacy_through` were written before the
    /// chain existed; `legacy_digest` says whether they changed since.
    Genesis {
        v: u32,
        chain_id: String,
        legacy_through: i64,
        legacy_rows: i64,
        legacy_digest: String,
        at: String,
    },
    Pending {
        event: i64,
        at: String,
        preset: String,
        action: String,
        summary: String,
        client: Option<String>,
        session: Option<String>,
    },
    Decision {
        event: i64,
        decision: String,
    },
    Windowed {
        event: i64,
        via_event: i64,
    },
    Outcome {
        event: i64,
        outcome_kind: String,
        outcome_data: String,
    },
}

fn audit(e: impl std::fmt::Display) -> WardenError {
    WardenError::Audit(e.to_string())
}

/// The link hash of `record` at `seq` after `prev`.
pub fn link(prev: &str, seq: i64, record: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"mcp-warden-audit-v1\n");
    h.update(prev.as_bytes());
    h.update(b"\n");
    h.update(seq.to_string().as_bytes());
    h.update(b"\n");
    h.update(record.as_bytes());
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Append `record` for `event_id` inside `tx`. The tip is read inside the
/// transaction, which holds the write lock, so two writers never append
/// the same `seq`.
pub(crate) fn append(tx: &Transaction, event_id: i64, record: &Record) -> Result<()> {
    let (seq, prev) = tip_in(tx)?.unwrap_or((0, ZERO.to_string()));
    let text = serde_json::to_string(record).map_err(audit)?;
    let seq = seq + 1;
    tx.execute(
        "INSERT INTO chain (seq, event_id, record, hash) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![seq, event_id, text, link(&prev, seq, &text)],
    )
    .map_err(audit)?;
    Ok(())
}

fn tip_in(conn: &Connection) -> Result<Option<(i64, String)>> {
    conn.query_row(
        "SELECT seq, hash FROM chain ORDER BY seq DESC LIMIT 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()
    .map_err(audit)
}

/// The last record's `(seq, hash)`.
pub(crate) fn tip(conn: &Connection) -> Result<Option<(i64, String)>> {
    tip_in(conn)
}

/// The stored hash of record `seq`.
pub(crate) fn hash_at(conn: &Connection, seq: i64) -> Result<Option<String>> {
    conn.query_row("SELECT hash FROM chain WHERE seq = ?1", [seq], |r| r.get(0))
        .optional()
        .map_err(audit)
}

/// The genesis record's chain id.
pub(crate) fn chain_id(conn: &Connection) -> Result<Option<String>> {
    let text: Option<String> = conn
        .query_row("SELECT record FROM chain WHERE seq = 1", [], |r| r.get(0))
        .optional()
        .map_err(audit)?;
    Ok(
        match text.and_then(|t| serde_json::from_str::<Record>(&t).ok()) {
            Some(Record::Genesis { chain_id, .. }) => Some(chain_id),
            _ => None,
        },
    )
}

/// Whether the records from `seq` (whose hash must be `hash`) to the tip
/// are contiguous and correctly linked: what moving the anchor needs, much
/// cheaper than a full `verify`.
pub(crate) fn links_from(conn: &Connection, seq: i64, hash: &str) -> Result<bool> {
    if hash_at(conn, seq)?.as_deref() != Some(hash) {
        return Ok(false);
    }
    let mut stmt = conn
        .prepare("SELECT seq, record, hash FROM chain WHERE seq > ?1 ORDER BY seq")
        .map_err(audit)?;
    let mut rows = stmt.query([seq]).map_err(audit)?;
    let (mut prev, mut expected) = (hash.to_string(), seq + 1);
    while let Some(row) = rows.next().map_err(audit)? {
        let (n, text, h): (i64, String, String) = (
            row.get(0).map_err(audit)?,
            row.get(1).map_err(audit)?,
            row.get(2).map_err(audit)?,
        );
        if n != expected || link(&prev, n, &text) != h {
            return Ok(false);
        }
        prev = h;
        expected += 1;
    }
    Ok(true)
}

/// Start the chain of a database that has none: a new one, or one written
/// before 0.6.0, whose rows the genesis record digests. Idempotent, and
/// safe when several processes open the database at once.
pub(crate) fn ensure_genesis(conn: &mut Connection) -> Result<()> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(audit)?;
    let started: bool = tx
        .query_row("SELECT EXISTS (SELECT 1 FROM chain)", [], |r| r.get(0))
        .map_err(audit)?;
    if !started {
        let through: i64 = tx
            .query_row("SELECT COALESCE(MAX(id), 0) FROM events", [], |r| r.get(0))
            .map_err(audit)?;
        let (rows, digest) = legacy_digest(&tx, through)?;
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).map_err(audit)?;
        let genesis = Record::Genesis {
            v: 1,
            chain_id: hex(&id),
            legacy_through: through,
            legacy_rows: rows,
            legacy_digest: digest,
            at: chrono::Utc::now().to_rfc3339(),
        };
        append(&tx, 0, &genesis)?;
        tx.pragma_update(None, "user_version", 1).map_err(audit)?;
    }
    tx.commit().map_err(audit)
}

/// The raw columns of every row up to `through`, in id order, as JSON
/// lines, hashed: how many rows, and their digest.
fn legacy_digest(conn: &Connection, through: i64) -> Result<(i64, String)> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {} FROM events WHERE id <= ?1 ORDER BY id",
            super::sqlite_sink::COLUMNS
        ))
        .map_err(audit)?;
    let mut rows = stmt.query([through]).map_err(audit)?;
    let mut h = Sha256::new();
    let mut n = 0;
    while let Some(row) = rows.next().map_err(audit)? {
        let values: Vec<serde_json::Value> = (0..11)
            .map(|i| match row.get_ref(i) {
                Ok(rusqlite::types::ValueRef::Integer(v)) => v.into(),
                Ok(rusqlite::types::ValueRef::Text(t)) => {
                    String::from_utf8_lossy(t).into_owned().into()
                }
                Ok(rusqlite::types::ValueRef::Real(f)) => f.into(),
                Ok(rusqlite::types::ValueRef::Blob(b)) => hex(b).into(),
                _ => serde_json::Value::Null,
            })
            .collect();
        h.update(serde_json::to_string(&values).map_err(audit)?.as_bytes());
        h.update(b"\n");
        n += 1;
    }
    Ok((n, hex(&h.finalize())))
}

/// What the chain says one `events` row should hold.
#[derive(Default)]
struct Expected {
    pending: Option<Record>,
    decision: Option<String>,
    via_event: Option<i64>,
    outcome: Option<(String, String)>,
}

/// Check the chain and the table against it. Read-only.
pub(crate) fn verify(conn: &Connection) -> Result<ChainReport> {
    let mut report = ChainReport::default();

    // Pass 1: the links, in order.
    let mut stmt = conn
        .prepare("SELECT seq, event_id, record, hash FROM chain ORDER BY seq")
        .map_err(audit)?;
    let mut exists = conn
        .prepare("SELECT EXISTS (SELECT 1 FROM events WHERE id = ?1)")
        .map_err(audit)?;
    let mut rows = stmt.query([]).map_err(audit)?;
    let mut prev = ZERO.to_string();
    let mut expected_seq = 1;
    let mut legacy: Option<(i64, i64, String)> = None;
    while let Some(row) = rows.next().map_err(audit)? {
        let (seq, event, text, hash): (i64, i64, String, String) = (
            row.get(0).map_err(audit)?,
            row.get(1).map_err(audit)?,
            row.get(2).map_err(audit)?,
            row.get(3).map_err(audit)?,
        );
        let at = format!("chain broken at record {seq} (event {event})");
        if seq != expected_seq {
            problem(
                &mut report,
                format!("{at}: record {expected_seq} is missing"),
            );
            return Ok(report);
        }
        if link(&prev, seq, &text) != hash {
            problem(&mut report, format!("{at}: its hash does not match"));
            return Ok(report);
        }
        let record: Record = match serde_json::from_str(&text) {
            Ok(r) => r,
            Err(_) => {
                problem(&mut report, format!("{at}: the record is not readable"));
                return Ok(report);
            }
        };
        match (&record, seq) {
            (
                Record::Genesis {
                    legacy_through,
                    legacy_rows,
                    legacy_digest,
                    chain_id,
                    ..
                },
                1,
            ) => {
                legacy = Some((*legacy_through, *legacy_rows, legacy_digest.clone()));
                report.chain_id = Some(chain_id.clone());
            }
            (Record::Genesis { .. }, _) | (_, 1) => {
                problem(
                    &mut report,
                    format!("{at}: genesis must be first, and only first"),
                );
                return Ok(report);
            }
            (Record::Pending { event: e, .. }, _) => {
                let present: bool = exists.query_row([e], |r| r.get(0)).map_err(audit)?;
                if !present {
                    problem(&mut report, format!("event {e} was deleted"));
                }
            }
            _ => {}
        }
        prev = hash;
        report.records = seq;
        expected_seq += 1;
    }
    let Some((legacy_through, legacy_rows, legacy_digest)) = legacy else {
        problem(&mut report, "the chain has no genesis record".into());
        return Ok(report);
    };
    report.tip = (report.records > 0).then(|| (report.records, prev.clone()));
    report.legacy_rows = legacy_rows;
    if self::legacy_digest(conn, legacy_through)? != (legacy_rows, legacy_digest) {
        problem(
            &mut report,
            format!("rows written before the chain started (up to event {legacy_through}) changed"),
        );
    }

    // Pass 2: every row after the legacy ones against its records.
    let mut events = conn
        .prepare(&format!(
            "SELECT {} FROM events WHERE id > ?1 ORDER BY id",
            super::sqlite_sink::COLUMNS
        ))
        .map_err(audit)?;
    let mut records = conn
        .prepare("SELECT record FROM chain WHERE event_id = ?1 ORDER BY seq")
        .map_err(audit)?;
    let mut rows = events.query([legacy_through]).map_err(audit)?;
    while let Some(row) = rows.next().map_err(audit)? {
        let id: i64 = row.get(0).map_err(audit)?;
        let mut want = Expected::default();
        let texts = records
            .query_map([id], |r| r.get::<_, String>(0))
            .map_err(audit)?;
        for text in texts {
            match serde_json::from_str::<Record>(&text.map_err(audit)?).map_err(audit)? {
                r @ Record::Pending { .. } => want.pending = Some(r),
                Record::Decision { decision, .. } => want.decision = Some(decision),
                Record::Windowed { via_event, .. } => {
                    want.decision = Some(crate::audit::AuditDecision::Windowed.as_str().into());
                    want.via_event = Some(via_event);
                }
                Record::Outcome {
                    outcome_kind,
                    outcome_data,
                    ..
                } => want.outcome = Some((outcome_kind, outcome_data)),
                Record::Genesis { .. } => {}
            }
        }
        let Some(Record::Pending {
            at,
            preset,
            action,
            summary,
            client,
            session,
            ..
        }) = want.pending
        else {
            problem(&mut report, format!("event {id} is not in the chain"));
            continue;
        };
        let get = |i: usize| -> Option<String> { row.get::<_, Option<String>>(i).ok().flatten() };
        let (outcome_kind, outcome_data) = want.outcome.unzip();
        let fields: [(&str, Option<String>, Option<String>); 9] = [
            ("created_at", Some(at), get(1)),
            ("preset", Some(preset), get(2)),
            ("action", Some(action), get(3)),
            ("summary", Some(summary), get(4)),
            ("decision", want.decision, get(5)),
            ("outcome_kind", outcome_kind, get(6)),
            ("outcome_data", outcome_data, get(7)),
            ("client", client, get(8)),
            ("session", session, get(9)),
        ];
        for (field, chain, table) in fields {
            if chain != table {
                problem(
                    &mut report,
                    format!(
                        "event {id} changed after it was recorded: {field} (chain: {}, table: {})",
                        shown(chain.as_deref()),
                        shown(table.as_deref())
                    ),
                );
            }
        }
        let via: Option<i64> = row.get(10).ok().flatten();
        if via != want.via_event {
            problem(
                &mut report,
                format!("event {id} changed after it was recorded: via_event"),
            );
        }
    }
    Ok(report)
}

fn problem(report: &mut ChainReport, text: String) {
    if report.problems.len() < MAX_PROBLEMS {
        report.problems.push(text);
    } else {
        report.more_problems = true;
    }
}

/// A value in a problem line: quoted, escaped, at most 60 characters.
fn shown(v: Option<&str>) -> String {
    match v {
        Some(v) => format!("{:?}", crate::audit::clip(v, 60)),
        None => "none".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::sqlite_sink::LocalSqlite;
    use crate::audit::{AuditDecision, AuditOutcome, AuditSink};

    fn sink(dir: &std::path::Path) -> LocalSqlite {
        LocalSqlite::open(&dir.join("audit.db")).unwrap()
    }

    /// A connection of its own, as `sqlite3` would be, with the triggers
    /// dropped as an attacker would.
    fn raw(dir: &std::path::Path) -> Connection {
        let c = Connection::open(dir.join("audit.db")).unwrap();
        c.execute_batch(
            "DROP TRIGGER chain_no_update; DROP TRIGGER chain_no_delete; \
             DROP TRIGGER events_no_delete;",
        )
        .unwrap();
        c
    }

    /// Two calls, as the executor records them.
    fn two_calls(s: &LocalSqlite) {
        let a = s
            .record_pending("gh", "proxy_http", "GET https://api.github.com/user")
            .unwrap();
        s.record_decision(a, AuditDecision::Approved).unwrap();
        s.record_outcome(a, AuditOutcome::Ok { status: 200 })
            .unwrap();
        let b = s
            .record_pending("gh", "proxy_http", "GET https://api.github.com/user")
            .unwrap();
        s.record_windowed(b, a).unwrap();
        s.record_outcome(
            b,
            AuditOutcome::Err {
                message: "boom".into(),
            },
        )
        .unwrap();
    }

    fn problems(s: &LocalSqlite) -> Vec<String> {
        s.verify_chain().unwrap().problems
    }

    #[test]
    fn every_write_is_one_linked_record() {
        let dir = tempfile::tempdir().unwrap();
        let s = sink(dir.path());
        two_calls(&s);
        let report = s.verify_chain().unwrap();
        assert!(report.intact(), "{:?}", report.problems);
        assert_eq!(report.records, 1 + 6);
        assert_eq!(report.legacy_rows, 0);
        assert_eq!(s.chain_tip().unwrap(), report.tip);
        assert_eq!(
            s.chain_hash_at(7).unwrap(),
            report.tip.as_ref().map(|t| t.1.clone())
        );
        // An update of an event that does not exist is an error, and adds
        // nothing to the chain.
        assert!(s.record_decision(999, AuditDecision::Denied).is_err());
        assert_eq!(s.verify_chain().unwrap().records, 7);
    }

    /// Several processes write one file: the chain stays one line.
    #[test]
    fn writers_in_parallel_make_one_chain() {
        let dir = tempfile::tempdir().unwrap();
        sink(dir.path());
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let path = dir.path().to_path_buf();
                std::thread::spawn(move || {
                    let s = sink(&path);
                    for _ in 0..10 {
                        two_calls(&s);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let report = sink(dir.path()).verify_chain().unwrap();
        assert!(report.intact(), "{:?}", report.problems);
        assert_eq!(report.records, 1 + 4 * 10 * 6);
    }

    #[test]
    fn the_triggers_refuse_rewrites() {
        let dir = tempfile::tempdir().unwrap();
        let s = sink(dir.path());
        two_calls(&s);
        let c = Connection::open(dir.path().join("audit.db")).unwrap();
        for sql in [
            "UPDATE chain SET record = 'x' WHERE seq = 2",
            "DELETE FROM chain WHERE seq = 2",
            "DELETE FROM events WHERE id = 1",
        ] {
            let err = c.execute_batch(sql).unwrap_err().to_string();
            assert!(err.contains("append-only"), "{sql}: {err}");
        }
    }

    /// Each kind of tampering is named.
    #[test]
    fn verify_names_every_kind_of_tampering() {
        let cases: &[(&str, &str)] = &[
            (
                "UPDATE events SET decision = 'auto' WHERE id = 1",
                "event 1 changed after it was recorded: decision",
            ),
            (
                "UPDATE events SET summary = 'GET /harmless' WHERE id = 2",
                "event 2 changed after it was recorded: summary",
            ),
            (
                "UPDATE events SET outcome_data = '200' WHERE id = 2",
                "outcome",
            ),
            (
                "UPDATE events SET via_event = NULL WHERE id = 2",
                "via_event",
            ),
            (
                "UPDATE chain SET record = replace(record, 'approved', 'denied') WHERE seq = 3",
                "chain broken at record 3 (event 1): its hash does not match",
            ),
            ("DELETE FROM chain WHERE seq = 4", "record 4 is missing"),
            ("DELETE FROM events WHERE id = 1", "event 1 was deleted"),
            (
                "INSERT INTO events (created_at, preset, action, summary) VALUES ('2026-01-01T00:00:00+00:00', 'x', 'proxy_http', 'forged')",
                "event 3 is not in the chain",
            ),
        ];
        for (sql, want) in cases {
            let dir = tempfile::tempdir().unwrap();
            let s = sink(dir.path());
            two_calls(&s);
            raw(dir.path()).execute_batch(sql).unwrap();
            let found = problems(&s);
            assert!(found.iter().any(|p| p.contains(want)), "{sql}: {found:?}");
        }
    }

    /// A record rewritten with its hash recomputed, so only the content is
    /// wrong: reported, not a panic.
    #[test]
    fn an_unreadable_record_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let s = sink(dir.path());
        two_calls(&s);
        let c = raw(dir.path());
        let prev: String = c
            .query_row("SELECT hash FROM chain WHERE seq = 1", [], |r| r.get(0))
            .unwrap();
        let text = "{not json";
        c.execute(
            "UPDATE chain SET record = ?1, hash = ?2 WHERE seq = 2",
            rusqlite::params![text, link(&prev, 2, text)],
        )
        .unwrap();
        let found = problems(&s);
        assert_eq!(
            found,
            ["chain broken at record 2 (event 1): the record is not readable"]
        );
    }

    /// The limit of a chain on its own: whoever can write the file can cut
    /// off its end, and the chain still holds. The keychain anchor is what
    /// catches that.
    #[test]
    fn a_cut_tail_is_invisible_without_the_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let s = sink(dir.path());
        two_calls(&s);
        let c = raw(dir.path());
        c.execute_batch("DELETE FROM chain WHERE event_id = 2; DELETE FROM events WHERE id = 2;")
            .unwrap();
        assert!(s.verify_chain().unwrap().intact());
    }

    /// A database written by 0.5.4: its rows are kept, marked as written
    /// before the chain, and any later change to them shows.
    #[test]
    fn a_database_from_before_the_chain_is_migrated_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
                    preset TEXT NOT NULL, action TEXT NOT NULL, summary TEXT NOT NULL,
                    decision TEXT, outcome_kind TEXT, outcome_data TEXT,
                    client TEXT, session TEXT, via_event INTEGER);
                 INSERT INTO events (created_at, preset, action, summary, decision)
                    VALUES ('2026-10-01T00:00:00+00:00', 'gh', 'proxy_http', 'GET /a', 'approved'),
                           ('2026-10-02T00:00:00+00:00', 'gh', 'proxy_http', 'GET /b', 'denied');",
            )
            .unwrap();
        }
        // Two processes open it at once: one genesis.
        let opens: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || LocalSqlite::open(&path).map(drop))
            })
            .collect();
        for o in opens {
            o.join().unwrap().unwrap();
        }
        let s = LocalSqlite::open(&path).unwrap();
        two_calls(&s);
        let report = s.verify_chain().unwrap();
        assert!(report.intact(), "{:?}", report.problems);
        assert_eq!(report.legacy_rows, 2);
        assert_eq!(report.records, 1 + 6);
        let genesis: i64 = Connection::open(&path)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM chain WHERE record LIKE '{\"kind\":\"genesis\"%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(genesis, 1);
        raw(dir.path())
            .execute_batch("UPDATE events SET decision = 'auto' WHERE id = 2")
            .unwrap();
        let found = problems(&s);
        assert!(
            found.iter().any(|p| p.contains("before the chain started")),
            "{found:?}"
        );
    }
}
