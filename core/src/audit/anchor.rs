//! The audit chain's anchor: how far the chain reached, kept in the
//! keychain, outside the SQLite file (docs/design/audit-hash-chain.md).
//!
//! A chain can be recomputed by anyone who can edit `audit.db`. The anchor
//! remembers a record's sequence number and hash, so a rewrite of the
//! history up to it, a rollback to an older copy or a replaced database
//! shows. It moves forward only when the record it names still has the
//! hash it names and the links from there to the tip hold: a rewritten log
//! is never blessed by moving the anchor onto it.

use crate::audit::AuditSink;
use crate::error::{Result, WardenError};
use crate::fslock::FileLock;
use crate::keychain::KeychainStore;
use crate::secret::Secret;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// The lock file moves of the anchor take, under the config dir's `locks/`.
const LOCK_NAME: &str = "audit-anchor.lock";

/// What the anchor records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    pub seq: i64,
    pub hash: String,
    pub chain_id: String,
    pub at: String,
}

impl Anchor {
    fn encode(&self) -> String {
        format!(
            "v1 seq={} hash={} chain={} at={}",
            self.seq, self.hash, self.chain_id, self.at
        )
    }

    fn decode(text: &str) -> Option<Self> {
        let mut parts = text.split(' ');
        if parts.next()? != "v1" {
            return None;
        }
        let mut field = |name: &str| {
            parts
                .next()?
                .strip_prefix(name)?
                .strip_prefix('=')
                .map(str::to_string)
        };
        let anchor = Anchor {
            seq: field("seq")?.parse().ok()?,
            hash: field("hash")?,
            chain_id: field("chain")?,
            at: field("at")?,
        };
        let hex = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit());
        (anchor.seq > 0 && hex(&anchor.hash, 64) && hex(&anchor.chain_id, 32)).then_some(anchor)
    }
}

/// The keychain entry for the database at `db`: by path, not by chain id,
/// so a database deleted and started afresh is checked against the old
/// anchor instead of looking like one never anchored.
pub fn entry_name(db: &Path) -> String {
    let digest = Sha256::digest(canonical(db).to_string_lossy().as_bytes());
    let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("audit/anchor/{hex}")
}

/// `db` with its directory resolved, whether or not the file exists.
fn canonical(db: &Path) -> PathBuf {
    match (db.parent(), db.file_name()) {
        (Some(dir), Some(name)) if !dir.as_os_str().is_empty() => std::fs::canonicalize(dir)
            .map(|d| d.join(name))
            .unwrap_or_else(|_| db.to_path_buf()),
        _ => db.to_path_buf(),
    }
}

/// The anchor for `db`, if there is one. A value that does not parse is an
/// error, never "no anchor": that would let an edited keychain entry pass.
pub fn read(kc: &dyn KeychainStore, db: &Path) -> Result<Option<Anchor>> {
    match kc.get(&entry_name(db))? {
        None => Ok(None),
        Some(value) => Anchor::decode(value.expose()).map(Some).ok_or_else(|| {
            WardenError::Audit("the audit anchor in the keychain is malformed".into())
        }),
    }
}

/// What [`advance`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Advance {
    /// The anchor now names the tip.
    Moved { to: i64 },
    /// It already named the tip.
    Unchanged,
    /// Another process was moving it.
    Busy,
    /// The anchored record no longer matches: the log was rewritten, cut or
    /// replaced. The anchor stays where it was.
    Refused(String),
}

/// Move the anchor for `db` to the chain's tip, if the anchored record
/// still holds. `locks` is the directory for the lock file that keeps
/// processes from racing (the config dir's `locks/`); `None` in tests.
pub fn advance(
    kc: &dyn KeychainStore,
    sink: &dyn AuditSink,
    db: &Path,
    locks: Option<&Path>,
) -> Result<Advance> {
    let _lock = match locks {
        Some(dir) => match FileLock::try_acquire(dir, LOCK_NAME)? {
            Some(lock) => Some(lock),
            None => return Ok(Advance::Busy),
        },
        None => None,
    };
    let Some((tip_seq, tip_hash)) = sink.chain_tip()? else {
        return Ok(Advance::Unchanged);
    };
    let current = read(kc, db)?;
    if let Some(a) = &current {
        if a.seq == tip_seq && a.hash == tip_hash {
            return Ok(Advance::Unchanged);
        }
        if a.seq > tip_seq || !sink.chain_links_from(a.seq, &a.hash)? {
            let why = format!(
                "the audit log no longer matches its anchor at record {}: it was rewritten, cut \
                 short or replaced; the anchor stays at record {} (run `mcp-warden audit verify`)",
                a.seq, a.seq
            );
            tracing::error!("{why}");
            return Ok(Advance::Refused(why));
        }
    }
    let anchor = Anchor {
        seq: tip_seq,
        hash: tip_hash,
        chain_id: sink.chain_id()?.unwrap_or_default(),
        at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    };
    kc.set(&entry_name(db), Secret::new(anchor.encode()))?;
    Ok(Advance::Moved { to: tip_seq })
}

/// What the anchor says about the log, for `audit verify`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorCheck {
    /// No anchor yet: a new install, or the keychain lost it (Linux
    /// keyutils entries may not survive a reboot).
    NotAnchored,
    /// The anchored record matches; `later` records after it are covered by
    /// the chain alone.
    Anchored { seq: i64, later: i64 },
    /// The log ends before the anchored record: records were removed, or
    /// the log was replaced.
    Removed { seq: i64 },
    /// The anchored record's hash differs: the history up to it was
    /// rewritten.
    Rewritten { seq: i64 },
}

impl AnchorCheck {
    pub fn holds(&self) -> bool {
        matches!(
            self,
            AnchorCheck::NotAnchored | AnchorCheck::Anchored { .. }
        )
    }
}

/// Compare the log with its anchor. Read-only.
pub fn check(kc: &dyn KeychainStore, sink: &dyn AuditSink, db: &Path) -> Result<AnchorCheck> {
    let Some(a) = read(kc, db)? else {
        return Ok(AnchorCheck::NotAnchored);
    };
    let tip = sink.chain_tip()?.map_or(0, |(seq, _)| seq);
    Ok(match sink.chain_hash_at(a.seq)? {
        None => AnchorCheck::Removed { seq: a.seq },
        Some(h) if h != a.hash => AnchorCheck::Rewritten { seq: a.seq },
        Some(_) => AnchorCheck::Anchored {
            seq: a.seq,
            later: tip - a.seq,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::sqlite_sink::LocalSqlite;
    use crate::audit::{AuditDecision, AuditOutcome};
    use crate::keychain::memory::InMemoryKeychain;
    use rusqlite::Connection;

    fn calls(s: &LocalSqlite, n: usize) {
        for _ in 0..n {
            let id = s.record_pending("gh", "proxy_http", "GET /user").unwrap();
            s.record_decision(id, AuditDecision::Approved).unwrap();
            s.record_outcome(id, AuditOutcome::Ok { status: 200 })
                .unwrap();
        }
    }

    #[test]
    fn it_moves_to_the_tip_and_reports_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("audit.db");
        let s = LocalSqlite::open(&db).unwrap();
        let kc = InMemoryKeychain::new();
        assert_eq!(check(&kc, &s, &db).unwrap(), AnchorCheck::NotAnchored);
        calls(&s, 2);
        assert_eq!(
            advance(&kc, &s, &db, None).unwrap(),
            Advance::Moved { to: 7 }
        );
        assert_eq!(advance(&kc, &s, &db, None).unwrap(), Advance::Unchanged);
        calls(&s, 1);
        assert_eq!(
            check(&kc, &s, &db).unwrap(),
            AnchorCheck::Anchored { seq: 7, later: 3 }
        );
        let a = read(&kc, &db).unwrap().unwrap();
        assert_eq!(a.seq, 7);
        assert_eq!(Some(a.chain_id), s.chain_id().unwrap());
        assert!(entry_name(&db).starts_with("audit/anchor/"));
    }

    /// Rewrite the log, recompute the whole chain so it verifies, then try
    /// to make the anchor follow: refused, and the anchor stays.
    #[test]
    fn a_laundered_log_does_not_move_the_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("audit.db");
        let s = LocalSqlite::open(&db).unwrap();
        let kc = InMemoryKeychain::new();
        calls(&s, 2);
        advance(&kc, &s, &db, None).unwrap();
        let before = read(&kc, &db).unwrap();

        let c = Connection::open(&db).unwrap();
        c.execute_batch(
            "DROP TRIGGER chain_no_update; \
             UPDATE events SET decision = 'auto' WHERE id = 1; \
             UPDATE chain SET record = replace(record, '\"approved\"', '\"auto\"') WHERE seq = 3;",
        )
        .unwrap();
        let rows: Vec<(i64, String)> = c
            .prepare("SELECT seq, record FROM chain ORDER BY seq")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        let mut prev = crate::audit::chain::ZERO.to_string();
        for (seq, record) in rows {
            let hash = crate::audit::chain::link(&prev, seq, &record);
            c.execute(
                "UPDATE chain SET hash = ?1 WHERE seq = ?2",
                rusqlite::params![hash, seq],
            )
            .unwrap();
            prev = hash;
        }
        assert!(
            s.verify_chain().unwrap().intact(),
            "the forgery verifies on its own"
        );
        calls(&s, 1);

        assert!(matches!(
            advance(&kc, &s, &db, None).unwrap(),
            Advance::Refused(_)
        ));
        assert_eq!(read(&kc, &db).unwrap(), before);
        assert_eq!(
            check(&kc, &s, &db).unwrap(),
            AnchorCheck::Rewritten { seq: 7 }
        );
    }

    #[test]
    fn a_rolled_back_or_deleted_log_is_caught() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("audit.db");
        let kc = InMemoryKeychain::new();
        {
            let s = LocalSqlite::open(&db).unwrap();
            calls(&s, 1);
        }
        std::fs::copy(&db, dir.path().join("old.db")).unwrap();
        {
            let s = LocalSqlite::open(&db).unwrap();
            calls(&s, 2);
            advance(&kc, &s, &db, None).unwrap();
        }
        // An older copy put back.
        std::fs::copy(dir.path().join("old.db"), &db).unwrap();
        let s = LocalSqlite::open(&db).unwrap();
        assert_eq!(
            check(&kc, &s, &db).unwrap(),
            AnchorCheck::Removed { seq: 10 }
        );
        assert!(matches!(
            advance(&kc, &s, &db, None).unwrap(),
            Advance::Refused(_)
        ));
        drop(s);
        // Deleted and started afresh.
        std::fs::remove_file(&db).unwrap();
        let s = LocalSqlite::open(&db).unwrap();
        calls(&s, 5);
        assert!(!check(&kc, &s, &db).unwrap().holds());
    }

    /// Processes racing to move it: it never goes backwards.
    #[test]
    fn racing_movers_never_move_it_back() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("audit.db");
        let locks = dir.path().join("locks");
        LocalSqlite::open(&db).unwrap();
        let kc = std::sync::Arc::new(InMemoryKeychain::new());
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let (db, locks, kc) = (db.clone(), locks.clone(), kc.clone());
                std::thread::spawn(move || {
                    let s = LocalSqlite::open(&db).unwrap();
                    let mut last = 0;
                    for _ in 0..10 {
                        calls(&s, 1);
                        advance(kc.as_ref(), &s, &db, Some(&locks)).unwrap();
                        if let Some(a) = read(kc.as_ref(), &db).unwrap() {
                            assert!(a.seq >= last, "{} after {last}", a.seq);
                            last = a.seq;
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let s = LocalSqlite::open(&db).unwrap();
        advance(kc.as_ref(), &s, &db, Some(&locks)).unwrap();
        assert!(check(kc.as_ref(), &s, &db).unwrap().holds());
    }

    #[test]
    fn a_malformed_anchor_is_an_error_not_a_pass() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("audit.db");
        let s = LocalSqlite::open(&db).unwrap();
        let kc = InMemoryKeychain::new();
        for bad in [
            "",
            "v1",
            "v2 seq=1 hash=x chain=y at=z",
            "v1 seq=-1 hash=00 chain=00 at=x",
        ] {
            kc.set(&entry_name(&db), Secret::new(bad.into())).unwrap();
            assert!(check(&kc, &s, &db).is_err(), "{bad:?}");
            assert!(advance(&kc, &s, &db, None).is_err(), "{bad:?}");
        }
    }
}
