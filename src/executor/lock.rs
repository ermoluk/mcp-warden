//! The kill switch. `mcp-warden lock` writes `<config dir>/lock`; every tool
//! call checks for it first and is refused while it exists.
//!
//! A running server *latches* the lock: once it has seen the file it refuses
//! every call until it restarts, even if the file is deleted by hand (e.g.
//! by an agent running `rm`). `mcp-warden unlock` asks a human before it
//! removes the file, and servers that saw the lock stay locked until they
//! restart.

use chrono::{DateTime, SecondsFormat, Utc};
use mcp_warden_core::error::{Result, WardenError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// Name of the lock file inside the config directory.
pub const LOCK_FILE: &str = "lock";

/// What `mcp-warden lock` records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockInfo {
    pub since: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl LockInfo {
    /// One line for humans: when, and why if a reason was given.
    pub fn describe(&self) -> String {
        let since = self.since.to_rfc3339_opts(SecondsFormat::Secs, true);
        match &self.reason {
            Some(r) => format!("locked since {since}: {r}"),
            None => format!("locked since {since}"),
        }
    }
}

/// True if a lock file (of any content, even unreadable) is present.
pub fn is_present(path: &Path) -> bool {
    path.symlink_metadata().is_ok()
}

/// The lock's details. A file that exists but cannot be parsed still locks;
/// it only loses its description.
pub fn read(path: &Path) -> Option<LockInfo> {
    is_present(path).then(|| {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(LockInfo {
                since: DateTime::<Utc>::UNIX_EPOCH,
                reason: Some("lock file unreadable".into()),
            })
    })
}

/// Write the lock file atomically, readable by the owner only.
pub fn write(path: &Path, info: &LockInfo) -> Result<()> {
    let json = serde_json::to_string(info).map_err(|e| WardenError::Executor(e.to_string()))?;
    let tmp = path.with_extension("tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    {
        use std::io::Write;
        let mut f = opts.open(&tmp).map_err(WardenError::Io)?;
        f.write_all(json.as_bytes()).map_err(WardenError::Io)?;
        f.sync_all().map_err(WardenError::Io)?;
    }
    std::fs::rename(&tmp, path).map_err(WardenError::Io)
}

/// The executor's view of the lock: a path to watch and a latch.
pub struct LockState {
    path: Option<PathBuf>,
    latched: AtomicBool,
}

impl LockState {
    /// Watch `path`.
    pub fn at(path: PathBuf) -> Self {
        Self {
            path: Some(path),
            latched: AtomicBool::new(false),
        }
    }

    /// No lock file to watch (tests and in-process tools).
    pub fn none() -> Self {
        Self {
            path: None,
            latched: AtomicBool::new(false),
        }
    }

    /// True when calls must be refused. Once the file has been seen, this
    /// stays true for the life of the process.
    pub fn is_locked(&self) -> bool {
        if self.latched.load(Ordering::SeqCst) {
            return true;
        }
        let present = self.path.as_deref().is_some_and(is_present);
        if present {
            self.latched.store(true, Ordering::SeqCst);
        }
        present
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latch_survives_deleting_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LOCK_FILE);
        let state = LockState::at(path.clone());
        assert!(!state.is_locked());

        write(
            &path,
            &LockInfo {
                since: Utc::now(),
                reason: None,
            },
        )
        .unwrap();
        assert!(state.is_locked());

        std::fs::remove_file(&path).unwrap();
        assert!(state.is_locked(), "a seen lock must hold until restart");
        assert!(
            !LockState::at(path).is_locked(),
            "a fresh process starts unlocked"
        );
    }

    #[test]
    fn unreadable_lock_file_still_locks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LOCK_FILE);
        std::fs::write(&path, "not json").unwrap();
        assert!(LockState::at(path.clone()).is_locked());
        assert!(read(&path).unwrap().describe().contains("unreadable"));
    }

    #[test]
    fn write_round_trips_and_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LOCK_FILE);
        let info = LockInfo {
            since: Utc::now(),
            reason: Some("agent went rogue".into()),
        };
        write(&path, &info).unwrap();
        let back = read(&path).unwrap();
        assert_eq!(back.reason.as_deref(), Some("agent went rogue"));
        assert!(back.describe().contains("agent went rogue"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn no_path_never_locks() {
        assert!(!LockState::none().is_locked());
    }
}
