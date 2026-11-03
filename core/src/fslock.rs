//! Exclusive locks between mcp-warden processes.
//!
//! Every MCP client session runs its own `mcp-warden mcp`, and the CLI runs
//! beside them. When two of them must not do the same thing at once —
//! store a rotated OAuth2 refresh token, move the audit anchor — they take
//! a lock file in `<config dir>/locks/`. The directory is private (0700),
//! the file is created 0600 and never through a symlink, and the lock is
//! the OS's own (`flock` / `LockFileEx`), released when the holder exits,
//! however it exits.

use crate::error::{Result, WardenError};
use std::fs::{File, OpenOptions, TryLockError};
use std::path::Path;
use std::time::{Duration, Instant};

/// An exclusive lock, held until dropped.
#[derive(Debug)]
pub struct FileLock {
    _file: File,
}

impl FileLock {
    /// Take the lock on `<dir>/<name>` now, or `None` if another holder has
    /// it. `name` is a plain file name chosen by mcp-warden.
    pub fn try_acquire(dir: &Path, name: &str) -> Result<Option<Self>> {
        let file = open(dir, name)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(e)) => Err(WardenError::Io(e)),
        }
    }

    /// Take the lock, waiting at most `timeout` for another holder to let
    /// go. Polls, so it never blocks an async runtime for long; call it
    /// from `spawn_blocking` or a CLI.
    pub fn acquire(dir: &Path, name: &str, timeout: Duration) -> Result<Self> {
        let started = Instant::now();
        loop {
            if let Some(lock) = Self::try_acquire(dir, name)? {
                return Ok(lock);
            }
            if started.elapsed() >= timeout {
                return Err(WardenError::Executor(format!(
                    "another mcp-warden process held the lock '{name}' for more than {} s",
                    timeout.as_secs()
                )));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn open(dir: &Path, name: &str) -> Result<File> {
    if name.is_empty() || name.contains(['/', '\\']) || name.starts_with('.') {
        return Err(WardenError::Validation(format!("bad lock name '{name}'")));
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir).map_err(WardenError::Io)?;
    let meta = std::fs::symlink_metadata(dir).map_err(WardenError::Io)?;
    if !meta.is_dir() {
        return Err(WardenError::Validation(format!(
            "lock directory {} is not a directory",
            dir.display()
        )));
    }
    let path = dir.join(name);
    // On Windows, which has no O_NOFOLLOW, refuse a link planted there.
    if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(WardenError::Validation(format!(
            "lock file {} is a symlink",
            path.display()
        )));
    }
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(&path).map_err(WardenError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_holder_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let locks = dir.path().join("locks");
        let held = FileLock::try_acquire(&locks, "x.lock").unwrap().unwrap();
        // A second open file description of the same file: what another
        // process would have.
        assert!(FileLock::try_acquire(&locks, "x.lock").unwrap().is_none());
        assert!(FileLock::try_acquire(&locks, "y.lock").unwrap().is_some());
        let started = Instant::now();
        assert!(FileLock::acquire(&locks, "x.lock", Duration::from_millis(100)).is_err());
        assert!(started.elapsed() >= Duration::from_millis(100));
        drop(held);
        FileLock::acquire(&locks, "x.lock", Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn a_waiter_gets_the_lock_once_it_is_released() {
        let dir = tempfile::tempdir().unwrap();
        let locks = dir.path().join("locks");
        let held = FileLock::try_acquire(&locks, "x.lock").unwrap().unwrap();
        let path = locks.clone();
        let waiter = std::thread::spawn(move || {
            FileLock::acquire(&path, "x.lock", Duration::from_secs(5)).map(drop)
        });
        std::thread::sleep(Duration::from_millis(100));
        drop(held);
        waiter.join().unwrap().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_lock_path_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let locks = dir.path().join("locks");
        std::fs::create_dir(&locks).unwrap();
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, "").unwrap();
        std::os::unix::fs::symlink(&target, locks.join("x.lock")).unwrap();
        assert!(FileLock::try_acquire(&locks, "x.lock").is_err());
    }

    #[test]
    fn lock_names_are_plain_file_names() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["", "../x", "a/b", ".hidden", "a\\b"] {
            assert!(FileLock::try_acquire(dir.path(), name).is_err(), "{name:?}");
        }
    }
}
