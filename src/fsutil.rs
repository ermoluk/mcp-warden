//! Replacing a file atomically without trusting the directory it sits in.

use std::io::Write;
use std::path::Path;

/// Write `bytes` to a fresh temp file next to `path`, then rename it over
/// `path`.
///
/// The temp file has an unpredictable name and is created with `O_EXCL`
/// (`create_new`), mode 0600 and `O_NOFOLLOW`, so a file or symlink planted
/// in the directory is never followed or overwritten, and the contents are
/// never readable by others before `perms` (if given) is applied. `rename`
/// replaces `path` itself, even when `path` is a symlink.
pub(crate) fn replace_atomic(
    path: &Path,
    bytes: &[u8],
    perms: Option<std::fs::Permissions>,
) -> std::io::Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let tmp = dir.join(format!(
        ".{name}.{}.{nonce}.mcp-warden-tmp",
        std::process::id()
    ));

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let result = opts
        .open(&tmp)
        .and_then(|mut f| {
            f.write_all(bytes)?;
            if let Some(perms) = perms {
                f.set_permissions(perms)?;
            }
            f.sync_all()
            // `f` closes here: Windows won't rename a file that is still open.
        })
        .and_then(|()| std::fs::rename(&tmp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Create the config dir private to the user (0700), and refuse one that
/// other users can write to: whoever can write it decides which presets
/// and wrapped servers run, and can plant files where the server reads its
/// state.
pub(crate) fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(dir)?;
        // SAFETY: geteuid takes no arguments and cannot fail.
        let me = unsafe { libc::geteuid() };
        if meta.uid() != me || meta.mode() & 0o022 != 0 {
            return Err(std::io::Error::other(format!(
                "config dir {} is writable by other users or not owned by you; \
                 run `chmod 700 {}` (and check its owner)",
                dir.display(),
                dir.display()
            )));
        }
    }
    Ok(())
}

/// Read a small state file from the config dir — `lock`, the Telegram
/// offset and inbox — as text, refusing anything that is not a regular file
/// of at most `max` bytes. It is opened with `O_NOFOLLOW` (a symlink to
/// `/dev/zero` is refused, not read forever) and `O_NONBLOCK` (a FIFO is
/// refused, not waited on).
pub(crate) fn read_small_nofollow(path: &Path, max: u64) -> std::io::Result<String> {
    use std::io::Read;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = opts.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > max {
        return Err(std::io::Error::other(format!(
            "{} is not a regular file of at most {max} bytes",
            path.display()
        )));
    }
    let mut text = String::new();
    file.take(max + 1).read_to_string(&mut text)?;
    if text.len() as u64 > max {
        return Err(std::io::Error::other(format!(
            "{} grew past {max} bytes",
            path.display()
        )));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run `f` on a thread and give up after a few seconds, so a read that
    /// would block or never end fails the test instead of hanging it.
    fn within_seconds<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("the read blocked or never ended")
    }

    /// The state files in the config dir (`lock`, `telegram/offset`, the
    /// Telegram inbox) are small. Whatever an agent puts in their place — a
    /// symlink to /dev/zero, a FIFO, a huge file — must not block or
    /// exhaust memory.
    #[cfg(unix)]
    #[test]
    fn small_state_files_are_read_without_following_or_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let ok = dir.path().join("offset");
        std::fs::write(&ok, "42").unwrap();
        assert_eq!(read_small_nofollow(&ok, 64).unwrap(), "42");

        let zero = dir.path().join("zero");
        std::os::unix::fs::symlink("/dev/zero", &zero).unwrap();
        assert!(within_seconds(move || read_small_nofollow(&zero, 64)).is_err());

        let fifo = dir.path().join("fifo");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(within_seconds(move || read_small_nofollow(&fifo, 64)).is_err());

        let big = dir.path().join("big");
        std::fs::write(&big, vec![b'1'; 1000]).unwrap();
        assert!(read_small_nofollow(&big, 64).is_err());
    }

    /// The config dir decides which presets run: created private, and
    /// refused when other users can write to it.
    #[cfg(unix)]
    #[test]
    fn the_config_dir_is_private_and_not_writable_by_others() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let fresh = tmp.path().join("new/mcp-warden");
        ensure_private_dir(&fresh).unwrap();
        let mode = std::fs::metadata(&fresh).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);

        let open = tmp.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = ensure_private_dir(&open).unwrap_err().to_string();
        assert!(err.contains("writable by other users"), "{err}");
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(ensure_private_dir(&open).is_err());
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&open).unwrap();
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".mcp-warden-tmp"))
            .collect()
    }

    #[test]
    fn replaces_contents_and_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, "old").unwrap();
        replace_atomic(&path, b"new", None).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        assert!(leftovers(dir.path()).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn new_file_is_private_and_given_permissions_apply() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("lock");
        replace_atomic(&private, b"x", None).unwrap();
        let mode = std::fs::metadata(&private).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let shared = dir.path().join("mcp.json");
        replace_atomic(&shared, b"x", Some(std::fs::Permissions::from_mode(0o640))).unwrap();
        let mode = std::fs::metadata(&shared).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o640);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_destination_is_replaced_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "keep me").unwrap();
        let path = dir.path().join("config.json");
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        replace_atomic(&path, b"new", None).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep me");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }
}
