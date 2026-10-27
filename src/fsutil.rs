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
    let result = opts.open(&tmp).and_then(|mut f| {
        f.write_all(bytes)?;
        if let Some(perms) = perms {
            f.set_permissions(perms)?;
        }
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    });
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

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
