//! What the operating system says, as opposed to what the environment says.
//!
//! Whoever starts an mcp-warden process chooses its environment — an agent
//! that runs the CLI (`HOME=/Users mcp-warden mcp`), or that edits the
//! `"env"` of an MCP client config. So `HOME`, `PATH`, `SystemRoot` and the
//! like are the caller's, not facts about the machine. Security decisions
//! take these values from the OS instead (audit 2026-11-09, H1, H2, H4).

use std::path::PathBuf;

/// The user's home directory from the account database — `getpwuid_r` on
/// Unix, the Profile known folder on Windows — never from `$HOME`.
pub fn account_home() -> Option<PathBuf> {
    imp::account_home()
}

/// Windows' `System32` directory, from the System known folder — never
/// from `SystemRoot` / `windir`.
#[cfg(windows)]
pub fn system_dir() -> Option<PathBuf> {
    dirs_sys::known_folder(windows_sys::Win32::UI::Shell::FOLDERID_System)
}

/// The Windows directory, from the Windows known folder — never from
/// `SystemRoot` / `windir`.
#[cfg(windows)]
pub fn windows_dir() -> Option<PathBuf> {
    dirs_sys::known_folder(windows_sys::Win32::UI::Shell::FOLDERID_Windows)
}

/// The Program Files directory, from its known folder — never from
/// `ProgramFiles`.
#[cfg(windows)]
pub fn program_files_dir() -> Option<PathBuf> {
    dirs_sys::known_folder(windows_sys::Win32::UI::Shell::FOLDERID_ProgramFiles)
}

#[cfg(unix)]
mod imp {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    pub fn account_home() -> Option<PathBuf> {
        // SAFETY: sysconf has no preconditions.
        let mut size = match unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) } {
            n if n > 0 => n as usize,
            _ => 1024,
        };
        loop {
            let mut buf = vec![0 as libc::c_char; size];
            // SAFETY: an all-zero `passwd` is a valid value to be filled in.
            let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
            let mut found: *mut libc::passwd = std::ptr::null_mut();
            // SAFETY: `buf` is `size` bytes and outlives every read of the
            // pointers `getpwuid_r` stores into `pw`, which point into it.
            let rc = unsafe {
                libc::getpwuid_r(
                    libc::getuid(),
                    &mut pw,
                    buf.as_mut_ptr(),
                    buf.len(),
                    &mut found,
                )
            };
            if rc == libc::ERANGE && size < 1 << 20 {
                size *= 2;
                continue;
            }
            if rc != 0 || found.is_null() || pw.pw_dir.is_null() {
                return None;
            }
            // SAFETY: non-null, NUL-terminated, inside `buf`.
            let dir = unsafe { CStr::from_ptr(pw.pw_dir) }.to_bytes();
            return (!dir.is_empty()).then(|| PathBuf::from(OsStr::from_bytes(dir)));
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::path::PathBuf;

    pub fn account_home() -> Option<PathBuf> {
        // `dirs` asks SHGetKnownFolderPath(FOLDERID_Profile) on Windows; it
        // reads no environment variable there.
        dirs::home_dir()
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use std::path::PathBuf;

    pub fn account_home() -> Option<PathBuf> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_account_home_is_an_existing_absolute_directory() {
        let home = account_home().expect("the account has a home directory");
        assert!(home.is_absolute(), "{}", home.display());
        assert!(home.is_dir(), "{}", home.display());
    }

    /// Helper for the test below: runs in a child process with `HOME` set.
    #[test]
    #[ignore = "helper: runs only in the child process the test below starts"]
    fn account_home_child() {
        let Ok(out) = std::env::var("OSENV_OUT") else {
            return;
        };
        let home = account_home().map(|h| h.display().to_string());
        std::fs::write(out, home.unwrap_or_default()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn home_from_the_environment_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("home");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "osenv::tests::account_home_child",
                "--ignored",
                "--test-threads=1",
            ])
            .env("OSENV_OUT", &out)
            .env("HOME", dir.path())
            .output()
            .unwrap();
        assert!(status.status.success());
        let seen = std::fs::read_to_string(&out).unwrap();
        assert_eq!(seen, account_home().unwrap().display().to_string());
        assert_ne!(seen, dir.path().display().to_string());
    }
}
