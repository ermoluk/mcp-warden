use crate::executor::lock;
use mcp_warden_core::audit::{AuditDecision, AuditSink};
use mcp_warden_core::config::{Config, WrappedServer};
use mcp_warden_core::error::{Result, WardenError};
use mcp_warden_core::keychain::KeychainStore;
use mcp_warden_core::secret::Secret;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

/// `mcp-warden run <name>`: launch the `[[server]]` named `name` with its
/// keys read from the keychain into its environment.
///
/// Whoever runs this chooses its environment and working directory — an
/// agent with a shell, or a client config it edited. So the server gets
/// neither (audit 2026-11-09, H1): its command is looked up in the entry's
/// own `path` (or a fixed default), never the caller's `PATH`; it starts
/// with a cleared environment holding only harmless locale and terminal
/// settings, `HOME`/`PATH` set by mcp-warden, and its keys; and it runs in
/// the account's home directory. The program the command resolved to is
/// part of the confirmation, so a different one asks again.
///
/// **stdout belongs to the launched server** (its JSON-RPC channel), so
/// nothing here prints to stdout; errors go to stderr.
pub async fn run(
    name: &str,
    config_dir: &Path,
    store: std::sync::Arc<dyn KeychainStore>,
    audit: &dyn AuditSink,
) -> Result<()> {
    if lock::is_present(&config_dir.join(lock::LOCK_FILE)) {
        return Err(WardenError::Locked);
    }
    crate::fsutil::ensure_private_dir(config_dir).map_err(WardenError::Io)?;
    let raw = std::fs::read_to_string(config_dir.join("config.toml")).unwrap_or_default();
    let cfg: Config = toml::from_str(&raw).map_err(|e| WardenError::Config(e.to_string()))?;
    cfg.validate_servers()?;
    let server = cfg.find_server(name).ok_or_else(|| {
        WardenError::Validation(format!(
            "no [[server]] named '{name}' in the config; add one with `mcp-warden server add`"
        ))
    })?;
    // Missing keys fail before anyone is asked; the index says which
    // exist without reading a value.
    let stored = store.list_names()?;
    if let Some(entry) = server
        .env
        .iter()
        .map(|var| server.secret_name(var))
        .find(|entry| !stored.contains(entry))
    {
        return Err(WardenError::Validation(format!(
            "server '{}': keychain has no '{entry}'; set it with \
             `mcp-warden secret add {entry}`",
            server.name
        )));
    }
    let program = program(server)?;
    let home = crate::osenv::account_home()
        .ok_or_else(|| WardenError::Executor("cannot find the account's home directory".into()))?;
    // The keys go only to the program a human confirmed: an edit to this
    // entry (another command, more variables, another `path`) or another
    // file behind the same command asks again first.
    let exec = crate::cli::confirm::executor(config_dir, &cfg, store.clone())?;
    crate::cli::confirm::ensure_server_confirmed(&exec, server, &program)
        .await
        .map_err(|e| {
            WardenError::Validation(format!(
                "server '{name}' was not started: launching it needs confirmation ({e})"
            ))
        })?;
    let env = resolve_env(server, store.as_ref())?;

    let id = audit.record_pending(name, "run", &command_line(server, &program))?;
    audit.record_decision(id, AuditDecision::Auto)?;

    let mut cmd = std::process::Command::new(&program);
    cmd.args(&server.args)
        .current_dir(&home)
        .env_clear()
        .envs(base_env(&server_path(server), &home));
    for (var, value) in &env {
        cmd.env(var, value.expose());
    }
    launch(cmd, &program)
}

/// The search path for the server's command, and its `PATH`: the entry's
/// own `path`, or a fixed default.
pub(crate) fn server_path(s: &WrappedServer) -> OsString {
    s.path.clone().map_or_else(default_path, OsString::from)
}

/// The file the server's command runs, resolved in `server_path`.
pub(crate) fn program(s: &WrappedServer) -> Result<PathBuf> {
    resolve_program(&s.command, &server_path(s)).map_err(|e| {
        WardenError::Validation(format!(
            "server '{}': {e}. Give the command as an absolute path, or set \
             `path` in its [[server]] entry (e.g. `mcp-warden server add {} \
             --force --path \"$PATH\" …`)",
            s.name, s.name
        ))
    })
}

/// Find the program `command` names. An absolute path is taken as it is; a
/// bare name is looked up in `path`, absolute directories only. Never the
/// caller's `PATH`, and never a path relative to the current directory —
/// both are the caller's to choose.
fn resolve_program(command: &str, path: &OsStr) -> std::result::Result<PathBuf, String> {
    let as_given = Path::new(command);
    if as_given.is_absolute() {
        return if as_given.is_file() {
            Ok(as_given.to_path_buf())
        } else {
            Err(format!("'{command}' does not exist"))
        };
    }
    if command.is_empty() || as_given.components().count() != 1 || command.contains('/') {
        return Err(format!(
            "'{command}' must be a bare program name or an absolute path"
        ));
    }
    std::env::split_paths(path)
        .filter(|dir| dir.is_absolute())
        .flat_map(|dir| candidates(&dir, command))
        .find(|candidate| is_executable(candidate))
        .ok_or_else(|| format!("'{command}' is not in {}", Path::new(path).display()))
}

#[cfg(unix)]
fn candidates(dir: &Path, name: &str) -> Vec<PathBuf> {
    vec![dir.join(name)]
}

/// Windows runs `npx` as `npx.cmd`: try the usual extensions unless the
/// name has one.
#[cfg(not(unix))]
fn candidates(dir: &Path, name: &str) -> Vec<PathBuf> {
    if Path::new(name).extension().is_some() {
        return vec![dir.join(name)];
    }
    [".exe", ".cmd", ".bat", ".com"]
        .iter()
        .map(|ext| dir.join(format!("{name}{ext}")))
        .collect()
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}

/// The default search path: system locations first, then the per-user
/// install directories of the usual MCP launchers (npx, uvx, cargo, nix).
#[cfg(unix)]
fn default_path() -> OsString {
    let mut dirs: Vec<PathBuf> = [
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
        "/run/current-system/sw/bin",
        "/nix/var/nix/profiles/default/bin",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect();
    if let Some(home) = crate::osenv::account_home() {
        for rel in [".nix-profile/bin", ".local/bin", ".cargo/bin"] {
            dirs.push(home.join(rel));
        }
    }
    std::env::join_paths(dirs).unwrap_or_default()
}

#[cfg(windows)]
fn default_path() -> OsString {
    let mut dirs = Vec::new();
    if let Some(system) = crate::osenv::system_dir() {
        dirs.push(system.join(r"WindowsPowerShell\v1.0"));
        dirs.push(system.join("Wbem"));
        dirs.insert(0, system);
    }
    if let Some(windows) = crate::osenv::windows_dir() {
        dirs.insert(1.min(dirs.len()), windows);
    }
    if let Some(program_files) = crate::osenv::program_files_dir() {
        dirs.push(program_files.join("nodejs"));
    }
    if let Some(roaming) = dirs::data_dir() {
        dirs.push(roaming.join("npm"));
    }
    if let Some(home) = crate::osenv::account_home() {
        dirs.push(home.join(r".local\bin"));
        dirs.push(home.join(r".cargo\bin"));
    }
    std::env::join_paths(dirs).unwrap_or_default()
}

#[cfg(not(any(unix, windows)))]
fn default_path() -> OsString {
    OsString::new()
}

/// Variables passed from the caller unchanged: locale and terminal
/// settings, which make no program load anything.
#[cfg(unix)]
const PASSED_THROUGH: &[&str] = &[
    "USER",
    "LOGNAME",
    "LANG",
    "LANGUAGE",
    "TERM",
    "COLORTERM",
    "NO_COLOR",
    "TZ",
    "TMPDIR",
];

#[cfg(not(unix))]
const PASSED_THROUGH: &[&str] = &[
    "USERNAME",
    "USERDOMAIN",
    "COMPUTERNAME",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "OS",
    "LANG",
    "TERM",
    "TZ",
];

/// The server's environment before its keys are added: `PATH` and the
/// home directory from mcp-warden, the caller's `PASSED_THROUGH` settings
/// (and `LC_*`), nothing else — no `NODE_OPTIONS`, `PYTHONPATH`,
/// `BASH_ENV`, `LD_PRELOAD`, `XDG_*`, proxy or certificate variable.
fn base_env(path: &OsStr, home: &Path) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(k, _)| {
            k.to_str()
                .is_some_and(|k| PASSED_THROUGH.contains(&k) || k.starts_with("LC_"))
        })
        .collect();
    env.push(("PATH".into(), path.to_os_string()));
    env.extend(home_env(home));
    env
}

#[cfg(unix)]
fn home_env(home: &Path) -> Vec<(OsString, OsString)> {
    vec![("HOME".into(), home.into())]
}

/// Windows programs find their profile, app data and system directories
/// through these; each comes from a known folder, not the caller.
#[cfg(windows)]
fn home_env(home: &Path) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = vec![
        ("USERPROFILE".into(), home.into()),
        ("PATHEXT".into(), ".COM;.EXE;.BAT;.CMD".into()),
    ];
    if let Some(windows) = crate::osenv::windows_dir() {
        env.push(("SystemRoot".into(), windows.clone().into()));
        env.push(("windir".into(), windows.into()));
    }
    if let Some(system) = crate::osenv::system_dir() {
        env.push(("ComSpec".into(), system.join("cmd.exe").into()));
    }
    if let Some(program_files) = crate::osenv::program_files_dir() {
        env.push(("ProgramFiles".into(), program_files.into()));
    }
    if let Some(roaming) = dirs::data_dir() {
        env.push(("APPDATA".into(), roaming.into()));
    }
    if let Some(local) = dirs::data_local_dir() {
        env.push(("TEMP".into(), local.join("Temp").into()));
        env.push(("TMP".into(), local.join("Temp").into()));
        env.push(("LOCALAPPDATA".into(), local.into()));
    }
    env
}

#[cfg(not(any(unix, windows)))]
fn home_env(_home: &Path) -> Vec<(OsString, OsString)> {
    Vec::new()
}

/// Read every secret the server needs from its own keychain entries
/// (`server/<name>/<VAR>`), never from entries the config names, so editing
/// the config cannot hand a preset's secret to a command. A missing one
/// fails loudly before anything starts, naming the entry only.
fn resolve_env(server: &WrappedServer, kc: &dyn KeychainStore) -> Result<Vec<(String, Secret)>> {
    server
        .env
        .iter()
        .map(|var| {
            let entry = server.secret_name(var);
            let value = kc.get(&entry)?.ok_or_else(|| {
                WardenError::Validation(format!(
                    "server '{}': keychain has no '{entry}'; set it with \
                     `mcp-warden secret add {entry}`",
                    server.name
                ))
            })?;
            Ok((var.clone(), value))
        })
        .collect()
}

/// What the audit log shows for a launch: the program and its arguments,
/// never the env.
fn command_line(server: &WrappedServer, program: &Path) -> String {
    std::iter::once(program.display().to_string())
        .chain(server.args.iter().cloned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Replace this process with the server, so stdio and signals reach it
/// directly. Returns only if the exec failed.
#[cfg(unix)]
fn launch(mut cmd: std::process::Command, program: &Path) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let err = cmd.exec();
    Err(WardenError::Executor(format!(
        "could not start '{}': {err}",
        program.display()
    )))
}

/// No exec on this platform: run the server as a child with inherited
/// stdio and exit with its status.
#[cfg(not(unix))]
fn launch(mut cmd: std::process::Command, program: &Path) -> Result<()> {
    let status = cmd.status().map_err(|e| {
        WardenError::Executor(format!("could not start '{}': {e}", program.display()))
    })?;
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_warden_core::keychain::memory::InMemoryKeychain;

    fn server() -> WrappedServer {
        toml::from_str(
            r#"
            name = "github"
            command = "npx"
            args = ["-y", "@modelcontextprotocol/server-github"]
            env = ["GITHUB_PERSONAL_ACCESS_TOKEN", "OTHER"]
            "#,
        )
        .unwrap()
    }

    #[test]
    fn resolve_env_reads_only_the_servers_own_entries() {
        let kc = InMemoryKeychain::new();
        kc.set(
            "server/github/GITHUB_PERSONAL_ACCESS_TOKEN",
            Secret::new("server value".into()),
        )
        .unwrap();
        kc.set("server/github/OTHER", Secret::new("x".into()))
            .unwrap();
        // A preset's secret under another name is never used.
        kc.set("github_pat", Secret::new("preset value".into()))
            .unwrap();
        let env = resolve_env(&server(), &kc).unwrap();
        let got: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.expose())).collect();
        assert_eq!(
            got,
            [
                ("GITHUB_PERSONAL_ACCESS_TOKEN", "server value"),
                ("OTHER", "x")
            ]
        );
    }

    #[test]
    fn missing_secret_names_the_entry_not_a_value() {
        let kc = InMemoryKeychain::new();
        kc.set(
            "server/github/GITHUB_PERSONAL_ACCESS_TOKEN",
            Secret::new("server value".into()),
        )
        .unwrap();
        let err = resolve_env(&server(), &kc).unwrap_err().to_string();
        assert!(err.contains("'server/github/OTHER'"), "{err}");
        assert!(!err.contains("server value"));
    }

    #[test]
    fn audit_summary_is_the_program_and_its_arguments_only() {
        assert_eq!(
            command_line(&server(), Path::new("/opt/homebrew/bin/npx")),
            "/opt/homebrew/bin/npx -y @modelcontextprotocol/server-github"
        );
    }

    #[cfg(unix)]
    fn executable(dir: &Path, name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(&p, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[cfg(unix)]
    #[test]
    fn a_bare_name_is_found_in_the_given_path_only() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let wanted = executable(second.path(), "srv");
        // Not executable: skipped.
        std::fs::write(first.path().join("srv"), "x").unwrap();
        let path = std::env::join_paths([first.path(), second.path()]).unwrap();
        assert_eq!(resolve_program("srv", &path).unwrap(), wanted);
        let err = resolve_program("nope", &path).unwrap_err();
        assert!(err.contains("'nope' is not in"), "{err}");
    }

    /// `PATH=.:…` and relative entries would search the caller's working
    /// directory; relative commands would run a file there.
    #[cfg(unix)]
    #[test]
    fn relative_directories_and_relative_commands_are_never_used() {
        let dir = tempfile::tempdir().unwrap();
        executable(dir.path(), "srv");
        let cwd = std::env::current_dir().unwrap();
        let rel = pathdiff(dir.path(), &cwd);
        let path = std::env::join_paths([rel.as_path(), Path::new(".")]).unwrap();
        assert!(resolve_program("srv", &path).is_err());
        for command in ["./srv", "bin/srv", "", "../srv"] {
            let err = resolve_program(command, OsStr::new("/usr/bin")).unwrap_err();
            assert!(err.contains("bare program name"), "{command}: {err}");
        }
        assert!(resolve_program("/no/such/program", OsStr::new("/usr/bin")).is_err());
        assert_eq!(
            resolve_program("/bin/sh", OsStr::new("")).unwrap(),
            Path::new("/bin/sh")
        );
    }

    /// `to` as a path relative to `from` (both absolute).
    #[cfg(unix)]
    fn pathdiff(to: &Path, from: &Path) -> PathBuf {
        let ups = from.components().count() - 1;
        let mut out: PathBuf = std::iter::repeat_n("..", ups).collect();
        out.push(to.strip_prefix("/").unwrap());
        out
    }

    #[test]
    fn the_server_environment_keeps_nothing_that_loads_code() {
        let home = Path::new("/home/someone");
        let env = base_env(OsStr::new("/usr/bin"), home);
        let names: Vec<String> = env
            .iter()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        for name in &names {
            assert!(
                PASSED_THROUGH.contains(&name.as_str())
                    || name.starts_with("LC_")
                    || [
                        "PATH",
                        "HOME",
                        "USERPROFILE",
                        "PATHEXT",
                        "SystemRoot",
                        "windir",
                        "ComSpec",
                        "ProgramFiles",
                        "APPDATA",
                        "LOCALAPPDATA",
                        "TEMP",
                        "TMP"
                    ]
                    .contains(&name.as_str()),
                "{name} reached the server environment"
            );
        }
        assert!(env.contains(&("PATH".into(), "/usr/bin".into())));
        #[cfg(unix)]
        assert!(env.contains(&("HOME".into(), home.into())));
    }

    // ---- Audit 2026-11-09, H1: the caller's environment ----------------
    //
    // `run` execs the server, which would replace the test process, so the
    // real `run` runs in a child: this test binary again, filtered down to
    // `audit_h1_child`. The child holds the server's key and a stamp for
    // exactly its entry and program (a human confirmed it earlier), and its
    // approval transport denies everything — so whatever the server
    // receives, it receives without anyone being asked.

    #[cfg(unix)]
    const AUDIT_H1_SECRET: &str = "audit-h1-key-7f3a91c2";

    #[cfg(unix)]
    #[test]
    #[ignore = "helper: runs only in the child process the audit_h1 tests start"]
    fn audit_h1_child() {
        use mcp_warden_core::stamp;
        let Ok(dir) = std::env::var("AUDIT_H1_DIR") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        let cfg_dir = dir.join("cfg");
        let entry = std::fs::read_to_string(dir.join("server.toml")).unwrap();
        std::fs::write(cfg_dir.join("config.toml"), format!("[[server]]\n{entry}")).unwrap();
        let s: WrappedServer = toml::from_str(&entry).unwrap();
        let kc: std::sync::Arc<dyn KeychainStore> = std::sync::Arc::new(InMemoryKeychain::new());
        for var in &s.env {
            kc.set(&s.secret_name(var), Secret::new(AUDIT_H1_SECRET.into()))
                .unwrap();
        }
        // What the human confirmed: this entry, run as the program it
        // resolves to in its own path.
        let confirmed = std::env::var("AUDIT_H1_CONFIRMED")
            .map(PathBuf::from)
            .unwrap_or_else(|_| program(&s).unwrap());
        stamp::record(
            kc.as_ref(),
            &stamp::server_stamp_name(&s.name),
            &stamp::server_fingerprint(&s, &confirmed),
        )
        .unwrap();
        let audit =
            mcp_warden_core::audit::sqlite_sink::LocalSqlite::open(&cfg_dir.join("audit.db"))
                .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // Returns only if `run` refused or the exec failed.
        let result = rt.block_on(run(&s.name, &cfg_dir, kc, &audit));
        std::fs::write(dir.join("refused"), format!("{result:?}")).unwrap();
    }

    /// Start `audit_h1_child` for the `[[server]]` body `entry`, with
    /// `caller_env` added to the environment `mcp-warden run` is started in.
    #[cfg(unix)]
    fn audit_h1_launch(entry: &str, caller_env: &[(&str, String)]) -> (tempfile::TempDir, String) {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("cfg");
        std::fs::create_dir(&cfg).unwrap();
        std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(dir.path().join("server.toml"), entry).unwrap();
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "--exact",
            "cli::run::tests::audit_h1_child",
            "--ignored",
            "--test-threads=1",
        ])
        .env("AUDIT_H1_DIR", dir.path())
        .env("MCP_WARDEN_BACKEND", "memory")
        .env("MCP_WARDEN_APPROVAL_TRANSPORT", "test-deny");
        for (k, v) in caller_env {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        let refused = std::fs::read_to_string(dir.path().join("refused")).unwrap_or_default();
        let report = format!(
            "status {:?}; refused: {refused}; stderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        (dir, report)
    }

    /// A program that writes its environment and working directory next to
    /// itself.
    #[cfg(unix)]
    fn recorder(dir: &Path, name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        let dump = dir.join("dump");
        std::fs::write(
            &p,
            format!(
                "#!/bin/sh\n/usr/bin/env > '{}'\npwd > '{}.cwd'\n",
                dump.display(),
                dump.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        dump
    }

    /// A human confirmed `mcpw-srv` from its entry's own `path`. The caller —
    /// an agent with a shell (`PATH=/tmp/x:$PATH mcp-warden run srv`), or a
    /// client config it edited — puts its own directory first on PATH. The
    /// key must reach the confirmed program, never the caller's.
    #[cfg(unix)]
    #[test]
    fn audit_h1_the_callers_path_does_not_pick_the_program_that_gets_the_key() {
        let legit = tempfile::tempdir().unwrap();
        let evil = tempfile::tempdir().unwrap();
        let legit_dump = recorder(legit.path(), "mcpw-srv");
        let evil_dump = recorder(evil.path(), "mcpw-srv");
        let path = format!(
            "{}:{}",
            evil.path().display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let (_dir, report) = audit_h1_launch(
            &format!(
                "name = \"srv\"\ncommand = \"mcpw-srv\"\npath = \"{}\"\nenv = [\"TOKEN\"]\n",
                legit.path().display()
            ),
            &[("PATH", path)],
        );
        let evil_seen = std::fs::read_to_string(&evil_dump).unwrap_or_default();
        assert!(
            !evil_seen.contains(AUDIT_H1_SECRET),
            "the caller's own program received the key, and nobody was asked ({report})"
        );
        let legit_seen = std::fs::read_to_string(&legit_dump).unwrap_or_default();
        assert!(
            legit_seen.contains(&format!("TOKEN={AUDIT_H1_SECRET}")),
            "the confirmed program should start with its key ({report})"
        );
    }

    /// A program planted earlier on the server's own search path — after the
    /// human confirmed the one further down — is not what was confirmed:
    /// the launch asks again (and the test transport denies).
    #[cfg(unix)]
    #[test]
    fn a_program_planted_earlier_on_the_path_asks_again() {
        let planted = tempfile::tempdir().unwrap();
        let legit = tempfile::tempdir().unwrap();
        let planted_dump = recorder(planted.path(), "mcpw-srv");
        recorder(legit.path(), "mcpw-srv");
        let (_dir, report) = audit_h1_launch(
            &format!(
                "name = \"srv\"\ncommand = \"mcpw-srv\"\npath = \"{}:{}\"\nenv = [\"TOKEN\"]\n",
                planted.path().display(),
                legit.path().display()
            ),
            &[(
                "AUDIT_H1_CONFIRMED",
                legit.path().join("mcpw-srv").display().to_string(),
            )],
        );
        assert!(
            !planted_dump.exists(),
            "the planted program ran without a new confirmation ({report})"
        );
        assert!(report.contains("needs confirmation"), "{report}");
    }

    /// The confirmed program itself runs, but the caller set variables that
    /// make it load the caller's code (`NODE_OPTIONS=--require …`,
    /// `BASH_ENV`, `PYTHONPATH`, …) and chose its working directory (where
    /// npx reads a project `.npmrc`). The server gets none of it.
    #[cfg(unix)]
    #[test]
    fn audit_h1_the_callers_code_loading_variables_do_not_reach_the_server() {
        let out = tempfile::tempdir().unwrap();
        let dump = recorder(out.path(), "srv.sh");
        let (_dir, report) = audit_h1_launch(
            &format!(
                "name = \"node\"\ncommand = \"{}\"\nenv = [\"TOKEN\"]\n",
                out.path().join("srv.sh").display()
            ),
            &[
                ("NODE_OPTIONS", "--require /tmp/agent.js".into()),
                ("BASH_ENV", "/tmp/agent.sh".into()),
                ("PYTHONPATH", "/tmp/agent".into()),
                ("HOME", "/tmp".into()),
            ],
        );
        let seen = std::fs::read_to_string(&dump).unwrap_or_default();
        assert!(
            seen.contains(&format!("TOKEN={AUDIT_H1_SECRET}")),
            "the confirmed server should start with its key ({report})"
        );
        for var in ["NODE_OPTIONS=", "BASH_ENV=", "PYTHONPATH="] {
            assert!(
                !seen.contains(var),
                "{var}… from the caller reached the server next to its key ({report})"
            );
        }
        let home = crate::osenv::account_home().unwrap();
        assert!(
            seen.contains(&format!("HOME={}\n", home.display())),
            "HOME is the account's: {seen}"
        );
        let cwd = std::fs::read_to_string(format!("{}.cwd", dump.display())).unwrap();
        assert_eq!(
            std::fs::canonicalize(cwd.trim()).unwrap(),
            std::fs::canonicalize(&home).unwrap(),
            "the server starts in the account's home directory"
        );
    }
}
