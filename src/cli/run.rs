use crate::executor::lock;
use mcp_warden_core::audit::{AuditDecision, AuditSink};
use mcp_warden_core::config::{Config, WrappedServer};
use mcp_warden_core::error::{Result, WardenError};
use mcp_warden_core::keychain::KeychainStore;
use mcp_warden_core::secret::Secret;
use std::path::Path;

/// `mcp-warden run <name>`: launch the `[[server]]` named `name` with its
/// keys read from the keychain into its environment.
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
    // The keys go only to the command a human confirmed: an edit to this
    // entry (another command, more variables) asks again first.
    let exec = crate::cli::confirm::executor(config_dir, &cfg, store.clone())?;
    crate::cli::confirm::ensure_server_confirmed(&exec, server)
        .await
        .map_err(|e| {
            WardenError::Validation(format!(
                "server '{name}' was not started: launching it needs confirmation ({e})"
            ))
        })?;
    let env = resolve_env(server, store.as_ref())?;

    let id = audit.record_pending(name, "run", &command_line(server))?;
    audit.record_decision(id, AuditDecision::Auto)?;

    let mut cmd = std::process::Command::new(&server.command);
    cmd.args(&server.args);
    for (var, value) in &env {
        cmd.env(var, value.expose());
    }
    launch(cmd, &server.command)
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

/// What the audit log shows for a launch: the command, never the env.
fn command_line(server: &WrappedServer) -> String {
    std::iter::once(server.command.as_str())
        .chain(server.args.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Replace this process with the server, so stdio and signals reach it
/// directly. Returns only if the exec failed.
#[cfg(unix)]
fn launch(mut cmd: std::process::Command, program: &str) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let err = cmd.exec();
    Err(WardenError::Executor(format!(
        "could not start '{program}': {err}"
    )))
}

/// No exec on this platform: run the server as a child with inherited
/// stdio and exit with its status.
#[cfg(not(unix))]
fn launch(mut cmd: std::process::Command, program: &str) -> Result<()> {
    let status = cmd
        .status()
        .map_err(|e| WardenError::Executor(format!("could not start '{program}': {e}")))?;
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
    fn audit_summary_is_the_command_line_only() {
        assert_eq!(
            command_line(&server()),
            "npx -y @modelcontextprotocol/server-github"
        );
    }

    // ---- Audit 2026-11-09, H1: the caller's environment ----------------
    //
    // `run` execs the server, which would replace the test process, so the
    // real `run` runs in a child: this test binary again, filtered down to
    // `audit_h1_child`. The child holds the server's key and a stamp for
    // exactly its entry (a human confirmed it earlier), and its approval
    // transport denies everything — so whatever the server receives, it
    // receives without anyone being asked.

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
        stamp::record(
            kc.as_ref(),
            &stamp::server_stamp_name(&s.name),
            &stamp::server_fingerprint(&s),
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

    /// A human confirmed `npx …` with its key. The caller — an agent with a
    /// shell (`PATH=/tmp/x:$PATH mcp-warden run github`), or a client config
    /// it edited — puts its own directory first on PATH. The key must not
    /// reach a program the caller chose.
    #[cfg(unix)]
    #[test]
    #[ignore = "audit 2026-11-09 H1: confirmed — fails until `run` stops resolving the command through the caller's PATH"]
    fn audit_h1_the_callers_path_does_not_pick_the_program_that_gets_the_key() {
        use std::os::unix::fs::PermissionsExt;
        let evil = tempfile::tempdir().unwrap();
        let dump = evil.path().join("dump");
        let fake = evil.path().join("npx");
        std::fs::write(&fake, format!("#!/bin/sh\nenv > '{}'\n", dump.display())).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = format!(
            "{}:{}",
            evil.path().display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let (_dir, report) = audit_h1_launch(
            "name = \"github\"\ncommand = \"npx\"\n\
             args = [\"-y\", \"@modelcontextprotocol/server-github\"]\n\
             env = [\"GITHUB_PERSONAL_ACCESS_TOKEN\"]\n",
            &[("PATH", path)],
        );
        let seen = std::fs::read_to_string(&dump).unwrap_or_default();
        assert!(
            !seen.contains(AUDIT_H1_SECRET),
            "the caller's own `npx` received the key, and nobody was asked ({report})"
        );
    }

    /// The confirmed program itself runs, but with variables the caller set
    /// that make it load the caller's code (`NODE_OPTIONS=--require …`,
    /// `BASH_ENV`, `PYTHONPATH`, …), next to its key.
    #[cfg(unix)]
    #[test]
    #[ignore = "audit 2026-11-09 H1: confirmed — fails until `run` stops passing the caller's environment to the server"]
    fn audit_h1_the_callers_code_loading_variables_do_not_reach_the_server() {
        let out = tempfile::tempdir().unwrap();
        let dump = out.path().join("dump");
        let (_dir, report) = audit_h1_launch(
            &format!(
                "name = \"node\"\ncommand = \"/bin/sh\"\n\
                 args = [\"-c\", \"env > '{}'\"]\nenv = [\"TOKEN\"]\n",
                dump.display()
            ),
            &[
                ("NODE_OPTIONS", "--require /tmp/agent.js".into()),
                ("BASH_ENV", "/tmp/agent.sh".into()),
                ("PYTHONPATH", "/tmp/agent".into()),
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
    }
}
