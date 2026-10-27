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
pub fn run(
    name: &str,
    config_dir: &Path,
    kc: &dyn KeychainStore,
    audit: &dyn AuditSink,
) -> Result<()> {
    if lock::is_present(&config_dir.join(lock::LOCK_FILE)) {
        return Err(WardenError::Locked);
    }
    let raw = std::fs::read_to_string(config_dir.join("config.toml")).unwrap_or_default();
    let cfg: Config = toml::from_str(&raw).map_err(|e| WardenError::Config(e.to_string()))?;
    cfg.validate_servers()?;
    let server = cfg.find_server(name).ok_or_else(|| {
        WardenError::Validation(format!(
            "no [[server]] named '{name}' in the config; add one with `mcp-warden server add`"
        ))
    })?;
    let env = resolve_env(server, kc)?;

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
}
