use crate::cli::server;
use crate::scan::{Finding, Options, scan};
use clap::Args;
use is_terminal::IsTerminal;
use mcp_warden_core::config::WrappedServer;
use mcp_warden_core::error::{Result, WardenError};
use mcp_warden_core::keychain::KeychainStore;
use mcp_warden_core::secret::Secret;
use serde_json::Value;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Args)]
pub struct ImportArgs {
    /// Also import from this project directory (repeatable). The current
    /// directory is always included.
    #[arg(long = "path", value_name = "DIR")]
    pub paths: Vec<PathBuf>,
    /// Skip user-level client configs (~/.claude.json, Claude Desktop, …).
    #[arg(long)]
    pub no_home: bool,
    /// Show what would change and stop.
    #[arg(long)]
    pub dry_run: bool,
    /// Don't ask for confirmation (required when stdin is not a terminal).
    #[arg(long)]
    pub yes: bool,
}

/// One MCP server entry whose plaintext keys move to the keychain.
struct Move<'a> {
    file: &'a Path,
    server_path: &'a [String],
    client_name: &'a str,
    findings: Vec<&'a Finding>,
}

/// `mcp-warden import`: move the keys `scan` marks importable — `env`
/// values of stdio MCP servers — into the keychain, and point each client
/// entry at `mcp-warden run <name>` instead.
pub fn run(args: ImportArgs, config_path: &Path, kc: &dyn KeychainStore) -> Result<()> {
    let mut dirs = vec![std::env::current_dir().map_err(WardenError::Io)?];
    dirs.extend(args.paths.iter().cloned());
    let home = (!args.no_home).then(dirs::home_dir).flatten();
    let report = scan(&Options {
        config_dir: home.as_ref().and_then(|_| dirs::config_dir()),
        home: home.clone(),
        dirs,
    });
    let exe = std::env::current_exe().map_err(WardenError::Io)?;
    let confirm = |plan: &str| confirm(plan, args.yes);
    import(
        &report.findings,
        config_path,
        kc,
        &exe.display().to_string(),
        home.as_deref(),
        args.dry_run,
        &confirm,
    )
}

/// The testable core: plan, confirm, then move server by server.
pub(crate) fn import(
    findings: &[Finding],
    config_path: &Path,
    kc: &dyn KeychainStore,
    exe: &str,
    home: Option<&Path>,
    dry_run: bool,
    confirm: &dyn Fn(&str) -> Result<bool>,
) -> Result<()> {
    let moves = group(findings);
    let skipped = findings.iter().filter(|f| f.import.is_none()).count();
    if moves.is_empty() {
        eprintln!(
            "Nothing to import.{}",
            if skipped > 0 {
                format!(" {skipped} finding(s) need a manual fix — see `mcp-warden scan`.")
            } else {
                String::new()
            }
        );
        return Ok(());
    }
    let mut cfg = server::load(config_path)?;
    let mut planned = Vec::new();
    for m in &moves {
        let name = free_name(&cfg, m.client_name, &planned);
        planned.push(name);
    }

    let mut plan = String::from("Will move these keys into the keychain:\n");
    for (m, name) in moves.iter().zip(&planned) {
        plan.push_str(&format!(
            "  {}  {}\n",
            display(m.file, home),
            m.server_path.join(".")
        ));
        for f in &m.findings {
            let var = &f.import.as_ref().expect("grouped importable").var;
            plan.push_str(&format!(
                "    {var} ({}, {}) → keychain server/{name}/{var}\n",
                f.kind, f.redacted
            ));
        }
        plan.push_str(&format!("    the entry becomes: {exe} run {name}\n"));
    }
    plan.push_str(
        "Quit Claude Code and Claude Desktop first: they rewrite their config files \
         and could put the old entry back.\n",
    );
    if skipped > 0 {
        plan.push_str(&format!(
            "{skipped} other finding(s) can't be imported — see `mcp-warden scan` for what to do.\n"
        ));
    }
    eprint!("{plan}");
    if dry_run || !confirm(&plan)? {
        eprintln!("Nothing changed.");
        return Ok(());
    }

    for (m, name) in moves.iter().zip(&planned) {
        move_server(m, name, &mut cfg, config_path, kc, exe)?;
        eprintln!(
            "Moved {} → `mcp-warden run {name}`.",
            m.server_path.join(".")
        );
    }
    eprintln!(
        "Done. Restart your MCP clients, then run `mcp-warden scan` to check nothing is left."
    );
    Ok(())
}

/// Importable findings, one group per server entry, in scan order.
fn group(findings: &[Finding]) -> Vec<Move<'_>> {
    let mut moves: Vec<Move> = Vec::new();
    for f in findings {
        let Some(target) = &f.import else { continue };
        match moves
            .iter_mut()
            .find(|m| m.file == f.file && m.server_path == target.server_path.as_slice())
        {
            Some(m) => m.findings.push(f),
            None => moves.push(Move {
                file: &f.file,
                server_path: &target.server_path,
                client_name: &target.server,
                findings: vec![f],
            }),
        }
    }
    moves
}

/// A `[[server]]` name for the client's entry: its name made safe, with a
/// suffix if the config (or this run) already uses it.
fn free_name(
    cfg: &mcp_warden_core::config::Config,
    client_name: &str,
    planned: &[String],
) -> String {
    let base: String = client_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let base = if base.is_empty() {
        "server".to_string()
    } else {
        base
    };
    let taken = |n: &str| cfg.find_server(n).is_some() || planned.iter().any(|p| p == n);
    if !taken(&base) {
        return base;
    }
    (2..)
        .map(|i| format!("{base}-{i}"))
        .find(|n| !taken(n))
        .expect("an unused name exists")
}

/// Keychain first (verified), then the warden config, then the client
/// config — so a failure part-way leaves the key in two places, never none.
fn move_server(
    m: &Move,
    name: &str,
    cfg: &mut mcp_warden_core::config::Config,
    config_path: &Path,
    kc: &dyn KeychainStore,
    exe: &str,
) -> Result<()> {
    let real = std::fs::canonicalize(m.file).map_err(WardenError::Io)?;
    let raw = std::fs::read_to_string(&real).map_err(WardenError::Io)?;
    let mut doc: Value = serde_json::from_str(&raw)
        .map_err(|e| WardenError::Config(format!("{}: {e}", m.file.display())))?;
    let entry = entry_mut(&mut doc, m.server_path).ok_or_else(|| {
        WardenError::Config(format!("{} changed since the scan", m.file.display()))
    })?;

    let command = entry["command"].as_str().unwrap_or_default().to_string();
    let args: Vec<String> = entry["args"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|a| a.as_str().map(str::to_string))
        .collect();
    let vars: Vec<String> = m
        .findings
        .iter()
        .map(|f| f.import.as_ref().expect("grouped importable").var.clone())
        .collect();
    let server = WrappedServer {
        name: name.to_string(),
        command,
        args,
        env: vars.clone(),
    };

    for var in &vars {
        let value = entry["env"][var].as_str().ok_or_else(|| {
            WardenError::Config(format!("{} changed since the scan", m.file.display()))
        })?;
        let secret_name = server.secret_name(var);
        kc.set(&secret_name, Secret::new(value.to_string()))?;
        let stored = kc.get(&secret_name)?;
        if stored.as_ref().map(Secret::expose) != Some(value) {
            return Err(WardenError::Keychain(format!(
                "'{secret_name}' did not read back as written; nothing else was changed"
            )));
        }
    }

    cfg.server.push(server);
    cfg.validate_servers()?;
    server::save(config_path, cfg)?;

    if let Some(env) = entry.get_mut("env").and_then(Value::as_object_mut) {
        for var in &vars {
            env.remove(var);
        }
        if env.is_empty() {
            entry.as_object_mut().map(|o| o.remove("env"));
        }
    }
    entry["command"] = Value::from(exe);
    entry["args"] = serde_json::json!(["run", name]);
    write_atomic(&real, &doc)
}

fn entry_mut<'a>(doc: &'a mut Value, path: &[String]) -> Option<&'a mut Value> {
    path.iter().try_fold(doc, |v, key| v.get_mut(key.as_str()))
}

/// Replace `path` with `doc` via a temp file in the same directory, keeping
/// the file's permissions. No backup is kept: it would hold the plaintext.
fn write_atomic(path: &Path, doc: &Value) -> Result<()> {
    let mut body =
        serde_json::to_string_pretty(doc).map_err(|e| WardenError::Config(e.to_string()))?;
    body.push('\n');
    let perms = std::fs::metadata(path)
        .map_err(WardenError::Io)?
        .permissions();
    let tmp = path.with_extension("mcp-warden-tmp");
    std::fs::write(&tmp, body).map_err(WardenError::Io)?;
    std::fs::set_permissions(&tmp, perms).map_err(WardenError::Io)?;
    std::fs::rename(&tmp, path).map_err(WardenError::Io)
}

fn confirm(_plan: &str, yes: bool) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        return Err(WardenError::Validation(
            "not a terminal: re-run with --yes to import without a prompt".into(),
        ));
    }
    eprint!("Proceed? [y/N] ");
    std::io::stderr().flush().ok();
    let mut answer = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut answer)
        .map_err(WardenError::Io)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

fn display(path: &Path, home: Option<&Path>) -> String {
    match home.and_then(|h| path.strip_prefix(h).ok()) {
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::detect::tests::fake;
    use mcp_warden_core::keychain::memory::InMemoryKeychain;

    struct Fixture {
        project: tempfile::TempDir,
        warden: tempfile::TempDir,
        token: String,
    }

    impl Fixture {
        fn new() -> Self {
            let project = tempfile::tempdir().unwrap();
            let token = fake(&["gh", "p_"].concat(), 36);
            let mcp = serde_json::json!({ "mcpServers": {
                "github": {
                    "type": "stdio",
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": token, "LOG_LEVEL": "debug" }
                },
                "plain": { "command": "uvx", "args": ["mcp-server-time"] }
            }});
            std::fs::write(
                project.path().join(".mcp.json"),
                serde_json::to_string_pretty(&mcp).unwrap(),
            )
            .unwrap();
            Self {
                project,
                warden: tempfile::tempdir().unwrap(),
                token,
            }
        }

        fn findings(&self) -> Vec<Finding> {
            scan(&Options {
                home: None,
                config_dir: None,
                dirs: vec![self.project.path().to_path_buf()],
            })
            .findings
        }

        fn config(&self) -> PathBuf {
            self.warden.path().join("config.toml")
        }

        fn mcp_json(&self) -> String {
            std::fs::read_to_string(self.project.path().join(".mcp.json")).unwrap()
        }
    }

    #[test]
    fn moves_the_key_and_rewires_the_entry() {
        let fx = Fixture::new();
        let kc = InMemoryKeychain::new();
        import(
            &fx.findings(),
            &fx.config(),
            &kc,
            "/opt/mcp-warden",
            None,
            false,
            &|_| Ok(true),
        )
        .unwrap();

        let stored = kc
            .get("server/github/GITHUB_PERSONAL_ACCESS_TOKEN")
            .unwrap()
            .unwrap();
        assert_eq!(stored.expose(), fx.token);

        let after = fx.mcp_json();
        assert!(
            !after.contains(&fx.token),
            "plaintext left behind:\n{after}"
        );
        let v: Value = serde_json::from_str(&after).unwrap();
        let gh = &v["mcpServers"]["github"];
        assert_eq!(gh["command"], "/opt/mcp-warden");
        assert_eq!(gh["args"], serde_json::json!(["run", "github"]));
        assert_eq!(gh["env"], serde_json::json!({ "LOG_LEVEL": "debug" }));
        assert_eq!(gh["type"], "stdio", "other keys are kept");
        assert_eq!(
            v["mcpServers"]["plain"]["command"], "uvx",
            "other servers untouched"
        );
        let keys: Vec<&str> = gh.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            ["type", "command", "args", "env"],
            "key order is kept"
        );

        let cfg = server::load(&fx.config()).unwrap();
        let s = cfg.find_server("github").unwrap();
        assert_eq!(s.command, "npx");
        assert_eq!(s.args, ["-y", "@modelcontextprotocol/server-github"]);
        assert_eq!(s.env, ["GITHUB_PERSONAL_ACCESS_TOKEN"]);
        assert!(
            !std::fs::read_to_string(fx.config())
                .unwrap()
                .contains(&fx.token)
        );

        assert!(fx.findings().is_empty(), "a re-scan finds nothing");
    }

    #[test]
    fn dry_run_and_declining_change_nothing() {
        let fx = Fixture::new();
        let before = fx.mcp_json();
        for (dry_run, answer) in [(true, true), (false, false)] {
            let kc = InMemoryKeychain::new();
            import(
                &fx.findings(),
                &fx.config(),
                &kc,
                "/x",
                None,
                dry_run,
                &|_| Ok(answer),
            )
            .unwrap();
            assert_eq!(fx.mcp_json(), before);
            assert!(kc.list_names().unwrap().is_empty());
            assert!(!fx.config().exists());
        }
    }

    #[test]
    fn taken_names_get_a_suffix() {
        let fx = Fixture::new();
        server::save(
            &fx.config(),
            &toml::from_str("[[server]]\nname = \"github\"\ncommand = \"other\"\n").unwrap(),
        )
        .unwrap();
        let kc = InMemoryKeychain::new();
        import(
            &fx.findings(),
            &fx.config(),
            &kc,
            "/x",
            None,
            false,
            &|_| Ok(true),
        )
        .unwrap();
        assert!(
            kc.get("server/github-2/GITHUB_PERSONAL_ACCESS_TOKEN")
                .unwrap()
                .is_some()
        );
        let v: Value = serde_json::from_str(&fx.mcp_json()).unwrap();
        assert_eq!(
            v["mcpServers"]["github"]["args"],
            serde_json::json!(["run", "github-2"])
        );
    }

    #[test]
    fn non_terminal_without_yes_is_refused() {
        // `cargo test` runs with stdin that is not a terminal.
        if std::io::stdin().is_terminal() {
            return;
        }
        assert!(confirm("plan", false).is_err());
        assert!(confirm("plan", true).unwrap());
    }
}
