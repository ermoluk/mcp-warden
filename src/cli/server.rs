use clap::{Args, Subcommand};
use mcp_warden_core::config::{Config, WrappedServer};
use mcp_warden_core::error::{Result, WardenError};
use mcp_warden_core::keychain::KeychainStore;
use std::fs;
use std::path::Path;

#[derive(Debug, Subcommand)]
pub enum ServerCmd {
    /// Wrap another MCP server so `mcp-warden run <name>` launches it with
    /// its keys from the keychain, e.g.
    /// `server add github --env GITHUB_PERSONAL_ACCESS_TOKEN=github_pat -- npx -y @modelcontextprotocol/server-github`
    Add(ServerAddArgs),
    /// List wrapped servers: command and which keychain entries they get.
    List,
    /// Remove a wrapped server. Its secrets stay in the keychain.
    Remove { name: String },
}

#[derive(Debug, Args)]
pub struct ServerAddArgs {
    /// Name to launch it by (`mcp-warden run <name>`).
    pub name: String,
    /// `VAR=SECRET`: set environment variable VAR from keychain entry
    /// SECRET. Repeat for several.
    #[arg(long = "env", value_name = "VAR=SECRET")]
    pub env: Vec<String>,
    /// Replace an existing server with the same name.
    #[arg(long)]
    pub force: bool,
    /// The server's command and arguments, after `--`.
    #[arg(last = true, required = true, num_args = 1..)]
    pub command: Vec<String>,
}

pub fn run(cmd: ServerCmd, config_path: &Path, kc: &dyn KeychainStore) -> Result<()> {
    match cmd {
        ServerCmd::Add(args) => add(args, config_path, kc),
        ServerCmd::List => list(config_path),
        ServerCmd::Remove { name } => remove(&name, config_path),
    }
}

fn load(config_path: &Path) -> Result<Config> {
    let raw = fs::read_to_string(config_path).unwrap_or_default();
    toml::from_str(&raw).map_err(|e| WardenError::Config(e.to_string()))
}

fn save(config_path: &Path, cfg: &Config) -> Result<()> {
    if let Some(dir) = config_path.parent() {
        fs::create_dir_all(dir).map_err(WardenError::Io)?;
    }
    let toml_str = toml::to_string_pretty(cfg).map_err(|e| WardenError::Config(e.to_string()))?;
    fs::write(config_path, toml_str).map_err(WardenError::Io)
}

/// Add or replace a `[[server]]` entry, keeping its shape valid.
pub(crate) fn upsert(config_path: &Path, server: WrappedServer, force: bool) -> Result<()> {
    let mut cfg = load(config_path)?;
    match cfg.server.iter_mut().find(|s| s.name == server.name) {
        Some(_) if !force => {
            return Err(WardenError::Validation(format!(
                "a server named '{}' already exists; pass --force to replace it",
                server.name
            )));
        }
        Some(existing) => *existing = server,
        None => cfg.server.push(server),
    }
    cfg.validate_servers()?;
    save(config_path, &cfg)
}

fn add(args: ServerAddArgs, config_path: &Path, kc: &dyn KeychainStore) -> Result<()> {
    let mut env = std::collections::BTreeMap::new();
    for pair in &args.env {
        let (var, secret) = pair.split_once('=').ok_or_else(|| {
            WardenError::Validation(format!("--env '{pair}': expected VAR=SECRET"))
        })?;
        env.insert(var.to_string(), secret.to_string());
    }
    let mut command = args.command.into_iter();
    let server = WrappedServer {
        name: args.name.clone(),
        command: command.next().unwrap_or_default(),
        args: command.collect(),
        env,
    };
    for secret in server.env.values() {
        if kc.get(secret)?.is_none() {
            eprintln!(
                "note: the keychain has no '{secret}' yet — add it with `mcp-warden secret add {secret}`"
            );
        }
    }
    upsert(config_path, server, args.force)?;
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "mcp-warden".into());
    eprintln!(
        "Added server '{}'. In your MCP client config, launch it as:\n  \
         {{ \"command\": \"{exe}\", \"args\": [\"run\", \"{}\"] }}",
        args.name, args.name
    );
    Ok(())
}

fn list(config_path: &Path) -> Result<()> {
    let cfg = load(config_path)?;
    if cfg.server.is_empty() {
        println!("(no servers)");
        return Ok(());
    }
    for s in &cfg.server {
        let env: Vec<String> = s.env.iter().map(|(v, k)| format!("{v}←{k}")).collect();
        println!(
            "{:20} {} {}  [{}]",
            s.name,
            s.command,
            s.args.join(" "),
            env.join(", ")
        );
    }
    Ok(())
}

fn remove(name: &str, config_path: &Path) -> Result<()> {
    let mut cfg = load(config_path)?;
    let before = cfg.server.len();
    cfg.server.retain(|s| s.name != name);
    if cfg.server.len() == before {
        return Err(WardenError::Validation(format!("no server named '{name}'")));
    }
    save(config_path, &cfg)?;
    eprintln!("Removed server '{name}'. Its secrets stay in the keychain.");
    Ok(())
}
