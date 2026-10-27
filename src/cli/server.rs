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
    /// `server add github --env GITHUB_PERSONAL_ACCESS_TOKEN -- npx -y @modelcontextprotocol/server-github`.
    /// Each variable's value is read from stdin (prompted on a terminal) into
    /// the server's own keychain entry `server/<name>/<VAR>`.
    Add(ServerAddArgs),
    /// List wrapped servers: command and the variables they get.
    List,
    /// Remove a wrapped server and its keychain entries.
    Remove { name: String },
}

#[derive(Debug, Args)]
pub struct ServerAddArgs {
    /// Name to launch it by (`mcp-warden run <name>`).
    pub name: String,
    /// Environment variable the server reads its key from. Repeat for
    /// several. Values are read from stdin, never taken as arguments.
    #[arg(long = "env", value_name = "VAR")]
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
        ServerCmd::Remove { name } => remove(&name, config_path, kc),
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
    if let Some(pair) = args.env.iter().find(|v| v.contains('=')) {
        // A value on the command line ends up in shell history and `ps`.
        return Err(WardenError::Validation(format!(
            "--env '{}': pass only the variable name; its value is read from stdin",
            pair.split('=').next().unwrap_or_default()
        )));
    }
    let mut command = args.command.into_iter();
    let server = WrappedServer {
        name: args.name.clone(),
        command: command.next().unwrap_or_default(),
        args: command.collect(),
        env: args.env,
    };
    // Validate before asking for any value.
    let mut probe = load(config_path)?;
    probe.server.retain(|s| s.name != server.name);
    probe.server.push(server.clone());
    probe.validate_servers()?;
    for var in &server.env {
        let entry = server.secret_name(var);
        if kc.get(&entry)?.is_none() {
            kc.set(&entry, crate::cli::secret::read_value(&entry)?)?;
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
        println!(
            "{:20} {} {}  [{}]",
            s.name,
            s.command,
            s.args.join(" "),
            s.env.join(", ")
        );
    }
    Ok(())
}

fn remove(name: &str, config_path: &Path, kc: &dyn KeychainStore) -> Result<()> {
    let mut cfg = load(config_path)?;
    let server = cfg
        .find_server(name)
        .cloned()
        .ok_or_else(|| WardenError::Validation(format!("no server named '{name}'")))?;
    cfg.server.retain(|s| s.name != name);
    save(config_path, &cfg)?;
    for var in &server.env {
        kc.delete(&server.secret_name(var))?;
    }
    eprintln!("Removed server '{name}' and its keychain entries.");
    Ok(())
}
