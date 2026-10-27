// Core trait surfaces (keychain, audit, approval, presets, config, error,
// secret) live in the `mcp-warden-core` crate. This binary contains the CLI,
// the MCP server, the action executor, the web UI, and the concrete
// approval transports (desktop / TUI / Telegram / always_deny).
mod approval;
mod cli;
mod executor;
mod mcp;
mod scan;
mod web;

use clap::Parser;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    // Several deps enable different rustls crypto backends; with more than one
    // compiled in, rustls refuses to pick implicitly. Pin ring process-wide.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args = cli::Cli::parse();
    let store = cli::keychain_for_env();
    let config_dir = cli::config_dir_for_env();
    let config_path = config_dir.join("config.toml");
    let audit_db = config_dir.join("audit.db");
    match args.command {
        cli::Command::Init => cli::init::run(&config_dir)?,
        cli::Command::Secret { cmd } => cli::secret::run(cmd, store.as_ref())?,
        cli::Command::Preset { cmd } => cli::preset::run(cmd, &config_path, store.as_ref()).await?,
        cli::Command::Audit(args) => cli::audit::run(args, &audit_db)?,
        cli::Command::Approval(args) => cli::approval::run(args, &config_path)?,
        cli::Command::Mcp => cli::mcp::cmd(&config_dir).await?,
        cli::Command::Doctor(args) => cli::doctor::run(args, &config_dir, store.as_ref()).await?,
        cli::Command::Web { port } => cli::web::run(port, &config_path, &audit_db).await?,
        cli::Command::Lock { reason } => {
            std::fs::create_dir_all(&config_dir)?;
            let audit = mcp_warden_core::audit::sqlite_sink::LocalSqlite::open(&audit_db)?;
            cli::lock::lock(&config_dir, reason, &audit)?
        }
        cli::Command::Unlock => cli::lock::unlock_cmd(&config_dir, store, &audit_db).await?,
        cli::Command::Run { name } => {
            std::fs::create_dir_all(&config_dir)?;
            let audit = mcp_warden_core::audit::sqlite_sink::LocalSqlite::open(&audit_db)?;
            cli::run::run(&name, &config_dir, store.as_ref(), &audit)?
        }
        cli::Command::Server { cmd } => cli::server::run(cmd, &config_path, store.as_ref())?,
        cli::Command::Scan(args) => cli::scan::run(args)?,
    }
    Ok(())
}
