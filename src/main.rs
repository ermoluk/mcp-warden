// The binary is a thin shell around the `mcp_warden` library target
// (src/lib.rs), which the fuzz targets in `fuzz/` link against too.
use clap::Parser;
use mcp_warden::{cli, fsutil};

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
        cli::Command::Preset { cmd } => cli::preset::run(cmd, &config_path, store).await?,
        cli::Command::Audit(args) => cli::audit::run(args, &audit_db, store.as_ref(), &config_dir)?,
        cli::Command::Approval(args) if args.is_telegram_test() => {
            cli::approval::telegram_test(&config_dir, store).await?
        }
        cli::Command::Approval(args) => {
            let name = args.preset.clone();
            cli::approval::run(args, &config_path)?;
            // An auto preset counts only once a human confirms it.
            cli::confirm::confirm_if_auto(&name, &config_path, store).await?
        }
        cli::Command::Mcp => cli::mcp::cmd(&config_dir).await?,
        cli::Command::Doctor(args) => cli::doctor::run(args, &config_dir, store).await?,
        cli::Command::Web { port } => cli::web::run(port, &config_path, &audit_db).await?,
        cli::Command::Lock { reason } => {
            fsutil::ensure_private_dir(&config_dir)?;
            let audit = mcp_warden_core::audit::sqlite_sink::LocalSqlite::open(&audit_db)?;
            cli::lock::lock(&config_dir, reason, &audit, store.as_ref())?
        }
        cli::Command::Unlock => cli::lock::unlock_cmd(&config_dir, store, &audit_db).await?,
        cli::Command::Run { name } => {
            fsutil::ensure_private_dir(&config_dir)?;
            let audit = mcp_warden_core::audit::sqlite_sink::LocalSqlite::open(&audit_db)?;
            cli::run::run(&name, &config_dir, store, &audit).await?
        }
        cli::Command::Server { cmd } => cli::server::run(cmd, &config_path, store.as_ref())?,
        cli::Command::Scan(args) => cli::scan::run(args)?,
        cli::Command::Import(args) => cli::import::run(args, &config_path, store.as_ref())?,
    }
    Ok(())
}
