use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;

pub mod approval;
pub mod audit;
pub mod doctor;
pub mod import;
pub mod init;
pub mod lock;
pub mod mcp;
pub mod openapi;
pub mod preset;
pub mod preset_templates;
pub mod run;
pub mod scan;
pub mod secret;
pub mod server;
pub mod web;

#[derive(Debug, Parser)]
#[command(
    name = "mcp-warden",
    version,
    about = "Local-first credential broker for AI agents."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// First-run setup — create the config directory and a template config file.
    Init,
    /// Manage secrets stored in the OS keychain.
    Secret {
        #[command(subcommand)]
        cmd: secret::SecretCmd,
    },
    /// Define and inspect presets (named, scoped actions).
    Preset {
        #[command(subcommand)]
        cmd: preset::PresetCmd,
    },
    /// Show recent audit log entries (read-only — append-only by design).
    Audit(audit::AuditArgs),
    /// Set the approval policy for a preset.
    Approval(approval::ApprovalArgs),
    /// Run the MCP server over stdio (consumed by the AI agent).
    Mcp,
    /// Print a diagnostic summary of the current configuration. Pass
    /// `--deep` to additionally run safe read-only probes for each preset.
    Doctor(doctor::DoctorArgs),
    /// Launch a wrapped MCP server (`[[server]]` in the config) with its keys
    /// injected from the keychain. Use it as the server's command in your
    /// MCP client config instead of writing the key there.
    Run {
        /// The `[[server]]` entry to launch.
        name: String,
    },
    /// Find plaintext secrets in MCP client configs (Claude Code, Claude
    /// Desktop, Cursor, Windsurf, VS Code, Codex) and `.env` files. Read-only;
    /// shows where they are and what they look like, never their values.
    Scan(scan::ScanArgs),
    /// Move the keys `scan` marks importable (`env` of stdio MCP servers)
    /// into the keychain, and point each client entry at `mcp-warden run`.
    Import(import::ImportArgs),
    /// Manage wrapped MCP servers for `mcp-warden run`.
    Server {
        #[command(subcommand)]
        cmd: server::ServerCmd,
    },
    /// Kill switch: every MCP server refuses every call from its next one on.
    Lock {
        /// Why — shown by `unlock` and recorded in the audit log.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Remove the lock after a human approves it (dialog / notification /
    /// Telegram). Servers that saw the lock stay locked until they restart.
    Unlock,
    /// Start a local read-only web UI (binds 127.0.0.1 only).
    Web {
        /// TCP port to listen on (default 7077).
        #[arg(long, default_value_t = 7077)]
        port: u16,
    },
}

/// Construct a `KeychainStore` for the current process.
///
/// In debug builds, the env var `MCP_WARDEN_BACKEND=memory` selects an
/// in-memory store for tests. Release builds always use the system keychain.
pub fn keychain_for_env() -> Arc<dyn mcp_warden_core::keychain::KeychainStore> {
    #[cfg(debug_assertions)]
    {
        if std::env::var("MCP_WARDEN_BACKEND").as_deref() == Ok("memory") {
            return Arc::new(mcp_warden_core::keychain::memory::InMemoryKeychain::new());
        }
    }
    Arc::new(mcp_warden_core::keychain::system::SystemKeychain::new())
}

/// Resolve the config directory.
///
/// `MCP_WARDEN_CONFIG_DIR` env var overrides; otherwise the platform default
/// (`~/.config/mcp-warden/` on Linux, `~/Library/Application Support/io.mcp-warden.mcp-warden/`
/// on macOS, `%APPDATA%\mcp-warden\mcp-warden\config\` on Windows).
pub fn config_dir_for_env() -> PathBuf {
    if let Ok(v) = std::env::var("MCP_WARDEN_CONFIG_DIR") {
        return PathBuf::from(v);
    }
    mcp_warden_core::config::config_path()
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}
