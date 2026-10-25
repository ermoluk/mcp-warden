use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;

pub mod approval;
pub mod audit;
pub mod doctor;
pub mod init;
pub mod mcp;
pub mod openapi;
pub mod preset;
pub mod preset_templates;
pub mod secret;
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
