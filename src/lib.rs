//! The modules behind the `mcp-warden` binary. Core trait surfaces
//! (keychain, audit, approval, presets, config, error, secret) live in the
//! `mcp-warden-core` crate; this crate holds the CLI, the MCP server, the
//! action executor, the web UI and the concrete approval transports
//! (desktop / TUI / Telegram / always_deny).
//!
//! It is a library only so the fuzz targets in `fuzz/` can reach the
//! parsers and checks; it is not a stable API.
#![doc(hidden)]

pub mod approval;
pub mod cli;
pub mod executor;
pub mod fsutil;
pub mod mcp;
pub mod scan;
#[cfg(test)]
mod testutil;
pub mod web;

/// Entry points for the fuzz targets in `fuzz/`: each runs one parser or
/// check on arbitrary input. Not a stable API.
#[doc(hidden)]
pub mod fuzz {
    /// `ssh_exec`'s shell-syntax check.
    pub fn check_words(command: &str) -> bool {
        crate::executor::ssh::check_words(command).is_ok()
    }

    /// `response_fields` selection on an upstream body.
    pub fn select_fields(
        body: &serde_json::Value,
        preset: &mcp_warden_core::config::Preset,
    ) -> Option<serde_json::Value> {
        crate::executor::response::select_fields(body, preset)
    }

    /// A Telegram `getUpdates` result as the bot parses it, and the checks
    /// it applies to button data and `/lock` messages.
    pub fn telegram_updates(json: &[u8]) {
        crate::approval::telegram::parse_updates_for_fuzzing(json);
    }
}
