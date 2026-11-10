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
pub mod osenv;
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

    /// A named command filled in from arbitrary values, against a preset
    /// whose parameters accept anything their type allows. What it renders
    /// must pass the shell-syntax check and fit the length limit.
    pub fn named_command(command: &str, params: &serde_json::Value) -> Option<String> {
        use std::sync::LazyLock;
        static PRESET: LazyLock<mcp_warden_core::config::Preset> = LazyLock::new(|| {
            toml::from_str(
                r#"
                name = "wide"
                type = "ssh"
                description = "x"
                host = "h"
                user = "u"
                secret = "k"
                approval = "prompt"
                [[commands]]
                name = "word"
                description = "x"
                template = "echo {v} {w}"
                params.v = { type = "string", pattern = ".*" }
                params.w = { type = "path", pattern = ".*" }
                [[commands]]
                name = "num"
                description = "x"
                template = "head -n {n} --color={c} f"
                params.n = { type = "int", min = 0, max = 9223372036854775807 }
                params.c = { type = "enum", values = ["auto", "never"] }
                "#,
            )
            .expect("fixture")
        });
        let params: std::collections::BTreeMap<String, serde_json::Value> =
            serde_json::from_value(params.clone()).ok()?;
        mcp_warden_core::commands::render(&PRESET, command, &params)
            .ok()
            .map(|r| r.command)
    }

    /// An OAuth2 token endpoint's answer, as `mint` reads it: the access
    /// token and any rotated refresh token, or an error.
    pub fn oauth_token_answer(status: u16, body: &[u8]) -> Option<(String, Option<String>)> {
        crate::executor::oauth2::parse_answer(status, body)
            .ok()
            .map(|(a, r)| (a.expose().to_string(), r.map(|r| r.expose().to_string())))
    }

    /// The audit chain check over arbitrary chain rows.
    pub fn audit_verify(rows: &[(i64, i64, String, String)]) {
        let _ = mcp_warden_core::audit::chain::verify_rows_for_fuzzing(rows);
    }

    /// A Telegram `getUpdates` result as the bot parses it, and the checks
    /// it applies to button data and `/lock` messages.
    pub fn telegram_updates(json: &[u8]) {
        crate::approval::telegram::parse_updates_for_fuzzing(json);
    }
}
