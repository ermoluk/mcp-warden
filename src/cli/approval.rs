use clap::Args;
use mcp_warden_core::config::{ApprovalPolicy, Config};
use mcp_warden_core::error::{Result, WardenError};
use std::fs;
use std::path::Path;

#[derive(Debug, Args)]
pub struct ApprovalArgs {
    /// Preset name.
    pub preset: String,
    /// New approval policy.
    #[arg(value_parser = ["auto", "prompt", "deny"])]
    pub policy: String,
    /// Required when setting `auto` (spec §9.4).
    #[arg(long)]
    pub confirm_auto: bool,
    /// Time-boxed approval window for `policy=prompt`.
    ///
    /// When set to a positive value, the approval prompt offers an
    /// "Approve for N seconds" choice that suppresses re-prompting for
    /// subsequent calls to the same preset+action within the window.
    /// `--window 0` removes any previously-configured window.
    /// Has no effect when policy is `auto` or `deny`.
    #[arg(long)]
    pub window: Option<u64>,
}

pub fn run(args: ApprovalArgs, config_path: &Path) -> Result<()> {
    if args.policy == "auto" && !args.confirm_auto {
        return Err(WardenError::Validation(
            "setting policy=auto requires --confirm-auto (spec §9.4)".into(),
        ));
    }
    let raw = fs::read_to_string(config_path).map_err(WardenError::Io)?;
    let mut cfg: Config = toml::from_str(&raw).map_err(|e| WardenError::Config(e.to_string()))?;
    let p = cfg
        .preset
        .iter_mut()
        .find(|p| p.name == args.preset)
        .ok_or_else(|| WardenError::PresetNotFound(args.preset.clone()))?;
    p.approval = match args.policy.as_str() {
        "auto" => ApprovalPolicy::Auto,
        "deny" => ApprovalPolicy::Deny,
        _ => ApprovalPolicy::Prompt,
    };
    // Window only makes sense for prompt; clear it otherwise so an
    // operator switching auto→prompt→auto doesn't carry a stale value.
    if p.approval != ApprovalPolicy::Prompt {
        p.approval_window_seconds = None;
    } else if let Some(w) = args.window {
        p.approval_window_seconds = if w == 0 { None } else { Some(w) };
    }
    let window_summary = match p.approval_window_seconds {
        Some(n) => format!(" (window: {n}s)"),
        None => String::new(),
    };
    let toml_str = toml::to_string_pretty(&cfg).map_err(|e| WardenError::Config(e.to_string()))?;
    fs::write(config_path, toml_str).map_err(WardenError::Io)?;
    eprintln!(
        "Set approval policy for '{}' to {}{}.",
        args.preset, args.policy, window_summary
    );
    Ok(())
}
