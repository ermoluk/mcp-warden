use mcp_warden_core::error::{Result, WardenError};
use std::fs;
use std::path::Path;

const TEMPLATE: &str = "\
# mcp-warden configuration
# Define presets — named, scoped actions an AI agent may perform.
# See docs/claude-code-setup.md and docs/cursor-setup.md for wiring.

# Example (uncomment + fill in):
#
# [[preset]]
# name = \"github-read\"
# type = \"http\"
# description = \"GitHub API (read-only)\"
# base_url = \"https://api.github.com\"
# auth = { type = \"bearer\", secret = \"gh_pat\" }
# allowed_methods = [\"GET\"]
# approval = \"auto\"
";

pub fn run(config_dir: &Path) -> Result<()> {
    fs::create_dir_all(config_dir).map_err(WardenError::Io)?;
    let path = config_dir.join("config.toml");
    if path.exists() {
        eprintln!("Config already exists at {}", path.display());
        return Ok(());
    }
    fs::write(&path, TEMPLATE).map_err(WardenError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    eprintln!("Initialized config at {}", path.display());
    eprintln!("Next: `mcp-warden secret add <name>` then `mcp-warden preset add ...`.");
    Ok(())
}
