use crate::config::Preset;
use crate::error::Result;
use crate::presets::PresetSource;

/// Presets captured once and never re-read.
///
/// The MCP server builds this from the `Config` it validated at startup
/// (invariant 10: load-once-and-freeze), so a later edit to `config.toml` —
/// a new preset, `approval = "auto"`, a wider allow-list — has no effect
/// until the server restarts and validates it again.
pub struct FrozenSource {
    presets: Vec<Preset>,
}

impl FrozenSource {
    pub fn new(presets: Vec<Preset>) -> Self {
        Self { presets }
    }
}

impl PresetSource for FrozenSource {
    fn list(&self) -> Result<Vec<Preset>> {
        Ok(self.presets.clone())
    }

    fn find(&self, name: &str) -> Result<Option<Preset>> {
        Ok(self.presets.iter().find(|p| p.name == name).cloned())
    }
}
