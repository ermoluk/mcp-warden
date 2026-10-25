use crate::config::{Config, Preset};
use crate::error::{Result, WardenError};
use crate::presets::PresetSource;
use std::path::PathBuf;

pub struct TomlSource {
    path: PathBuf,
}

impl TomlSource {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn load(&self) -> Result<Config> {
        let raw = std::fs::read_to_string(&self.path).map_err(WardenError::Io)?;
        toml::from_str(&raw).map_err(|e| WardenError::Config(e.to_string()))
    }
}

impl PresetSource for TomlSource {
    fn list(&self) -> Result<Vec<Preset>> {
        Ok(self.load()?.preset)
    }

    fn find(&self, name: &str) -> Result<Option<Preset>> {
        Ok(self.load()?.preset.into_iter().find(|p| p.name == name))
    }
}
