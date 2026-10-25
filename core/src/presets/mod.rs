use crate::config::Preset;
use crate::error::Result;

pub mod toml_source;

pub trait PresetSource: Send + Sync {
    fn list(&self) -> Result<Vec<Preset>>;
    fn find(&self, name: &str) -> Result<Option<Preset>>;
}

#[cfg(test)]
mod tests {
    use super::toml_source::TomlSource;
    use super::*;
    use std::io::Write;

    #[test]
    fn loads_presets_from_toml() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"
            [[preset]]
            name = "p1"
            type = "http"
            description = "x"
            base_url = "https://api.example.com"
            auth = {{ type = "bearer", secret = "k" }}
            allowed_methods = ["GET"]
            approval = "auto"
        "#
        )
        .unwrap();
        let src = TomlSource::new(f.path().to_path_buf());
        let presets = src.list().unwrap();
        assert_eq!(presets.len(), 1);
        assert_eq!(src.find("p1").unwrap().unwrap().name, "p1");
        assert!(src.find("missing").unwrap().is_none());
    }

    #[test]
    fn empty_file_yields_empty_list() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let src = TomlSource::new(f.path().to_path_buf());
        assert!(src.list().unwrap().is_empty());
    }
}
