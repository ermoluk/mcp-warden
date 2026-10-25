use crate::error::{Result, WardenError};
use crate::keychain::KeychainStore;
use crate::secret::Secret;
use std::sync::Once;

const SERVICE: &str = "mcp-warden";
const INDEX_KEY: &str = "__mcp_warden_index__";
const SEPARATOR: char = '\u{1f}';

static INIT: Once = Once::new();

fn ensure_store() -> Result<()> {
    let mut init_err: Option<String> = None;
    INIT.call_once(|| {
        if let Err(e) = keyring::use_native_store(false) {
            init_err = Some(e.to_string());
        }
    });
    if let Some(e) = init_err {
        return Err(WardenError::Keychain(e));
    }
    Ok(())
}

pub struct SystemKeychain;

impl SystemKeychain {
    pub fn new() -> Self {
        Self
    }

    fn read_index(&self) -> Vec<String> {
        if ensure_store().is_err() {
            return vec![];
        }
        let entry = match keyring_core::Entry::new(SERVICE, INDEX_KEY) {
            Ok(e) => e,
            Err(_) => return vec![],
        };
        match entry.get_password() {
            Ok(s) if !s.is_empty() => s.split(SEPARATOR).map(String::from).collect(),
            _ => vec![],
        }
    }

    fn write_index(&self, names: &[String]) -> Result<()> {
        ensure_store()?;
        let entry = keyring_core::Entry::new(SERVICE, INDEX_KEY)
            .map_err(|e| WardenError::Keychain(e.to_string()))?;
        entry
            .set_password(&names.join(&SEPARATOR.to_string()))
            .map_err(|e| WardenError::Keychain(e.to_string()))
    }
}

impl Default for SystemKeychain {
    fn default() -> Self {
        Self::new()
    }
}

impl KeychainStore for SystemKeychain {
    fn set(&self, name: &str, value: Secret) -> Result<()> {
        ensure_store()?;
        let entry = keyring_core::Entry::new(SERVICE, name)
            .map_err(|e| WardenError::Keychain(e.to_string()))?;
        entry
            .set_password(value.expose())
            .map_err(|e| WardenError::Keychain(e.to_string()))?;
        let mut idx = self.read_index();
        if !idx.iter().any(|n| n == name) {
            idx.push(name.to_string());
            self.write_index(&idx)?;
        }
        Ok(())
    }

    fn get(&self, name: &str) -> Result<Option<Secret>> {
        ensure_store()?;
        let entry = keyring_core::Entry::new(SERVICE, name)
            .map_err(|e| WardenError::Keychain(e.to_string()))?;
        match entry.get_password() {
            Ok(s) => Ok(Some(Secret::new(s))),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(e) => Err(WardenError::Keychain(e.to_string())),
        }
    }

    fn delete(&self, name: &str) -> Result<()> {
        ensure_store()?;
        let entry = keyring_core::Entry::new(SERVICE, name)
            .map_err(|e| WardenError::Keychain(e.to_string()))?;
        let _ = entry.delete_credential();
        let idx: Vec<String> = self
            .read_index()
            .into_iter()
            .filter(|n| n != name)
            .collect();
        self.write_index(&idx)
    }

    fn list_names(&self) -> Result<Vec<String>> {
        Ok(self.read_index())
    }
}
