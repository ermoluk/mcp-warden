use crate::error::{Result, WardenError};
use crate::keychain::KeychainStore;
use crate::secret::Secret;
use std::sync::{Arc, Once};

const SERVICE: &str = "mcp-warden";
const INDEX_KEY: &str = "__mcp_warden_index__";
const SEPARATOR: char = '\u{1f}';

static INIT: Once = Once::new();

// The OS credential store, linked directly rather than through the `keyring`
// crate: keyring 4.2 moved `use_native_store` behind a feature in a minor
// release, which broke every `cargo install` without `--locked`. These are the
// stores keyring 4.0's `use_native_store(false)` picked, with the same default
// configuration, so entries written by earlier versions stay readable.
#[cfg(target_os = "macos")]
fn native_store() -> keyring_core::Result<Arc<keyring_core::CredentialStore>> {
    Ok(apple_native_keyring_store::keychain::Store::new()?)
}

#[cfg(target_os = "windows")]
fn native_store() -> keyring_core::Result<Arc<keyring_core::CredentialStore>> {
    Ok(windows_native_keyring_store::Store::new()?)
}

#[cfg(target_os = "linux")]
fn native_store() -> keyring_core::Result<Arc<keyring_core::CredentialStore>> {
    Ok(linux_keyutils_keyring_store::Store::new()?)
}

// keyring fell back to a plaintext sample store here; refuse instead.
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn native_store() -> keyring_core::Result<Arc<keyring_core::CredentialStore>> {
    Err(keyring_core::Error::NotSupportedByStore(
        "no OS keychain support on this platform (macOS, Windows and Linux only)".to_string(),
    ))
}

fn ensure_store() -> Result<()> {
    let mut init_err: Option<String> = None;
    INIT.call_once(|| match native_store() {
        Ok(store) => keyring_core::set_default_store(store),
        Err(e) => init_err = Some(e.to_string()),
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
        write_index_to(&entry, names)
    }
}

/// Store the index of secret names in `entry`. An empty index deletes the
/// entry instead: keyutils, the Linux store, can't hold an empty value, so
/// writing one made removing the last secret fail.
fn write_index_to(entry: &keyring_core::Entry, names: &[String]) -> Result<()> {
    if names.is_empty() {
        return match entry.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(e) => Err(WardenError::Keychain(e.to_string())),
        };
    }
    entry
        .set_password(&names.join(&SEPARATOR.to_string()))
        .map_err(|e| WardenError::Keychain(e.to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use keyring_core::api::CredentialStoreApi;

    #[test]
    fn an_empty_index_leaves_no_entry() {
        // The Linux store (keyutils) refuses empty values, so removing the
        // last secret failed with "cannot be empty" and left its name in the
        // index. An empty index must leave no index entry at all.
        let store = keyring_core::mock::Store::new().unwrap();
        let entry = store.build(SERVICE, INDEX_KEY, None).unwrap();
        write_index_to(&entry, &["a".into(), "b".into()]).unwrap();
        assert_eq!(entry.get_password().unwrap(), "a\u{1f}b");
        write_index_to(&entry, &[]).unwrap();
        assert!(
            matches!(entry.get_password(), Err(keyring_core::Error::NoEntry)),
            "{:?}",
            entry.get_password()
        );
        // Already gone: still fine.
        write_index_to(&entry, &[]).unwrap();
    }
}
