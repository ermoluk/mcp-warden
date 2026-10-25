use crate::error::Result;
use crate::keychain::KeychainStore;
use crate::secret::Secret;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Default)]
pub struct InMemoryKeychain {
    inner: Mutex<HashMap<String, String>>,
}

impl InMemoryKeychain {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeychainStore for InMemoryKeychain {
    fn set(&self, name: &str, value: Secret) -> Result<()> {
        self.inner
            .lock()
            .unwrap()
            .insert(name.to_string(), value.expose().to_string());
        Ok(())
    }

    fn get(&self, name: &str) -> Result<Option<Secret>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .map(Secret::new))
    }

    fn delete(&self, name: &str) -> Result<()> {
        self.inner.lock().unwrap().remove(name);
        Ok(())
    }

    fn list_names(&self) -> Result<Vec<String>> {
        Ok(self.inner.lock().unwrap().keys().cloned().collect())
    }
}
