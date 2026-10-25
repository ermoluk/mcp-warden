use crate::error::Result;
use crate::secret::Secret;

pub mod memory;
pub mod system;

pub trait KeychainStore: Send + Sync {
    fn set(&self, name: &str, value: Secret) -> Result<()>;
    fn get(&self, name: &str) -> Result<Option<Secret>>;
    fn delete(&self, name: &str) -> Result<()>;
    fn list_names(&self) -> Result<Vec<String>>;
}

#[cfg(test)]
mod tests {
    use super::memory::InMemoryKeychain;
    use super::*;

    #[test]
    fn round_trip() {
        let kc = InMemoryKeychain::new();
        kc.set("api_key", Secret::new("abc123".into())).unwrap();
        let got = kc.get("api_key").unwrap().unwrap();
        assert_eq!(got.expose(), "abc123");
    }

    #[test]
    fn list_names_returns_only_names() {
        let kc = InMemoryKeychain::new();
        kc.set("a", Secret::new("1".into())).unwrap();
        kc.set("b", Secret::new("2".into())).unwrap();
        let mut names = kc.list_names().unwrap();
        names.sort();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn delete_removes() {
        let kc = InMemoryKeychain::new();
        kc.set("k", Secret::new("v".into())).unwrap();
        kc.delete("k").unwrap();
        assert!(kc.get("k").unwrap().is_none());
    }

    #[test]
    fn get_missing_is_none_not_err() {
        let kc = InMemoryKeychain::new();
        assert!(kc.get("nope").unwrap().is_none());
    }
}
