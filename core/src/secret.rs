use zeroize::Zeroizing;

#[derive(Clone)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak_value() {
        let s = Secret::new("hunter2".into());
        assert_eq!(format!("{:?}", s), "Secret(***)");
        assert_eq!(format!("{}", s), "***");
    }

    #[test]
    fn expose_returns_underlying() {
        let s = Secret::new("hunter2".into());
        assert_eq!(s.expose(), "hunter2");
    }
}
