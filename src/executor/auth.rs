//! The credential an HTTP call carries, from the keychain to the request.
//!
//! [`load`] reads every keychain entry the preset's `auth` names, and is
//! called only once the call has passed its checks and its approval
//! (invariant 3). [`Credential::apply`] puts the credential on the request
//! in the form `auth` says, and [`Credential::forms`] gives every form it
//! was sent in, so a response or error that echoes it can be scrubbed
//! (invariants 1–2) before the plaintext is dropped (invariant 8). Shared
//! by `proxy_http` and `doctor --deep`.

use super::credential_echo::CredentialForms;
use mcp_warden_core::config::{Auth, Preset};
use mcp_warden_core::error::{Result, WardenError};
use mcp_warden_core::keychain::KeychainStore;
use mcp_warden_core::secret::Secret;

/// The credential material of one call, zeroized on drop.
pub struct Credential {
    auth: Auth,
    /// One per entry of `auth.secrets()`, in that order.
    secrets: Vec<Secret>,
}

/// Read the preset's credential from the keychain.
pub fn load(kc: &dyn KeychainStore, preset: &Preset) -> Result<Credential> {
    let auth = preset
        .auth
        .clone()
        .ok_or_else(|| WardenError::Validation("preset missing auth".into()))?;
    let secrets = auth
        .secrets()
        .into_iter()
        .map(|name| {
            kc.get(name)?.ok_or_else(|| WardenError::MissingSecret {
                preset: preset.name.clone(),
                secret: name.to_string(),
            })
        })
        .collect::<Result<_>>()?;
    Ok(Credential { auth, secrets })
}

impl Credential {
    /// The request with the credential on it.
    pub fn apply(&self, b: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let secret = self.secrets[0].expose();
        match &self.auth {
            Auth::Bearer { .. } => b.bearer_auth(secret),
            Auth::Header { name, prefix, .. } => {
                let value = match prefix {
                    Some(p) => format!("{p}{secret}"),
                    None => secret.to_string(),
                };
                b.header(name, value)
            }
            Auth::Basic { username, .. } => b.basic_auth(username, Some(secret)),
        }
    }

    /// Every form the credential was sent in, for scrubbing what comes back.
    pub fn forms(&self) -> CredentialForms {
        CredentialForms::http(&Some(self.auth.clone()), &self.secrets[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_warden_core::keychain::memory::InMemoryKeychain;

    fn preset(auth: &str) -> Preset {
        toml::from_str(&format!(
            r#"
            name = "p"
            type = "http"
            description = "x"
            base_url = "https://api.example.com"
            auth = {auth}
            allowed_methods = ["GET"]
            approval = "prompt"
            "#
        ))
        .unwrap()
    }

    #[test]
    fn every_named_entry_must_exist() {
        let kc = InMemoryKeychain::new();
        let p = preset(r#"{ type = "bearer", secret = "tok" }"#);
        let err = load(&kc, &p).err().unwrap();
        assert!(matches!(err, WardenError::MissingSecret { .. }), "{err}");
        kc.set("tok", Secret::new("s3cret".into())).unwrap();
        let c = load(&kc, &p).unwrap();
        let req = c
            .apply(reqwest::Client::new().get("https://api.example.com/x"))
            .build()
            .unwrap();
        assert_eq!(req.headers()["authorization"], "Bearer s3cret");
    }
}
