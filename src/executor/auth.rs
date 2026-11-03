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
    /// OAuth2: the token minted for this call by [`Credential::prepare`].
    minted: Option<super::oauth2::Minted>,
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
    Ok(Credential {
        auth,
        secrets,
        minted: None,
    })
}

impl Credential {
    /// Whatever must happen before the request can carry the credential:
    /// for OAuth2, mint this call's access token (`state_dir` holds the
    /// lock files shared with other mcp-warden processes).
    pub async fn prepare(
        &mut self,
        kc: &dyn KeychainStore,
        state_dir: Option<&std::path::Path>,
        preset: &Preset,
    ) -> Result<()> {
        if let Auth::Oauth2 { client_secret, .. } = &self.auth {
            let secret = client_secret.as_ref().map(|_| &self.secrets[0]);
            self.minted = Some(super::oauth2::mint(kc, state_dir, preset, secret).await?);
        }
        Ok(())
    }

    /// The request with the credential on it.
    pub fn apply(&self, b: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            Auth::Bearer { .. } => b.bearer_auth(self.secrets[0].expose()),
            Auth::Header { name, prefix, .. } => {
                let secret = self.secrets[0].expose();
                let value = match prefix {
                    Some(p) => format!("{p}{secret}"),
                    None => secret.to_string(),
                };
                b.header(name, value)
            }
            Auth::Basic { username, .. } => b.basic_auth(username, Some(self.secrets[0].expose())),
            Auth::Query { .. } => b,
            Auth::Oauth2 { .. } => match &self.minted {
                Some(m) => b.bearer_auth(m.access_token.expose()),
                None => b,
            },
        }
    }

    /// For `query` auth, the credential's parameter, appended after every
    /// other: the agent's pairs are already on `url`.
    pub fn apply_to_url(&self, url: &mut url::Url) {
        if let Auth::Query { name, .. } = &self.auth {
            url.query_pairs_mut()
                .append_pair(name, self.secrets[0].expose());
        }
    }

    /// Every form the credential was sent in, for scrubbing what comes back:
    /// for OAuth2 also the client secret and every refresh token the call
    /// saw, which a hostile upstream may have been handed.
    pub fn forms(&self) -> CredentialForms {
        match &self.auth {
            Auth::Oauth2 { .. } => {
                let bearer = Some(Auth::Bearer {
                    secret: String::new(),
                });
                let minted = self.minted.iter().flat_map(|m| {
                    std::iter::once(CredentialForms::http(&bearer, &m.access_token))
                        .chain(m.refresh_tokens.iter().map(CredentialForms::raw))
                });
                CredentialForms::merge(
                    self.secrets
                        .iter()
                        .map(CredentialForms::raw)
                        .chain(minted)
                        .collect::<Vec<_>>(),
                )
            }
            auth => CredentialForms::http(&Some(auth.clone()), &self.secrets[0]),
        }
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
