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
            // Signed once the request is complete: `sign`.
            Auth::AwsSigv4 { .. } => b,
        }
    }

    /// For `aws_sigv4`, sign the finished request — method, URL with every
    /// query parameter, headers and body — as at `now`, adding the
    /// `Authorization`, `x-amz-date` and (with a session token)
    /// `x-amz-security-token` headers; S3 also gets
    /// `x-amz-content-sha256`. Runs after every allow-list check and after
    /// the approval, like every credential use (invariant 3).
    pub fn sign(&self, request: &mut reqwest::Request, now: std::time::SystemTime) -> Result<()> {
        use aws_sigv4::http_request::{
            PayloadChecksumKind, SignableBody, SignableRequest, SigningSettings, sign,
        };
        let Auth::AwsSigv4 {
            region,
            service,
            session_token,
            ..
        } = &self.auth
        else {
            return Ok(());
        };
        let bad = |e: &dyn std::fmt::Display| WardenError::Executor(format!("aws_sigv4: {e}"));
        let identity = aws_credential_types::Credentials::new(
            self.secrets[0].expose(),
            self.secrets[1].expose(),
            session_token
                .as_ref()
                .map(|_| self.secrets[2].expose().to_string()),
            None,
            "mcp-warden",
        )
        .into();
        let mut settings = SigningSettings::default();
        if service == "s3" {
            settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        }
        let params = aws_sigv4::sign::v4::SigningParams::builder()
            .identity(&identity)
            .region(region)
            .name(service)
            .time(now)
            .settings(settings)
            .build()
            .map_err(|e| bad(&e))?
            .into();
        let body = request.body().and_then(|b| b.as_bytes()).unwrap_or(&[]);
        let headers = request
            .headers()
            .iter()
            .map(|(k, v)| v.to_str().map(|v| (k.as_str(), v)))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| bad(&e))?;
        let signable = SignableRequest::new(
            request.method().as_str(),
            request.url().as_str(),
            headers.into_iter(),
            SignableBody::Bytes(body),
        )
        .map_err(|e| bad(&e))?;
        let (instructions, _) = sign(signable, &params).map_err(|e| bad(&e))?.into_parts();
        let added: Vec<(String, String)> = instructions
            .headers()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        for (name, value) in added {
            let name =
                reqwest::header::HeaderName::from_bytes(name.as_bytes()).map_err(|e| bad(&e))?;
            let value = reqwest::header::HeaderValue::from_str(&value).map_err(|e| bad(&e))?;
            request.headers_mut().insert(name, value);
        }
        Ok(())
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
            // Every key; the signature is derived from them, not one.
            Auth::AwsSigv4 { .. } => CredentialForms::merge(
                self.secrets
                    .iter()
                    .map(CredentialForms::raw)
                    .collect::<Vec<_>>(),
            ),
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

    /// AWS's own test vector (aws-sig-v4-test-suite, `get-vanilla`): the
    /// signature must be exactly theirs.
    #[test]
    fn sigv4_matches_the_aws_test_suite() {
        let kc = InMemoryKeychain::new();
        kc.set("akid", Secret::new("AKIDEXAMPLE".into())).unwrap();
        kc.set(
            "sk",
            Secret::new("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into()),
        )
        .unwrap();
        let mut p = preset(
            r#"{ type = "aws_sigv4", region = "us-east-1", service = "service", access_key_id = "akid", secret_access_key = "sk" }"#,
        );
        p.base_url = Some("https://example.amazonaws.com".into());
        let c = load(&kc, &p).unwrap();
        let mut req = reqwest::Client::new()
            .get("https://example.amazonaws.com/")
            .build()
            .unwrap();
        let at = chrono::DateTime::parse_from_rfc3339("2015-08-30T12:36:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        c.sign(&mut req, at.into()).unwrap();
        assert_eq!(req.headers()["x-amz-date"], "20150830T123600Z");
        assert_eq!(
            req.headers()["authorization"],
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
        assert!(req.headers().get("x-amz-security-token").is_none());
    }

    #[test]
    fn sigv4_sends_the_session_token_and_s3_payload_hash() {
        let kc = InMemoryKeychain::new();
        for (k, v) in [
            ("akid", "AKIDEXAMPLE"),
            ("sk", "secret"),
            ("st", "session-token"),
        ] {
            kc.set(k, Secret::new(v.into())).unwrap();
        }
        let p = preset(
            r#"{ type = "aws_sigv4", region = "eu-central-1", service = "s3", access_key_id = "akid", secret_access_key = "sk", session_token = "st" }"#,
        );
        let c = load(&kc, &p).unwrap();
        let mut req = reqwest::Client::new()
            .get("https://bucket.s3.eu-central-1.amazonaws.com/key")
            .build()
            .unwrap();
        c.sign(&mut req, std::time::SystemTime::now()).unwrap();
        assert_eq!(req.headers()["x-amz-security-token"], "session-token");
        assert_eq!(
            req.headers()["x-amz-content-sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let auth = req.headers()["authorization"].to_str().unwrap();
        assert!(auth.contains("/eu-central-1/s3/aws4_request"), "{auth}");
        assert!(!auth.contains("secret"), "{auth}");
    }
}
