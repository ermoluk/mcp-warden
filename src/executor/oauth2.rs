//! OAuth 2.0 access tokens for `auth = { type = "oauth2", … }` presets.
//!
//! A token is minted for every call and dropped after it: nothing is cached
//! in memory between calls (invariant 8). The token endpoint is treated as
//! untrusted: no redirects are followed, at most 64 KiB of answer is read,
//! a call that stalls ends after 15 seconds, and an error says only the
//! status and the RFC 6749 `error` code — never the body or its
//! `error_description`, which a hostile endpoint could fill with the
//! credentials it was sent.

use mcp_warden_core::config::{Auth, ClientAuth, OAuth2Grant, Preset};
use mcp_warden_core::error::{Result, WardenError};
use mcp_warden_core::fslock::{FileLock, name_for};
use mcp_warden_core::keychain::KeychainStore;
use mcp_warden_core::secret::Secret;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// The most of a token endpoint's answer that is read.
pub const MAX_TOKEN_RESPONSE_BYTES: u64 = 64 * 1024;
/// The longest access or refresh token accepted.
pub const MAX_TOKEN_CHARS: usize = 16 * 1024;
/// How long a token request may take, at most.
pub const MAX_TOKEN_SECONDS: u64 = 15;
/// How long a call waits for another process using the same refresh token.
const LOCK_WAIT: Duration = Duration::from_secs(30);

/// What a token request produced.
pub struct Minted {
    pub access_token: Secret,
    /// The refresh tokens this call saw — read from the keychain, or sent
    /// back by the endpoint — so an echo of any of them is scrubbed.
    pub refresh_tokens: Vec<Secret>,
}

/// Mint an access token for `preset`. `client_secret` was read from the
/// keychain by the caller; a refresh token is read here, under a lock
/// shared with every other mcp-warden process using the same entry
/// (`state_dir`/locks), so two of them never spend the same token.
pub async fn mint(
    kc: &dyn KeychainStore,
    state_dir: Option<&Path>,
    preset: &Preset,
    client_secret: Option<&Secret>,
) -> Result<Minted> {
    let Some(Auth::Oauth2 {
        grant,
        token_url,
        client_id,
        refresh_token,
        scopes,
        client_auth,
        ..
    }) = &preset.auth
    else {
        return Err(WardenError::Validation(
            "preset is not an oauth2 preset".into(),
        ));
    };
    let mut form: Vec<(&str, String)> = Vec::new();
    let mut refresh_tokens = Vec::new();
    let _guards = match (grant, refresh_token) {
        (OAuth2Grant::RefreshToken, Some(entry)) => {
            let guards = lock(state_dir, entry).await?;
            let token = kc.get(entry)?.ok_or_else(|| WardenError::MissingSecret {
                preset: preset.name.clone(),
                secret: entry.clone(),
            })?;
            form.push(("grant_type", "refresh_token".into()));
            form.push(("refresh_token", token.expose().to_string()));
            refresh_tokens.push(token);
            Some(guards)
        }
        (OAuth2Grant::RefreshToken, None) => {
            return Err(WardenError::Validation(
                "oauth2 refresh_token grant without refresh_token".into(),
            ));
        }
        (OAuth2Grant::ClientCredentials, _) => {
            form.push(("grant_type", "client_credentials".into()));
            None
        }
    };
    if !scopes.is_empty() {
        form.push(("scope", scopes.join(" ")));
    }

    let timeout = preset
        .timeout_seconds
        .map_or(MAX_TOKEN_SECONDS, |t| t.clamp(1, MAX_TOKEN_SECONDS));
    // A loopback `http://` token endpoint gets the client secret and the
    // refresh token in clear text: never through a proxy (audit 2026-11-09,
    // H5).
    let client = crate::executor::http::direct_if_plain(
        reqwest::Client::builder(),
        token_url.starts_with("http://"),
    )
    .redirect(reqwest::redirect::Policy::none())
    .timeout(Duration::from_secs(timeout))
    .user_agent(format!("mcp-warden/{}", env!("CARGO_PKG_VERSION")))
    .build()
    .map_err(|e| WardenError::Executor(e.to_string()))?;
    let mut request = client.post(token_url);
    match (client_auth, client_secret) {
        // RFC 6749 §2.3.1: both form-encoded, then HTTP Basic.
        (ClientAuth::Basic, Some(secret)) => {
            request =
                request.basic_auth(form_encode(client_id), Some(form_encode(secret.expose())));
        }
        (ClientAuth::Body, Some(secret)) => {
            form.push(("client_id", client_id.clone()));
            form.push(("client_secret", secret.expose().to_string()));
        }
        (_, None) => form.push(("client_id", client_id.clone())),
    }
    let request = request.form(&form);
    for (_, value) in &mut form {
        zeroize::Zeroize::zeroize(value);
    }

    let response = request.send().await.map_err(|e| {
        WardenError::Executor(format!(
            "oauth2 token endpoint: {}",
            super::http::error_text(e)
        ))
    })?;
    let status = response.status().as_u16();
    let body = super::response::read_limited(response, MAX_TOKEN_RESPONSE_BYTES)
        .await
        .ok_or_else(|| {
            WardenError::Executor(format!(
                "oauth2 token endpoint answered more than {MAX_TOKEN_RESPONSE_BYTES} bytes"
            ))
        })?;
    let (access_token, rotated) = parse_answer(status, &zeroize::Zeroizing::new(body))?;
    if let Some(rotated) = rotated {
        // A provider that rotates refresh tokens has just made the stored
        // one unusable, so the new one is written back while the lock is
        // still held. If that fails, so does the call: going on would leave
        // a dead token in the keychain without anyone knowing.
        if let (OAuth2Grant::RefreshToken, Some(entry)) = (grant, refresh_token)
            && refresh_tokens
                .first()
                .is_some_and(|old| old.expose() != rotated.expose())
        {
            store_rotated(kc, &preset.name, entry, &rotated)?;
        }
        refresh_tokens.push(rotated);
    }
    Ok(Minted {
        access_token,
        refresh_tokens,
    })
}

fn store_rotated(kc: &dyn KeychainStore, preset: &str, entry: &str, token: &Secret) -> Result<()> {
    // Config validation already keeps reserved names out; never write one.
    if mcp_warden_core::stamp::is_reserved_name(entry) {
        return Err(WardenError::Validation(format!(
            "preset '{preset}': refusing to write a rotated refresh token to '{entry}'"
        )));
    }
    kc.set(entry, Secret::new(token.expose().to_string()))
        .map_err(|e| {
            tracing::error!(
                "preset '{preset}': the provider rotated the refresh token but it could not be \
                 stored in '{entry}': {e}"
            );
            WardenError::Executor(format!(
                "the provider rotated the refresh token, but storing it in '{entry}' failed \
                 ({e}); the stored token may no longer work — authorise again and run \
                 `mcp-warden secret add {entry}`"
            ))
        })
}

/// The token endpoint's answer, read: the access token and any rotated
/// refresh token, or the error to report — the status and the RFC 6749
/// `error` code, never anything else from the body. Pure, so it can be
/// fuzzed.
pub fn parse_answer(status: u16, body: &[u8]) -> Result<(Secret, Option<Secret>)> {
    let json: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    if status != 200 {
        let code = json
            .get("error")
            .and_then(Value::as_str)
            .filter(|c| {
                !c.is_empty()
                    && c.len() <= 64
                    && c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
            })
            .map(|c| format!(" ({c})"))
            .unwrap_or_default();
        return Err(WardenError::Executor(format!(
            "oauth2 token endpoint answered {status}{code}"
        )));
    }
    let access_token = token_field(&json, "access_token")?.ok_or_else(|| {
        WardenError::Executor("oauth2 token endpoint sent no access_token".into())
    })?;
    if let Some(kind) = json.get("token_type")
        && !kind
            .as_str()
            .is_some_and(|k| k.eq_ignore_ascii_case("bearer"))
    {
        return Err(WardenError::Executor(
            "oauth2 token endpoint sent a token_type other than bearer".into(),
        ));
    }
    Ok((access_token, token_field(&json, "refresh_token")?))
}

/// A token string from the endpoint's answer: printable ASCII without
/// spaces, at most [`MAX_TOKEN_CHARS`]. A token that is anything else —
/// with a newline that could split a header, say — is refused.
fn token_field(json: &Value, field: &str) -> Result<Option<Secret>> {
    let Some(value) = json.get(field) else {
        return Ok(None);
    };
    match value.as_str() {
        Some(t)
            if !t.is_empty()
                && t.len() <= MAX_TOKEN_CHARS
                && t.bytes().all(|b| (0x21..=0x7e).contains(&b)) =>
        {
            Ok(Some(Secret::new(t.to_string())))
        }
        _ => Err(WardenError::Executor(format!(
            "oauth2 token endpoint sent a malformed {field}"
        ))),
    }
}

/// `application/x-www-form-urlencoded`, as RFC 6749 wants for Basic.
fn form_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Held while a refresh token is spent: a lock within this process, and,
/// with a config dir, a lock file every mcp-warden process takes.
struct Guards {
    _process: tokio::sync::OwnedMutexGuard<()>,
    _file: Option<FileLock>,
}

async fn lock(state_dir: Option<&Path>, entry: &str) -> Result<Guards> {
    static IN_PROCESS: OnceLock<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> =
        OnceLock::new();
    let mutex = IN_PROCESS
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| WardenError::Executor("oauth2 lock poisoned".into()))?
        .entry(entry.to_string())
        .or_default()
        .clone();
    let process = tokio::time::timeout(LOCK_WAIT, mutex.lock_owned())
        .await
        .map_err(|_| {
            WardenError::Executor("another call held the oauth2 refresh token too long".into())
        })?;
    let file = match state_dir {
        Some(dir) => {
            let dir = dir.join("locks");
            let name = name_for("oauth2", entry);
            Some(
                tokio::task::spawn_blocking(move || FileLock::acquire(&dir, &name, LOCK_WAIT))
                    .await
                    .map_err(|e| WardenError::Executor(e.to_string()))??,
            )
        }
        None => None,
    };
    Ok(Guards {
        _process: process,
        _file: file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::ActionExecutor;
    use crate::executor::http::{HttpRequest, HttpResponse, execute};
    use crate::testutil::{CountingApproval, CountingKeychain};
    use mcp_warden_core::approval::ApprovalDecision;
    use mcp_warden_core::audit::AuditSink;
    use mcp_warden_core::audit::sqlite_sink::LocalSqlite;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const CLIENT_SECRET: &str = "cs-SECRET-0123456789abcdef";
    const REFRESH_TOKEN: &str = "rt-REFRESH-0123456789abcdef";
    const ACCESS_TOKEN: &str = "at-ACCESS-0123456789abcdef";

    struct Setup {
        exec: ActionExecutor,
        audit: Arc<LocalSqlite>,
        preset: Preset,
        _dir: tempfile::TempDir,
    }

    /// An `auto` OAuth2 preset whose API is `api` and whose token endpoint
    /// is `token`; `auth` is the TOML of everything after `token_url`.
    fn setup(api: &MockServer, token: &MockServer, auth: &str) -> Setup {
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(LocalSqlite::open(&dir.path().join("audit.db")).unwrap());
        let exec = ActionExecutor::new(
            CountingKeychain::with(&[("cs", CLIENT_SECRET), ("rt", REFRESH_TOKEN)]),
            CountingApproval::new(ApprovalDecision::Approved),
            None,
            audit.clone(),
        );
        let preset: Preset = toml::from_str(&format!(
            r#"
            name = "drive"
            type = "http"
            description = "x"
            base_url = "{api}"
            allowed_methods = ["GET"]
            approval = "auto"
            timeout_seconds = 2
            [auth]
            type = "oauth2"
            token_url = "{token}/token"
            client_id = "app id"
            {auth}
            "#,
            api = api.uri(),
            token = token.uri(),
        ))
        .unwrap();
        Setup {
            exec,
            audit,
            preset,
            _dir: dir,
        }
    }

    /// Audit 2026-11-09, H5 (helper): mints a token from a loopback
    /// `http://` endpoint in a child process whose environment names a
    /// proxy.
    #[test]
    #[ignore = "helper: runs only in the child process the test below starts"]
    fn proxy_child() {
        let Ok(token_url) = std::env::var("PROXY_CHILD_TOKEN_URL") else {
            return;
        };
        let kc = mcp_warden_core::keychain::memory::InMemoryKeychain::new();
        let preset: Preset = toml::from_str(&format!(
            r#"
            name = "drive"
            type = "http"
            description = "x"
            base_url = "http://127.0.0.1:9"
            allowed_methods = ["GET"]
            approval = "auto"
            timeout_seconds = 2
            [auth]
            type = "oauth2"
            token_url = "{token_url}"
            client_id = "app"
            grant = "client_credentials"
            client_secret = "cs"
            "#
        ))
        .unwrap();
        let secret = Secret::new(CLIENT_SECRET.into());
        let _ = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(mint(&kc, None, &preset, Some(&secret)));
    }

    /// The token request to a loopback `http://` endpoint carries the
    /// client secret in clear text; a proxy the caller named never gets it.
    #[test]
    fn a_plain_http_token_request_never_goes_through_the_callers_proxy() {
        use std::io::Read;
        let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
        let token_port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let seen = Arc::new(std::sync::Mutex::new(String::new()));
        let seen_by_proxy = seen.clone();
        std::thread::spawn(move || {
            if let Ok((mut conn, _)) = proxy.accept() {
                conn.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut buf = [0u8; 8192];
                let n = conn.read(&mut buf).unwrap_or(0);
                *seen_by_proxy.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).into();
            }
        });
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "executor::oauth2::tests::proxy_child",
                "--ignored",
                "--test-threads=1",
            ])
            .env(
                "PROXY_CHILD_TOKEN_URL",
                format!("http://127.0.0.1:{token_port}/token"),
            )
            .env("HTTP_PROXY", &proxy_url)
            .env("http_proxy", &proxy_url)
            .env("ALL_PROXY", &proxy_url)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .output()
            .unwrap();
        assert!(out.status.success());
        let seen = seen.lock().unwrap().clone();
        assert!(
            seen.is_empty(),
            "the caller's proxy got the token request:\n{seen}"
        );
    }

    const REFRESH: &str = r#"grant = "refresh_token"
            client_secret = "cs"
            refresh_token = "rt""#;

    async fn get(s: &Setup) -> Result<HttpResponse> {
        execute(
            &s.exec,
            &s.preset,
            HttpRequest {
                preset_name: s.preset.name.clone(),
                path: "/files".into(),
                method: "GET".into(),
                body: None,
                query: None,
            },
        )
        .await
    }

    async fn token_answers(server: &MockServer, response: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(response)
            .mount(server)
            .await;
    }

    async fn api_echoes(server: &MockServer) {
        Mock::given(method("GET"))
            .respond_with(|req: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "authorization": req.headers["authorization"].to_str().unwrap(),
                }))
            })
            .mount(server)
            .await;
    }

    fn form(req: &wiremock::Request) -> HashMap<String, String> {
        url::form_urlencoded::parse(&req.body)
            .into_owned()
            .collect()
    }

    fn ok_token() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": ACCESS_TOKEN,
            "token_type": "Bearer",
            "expires_in": 3599,
        }))
    }

    /// A token for every call (invariant 8: nothing kept between calls),
    /// sent as the bearer token; the echoed token is scrubbed.
    #[tokio::test]
    async fn every_call_mints_a_token_and_sends_it_as_bearer() {
        let (api, token) = (MockServer::start().await, MockServer::start().await);
        token_answers(&token, ok_token()).await;
        api_echoes(&api).await;
        let s = setup(&api, &token, REFRESH);
        for _ in 0..2 {
            let resp = get(&s).await.unwrap();
            assert_eq!(resp.status, 200);
            assert!(
                !resp.body.to_string().contains(ACCESS_TOKEN),
                "{}",
                resp.body
            );
        }
        let token_requests = token.received_requests().await.unwrap();
        assert_eq!(token_requests.len(), 2);
        // The audit summary (and the prompt) says where the token comes from.
        let summary = s.audit.recent(1).unwrap()[0].summary.clone();
        assert!(summary.ends_with(" (token via 127.0.0.1)"), "{summary}");
        let sent = &api.received_requests().await.unwrap()[0];
        assert_eq!(
            sent.headers["authorization"].to_str().unwrap(),
            format!("Bearer {ACCESS_TOKEN}")
        );
        let f = form(&token_requests[0]);
        assert_eq!(f["grant_type"], "refresh_token");
        assert_eq!(f["refresh_token"], REFRESH_TOKEN);
        assert!(!f.contains_key("client_secret"), "Basic by default");
        // RFC 6749 §2.3.1: form-encoded, then Basic.
        use base64::Engine;
        let basic =
            base64::engine::general_purpose::STANDARD.encode(format!("app+id:{CLIENT_SECRET}"));
        assert_eq!(
            token_requests[0].headers["authorization"].to_str().unwrap(),
            format!("Basic {basic}")
        );
    }

    #[tokio::test]
    async fn client_credentials_in_the_body() {
        let (api, token) = (MockServer::start().await, MockServer::start().await);
        token_answers(&token, ok_token()).await;
        api_echoes(&api).await;
        let s = setup(
            &api,
            &token,
            r#"grant = "client_credentials"
            client_secret = "cs"
            client_auth = "body"
            scopes = ["files.read", "files.list"]"#,
        );
        get(&s).await.unwrap();
        let req = &token.received_requests().await.unwrap()[0];
        let f = form(req);
        assert_eq!(f["grant_type"], "client_credentials");
        assert_eq!(f["client_id"], "app id");
        assert_eq!(f["client_secret"], CLIENT_SECRET);
        assert_eq!(f["scope"], "files.read files.list");
        assert!(req.headers.get("authorization").is_none());
    }

    /// A hostile or broken token endpoint: the call fails, says only the
    /// status and the error code, and nothing it was sent reaches the
    /// agent or the audit log.
    #[tokio::test]
    async fn a_hostile_token_endpoint_learns_nothing_back() {
        let cases: Vec<(ResponseTemplate, &str)> = vec![
            (
                ResponseTemplate::new(400).set_body_json(serde_json::json!({
                    "error": "invalid_grant",
                    "error_description": format!("bad {REFRESH_TOKEN} for {CLIENT_SECRET}"),
                })),
                "answered 400 (invalid_grant)",
            ),
            (
                ResponseTemplate::new(400).set_body_json(serde_json::json!({
                    "error": format!("x {REFRESH_TOKEN}"),
                })),
                "answered 400",
            ),
            (
                ResponseTemplate::new(200).set_body_string("x".repeat(70 * 1024)),
                "more than 65536 bytes",
            ),
            (
                ResponseTemplate::new(200).set_body_string("not json"),
                "no access_token",
            ),
            (
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"access_token": "abc", "token_type": "mac"})),
                "other than bearer",
            ),
            (
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"access_token": "abc\r\nX-Evil: 1"})),
                "malformed access_token",
            ),
            (
                ResponseTemplate::new(302).insert_header("location", "/elsewhere"),
                "answered 302",
            ),
            (
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"access_token": "abc"}))
                    .set_delay(Duration::from_secs(5)),
                "token endpoint",
            ),
        ];
        for (response, want) in cases {
            let (api, token) = (MockServer::start().await, MockServer::start().await);
            token_answers(&token, response).await;
            Mock::given(path("/elsewhere"))
                .respond_with(ok_token())
                .expect(0)
                .mount(&token)
                .await;
            api_echoes(&api).await;
            let s = setup(&api, &token, REFRESH);
            let err = get(&s).await.unwrap_err().to_string();
            assert!(err.contains(want), "{want}: {err}");
            let logged = format!("{:?}", s.audit.recent(1).unwrap()[0]);
            for text in [&err, &logged] {
                for secret in [REFRESH_TOKEN, CLIENT_SECRET] {
                    assert!(!text.contains(secret), "{secret} in {text}");
                }
            }
            assert!(api.received_requests().await.unwrap().is_empty(), "{want}");
        }
    }

    #[tokio::test]
    async fn the_token_request_is_form_encoded() {
        let (api, token) = (MockServer::start().await, MockServer::start().await);
        Mock::given(method("POST"))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .respond_with(ok_token())
            .mount(&token)
            .await;
        api_echoes(&api).await;
        let s = setup(&api, &token, REFRESH);
        get(&s).await.unwrap();
    }

    /// The agent never sees an OAuth2 preset's refresh token or client
    /// secret, even through get_secret_for_env.
    #[test]
    fn oauth2_secrets_are_not_revealable() {
        let api_uri = "https://api.example.com";
        let p: Preset = toml::from_str(&format!(
            r#"
            name = "drive"
            type = "http"
            description = "x"
            base_url = "{api_uri}"
            allowed_methods = ["GET"]
            approval = "prompt"
            [auth]
            type = "oauth2"
            token_url = "https://oauth2.example.com/token"
            client_id = "id"
            {REFRESH}
            "#
        ))
        .unwrap();
        assert_eq!(p.secret_names(), ["cs", "rt"]);
        assert!(p.revealable_secrets().is_empty());
    }

    /// A provider that rotates: each refresh token works once, and each
    /// answer carries the next one.
    async fn rotating_endpoint(server: &MockServer) -> Arc<Mutex<String>> {
        let current = Arc::new(Mutex::new(REFRESH_TOKEN.to_string()));
        let state = current.clone();
        let issued = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(move |req: &wiremock::Request| {
                let sent = form(req)["refresh_token"].clone();
                let mut current = state.lock().unwrap();
                if sent != *current {
                    return ResponseTemplate::new(400)
                        .set_body_json(serde_json::json!({"error": "invalid_grant"}));
                }
                let n = issued.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                *current = format!("rt-ROTATED-{n}");
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": format!("at-{n}"),
                    "refresh_token": *current,
                }))
            })
            .mount(server)
            .await;
        current
    }

    /// Two calls at once, as two agents' calls would be: the second waits
    /// for the first to store the rotated token, so both succeed.
    #[tokio::test]
    async fn a_rotated_refresh_token_is_stored_and_calls_take_turns() {
        let (api, token) = (MockServer::start().await, MockServer::start().await);
        let current = rotating_endpoint(&token).await;
        api_echoes(&api).await;
        let s = setup(&api, &token, REFRESH);
        let (a, b) = tokio::join!(get(&s), get(&s));
        a.unwrap();
        b.unwrap();
        let stored = s.exec.keychain.get("rt").unwrap().unwrap();
        assert_eq!(stored.expose(), current.lock().unwrap().as_str());
        assert_eq!(stored.expose(), "rt-ROTATED-1");
    }

    /// The same across processes: the lock file in the config dir.
    #[tokio::test]
    async fn the_lock_file_serialises_callers_with_a_config_dir() {
        let (api, token) = (MockServer::start().await, MockServer::start().await);
        rotating_endpoint(&token).await;
        api_echoes(&api).await;
        let mut s = setup(&api, &token, REFRESH);
        let dir = tempfile::tempdir().unwrap();
        s.exec = s.exec.with_state_dir(dir.path().to_path_buf());
        let (a, b) = tokio::join!(get(&s), get(&s));
        a.unwrap();
        b.unwrap();
        let locks: Vec<_> = std::fs::read_dir(dir.path().join("locks"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(locks.len(), 1);
        assert!(locks[0].starts_with("oauth2-"), "{locks:?}");
    }

    struct ReadOnly(CountingKeychain);
    impl KeychainStore for ReadOnly {
        fn set(&self, _: &str, _: Secret) -> Result<()> {
            Err(WardenError::Keychain("locked".into()))
        }
        fn get(&self, name: &str) -> Result<Option<Secret>> {
            self.0.get(name)
        }
        fn delete(&self, name: &str) -> Result<()> {
            self.0.delete(name)
        }
        fn list_names(&self) -> Result<Vec<String>> {
            self.0.list_names()
        }
    }

    /// Fail closed: a rotated token that cannot be stored ends the call.
    #[tokio::test]
    async fn a_rotated_token_that_cannot_be_stored_fails_the_call() {
        let (api, token) = (MockServer::start().await, MockServer::start().await);
        rotating_endpoint(&token).await;
        api_echoes(&api).await;
        let mut s = setup(&api, &token, REFRESH);
        let kc = CountingKeychain::default();
        kc.set("cs", Secret::new(CLIENT_SECRET.into())).unwrap();
        kc.set("rt", Secret::new(REFRESH_TOKEN.into())).unwrap();
        s.exec.keychain = Arc::new(ReadOnly(kc));
        let err = get(&s).await.unwrap_err().to_string();
        assert!(err.contains("storing it in 'rt' failed"), "{err}");
        assert!(!err.contains("rt-ROTATED"), "{err}");
        assert!(api.received_requests().await.unwrap().is_empty());
    }

    /// A provider that answers with an empty or malformed refresh token:
    /// the call fails and the stored token is left as it was.
    #[tokio::test]
    async fn a_malformed_rotated_token_is_not_stored() {
        for rotated in [
            serde_json::json!(""),
            serde_json::json!("a b"),
            serde_json::json!(5),
        ] {
            let (api, token) = (MockServer::start().await, MockServer::start().await);
            token_answers(
                &token,
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": ACCESS_TOKEN,
                    "refresh_token": rotated,
                })),
            )
            .await;
            api_echoes(&api).await;
            let s = setup(&api, &token, REFRESH);
            let err = get(&s).await.unwrap_err().to_string();
            assert!(err.contains("malformed refresh_token"), "{err}");
            assert_eq!(
                s.exec.keychain.get("rt").unwrap().unwrap().expose(),
                REFRESH_TOKEN
            );
            assert!(api.received_requests().await.unwrap().is_empty());
        }
    }
}
