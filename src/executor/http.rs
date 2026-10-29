use crate::executor::ActionExecutor;
use crate::executor::credential_echo::CredentialForms;
use crate::executor::policy::{Request, check_request};
use mcp_warden_core::audit::AuditOutcome;
use mcp_warden_core::config::{Auth, Preset};
use mcp_warden_core::error::{Result, WardenError};
use mcp_warden_core::secret::Secret;
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;

#[derive(Debug, Deserialize, Serialize)]
pub struct HttpRequest {
    pub preset_name: String,
    pub path: String,
    pub method: String,
    #[serde(default)]
    pub body: Option<serde_json::Value>,
    #[serde(default)]
    pub query: Option<std::collections::BTreeMap<String, String>>,
}

#[derive(Debug, Serialize)]
pub struct HttpResponse {
    pub status: u16,
    pub body: serde_json::Value,
    /// Why mcp-warden withheld or trimmed the body, if it did.
    pub notice: Option<String>,
}

/// Validate method + path against the preset's allow-list.
///
/// Runs BEFORE any credential is touched — spec §9.3.
pub fn validate_request(preset: &Preset, method: &str, path: &str) -> Result<()> {
    if !preset
        .allowed_methods
        .iter()
        .any(|m| m.eq_ignore_ascii_case(method))
    {
        return Err(WardenError::Validation(format!(
            "method '{method}' not in preset '{}' allow-list",
            preset.name
        )));
    }
    if !path.starts_with('/') || path.contains("..") || path.contains("://") {
        return Err(WardenError::Validation(format!(
            "path '{path}' must be relative, no traversal, no scheme"
        )));
    }
    // URL parsers treat `%2e` as `.` (WHATWG URL spec) and `\` as `/` for
    // http(s), so `/users/%2e%2e/admin` would pass the allow-list and then be
    // normalised to `/admin`. Refuse anything normalisation could rewrite.
    // `%2f` stays allowed — GitLab-style APIs need it for namespaced ids —
    // but patterns see it decoded, as a separator (see `decode_path`).
    let lower = path.to_ascii_lowercase();
    if path.contains('\\')
        || lower.contains("%2e")
        || lower.contains("%5c")
        || path.split('/').any(|seg| seg == ".")
    {
        return Err(WardenError::Validation(format!(
            "path '{path}' contains dot segments, encoded dots or backslashes"
        )));
    }
    // Patterns see the path decoded once, but an upstream may decode twice
    // (a proxy in front of an app), turning `%252e%252e` into `..` and
    // `%252F` into `/`. A second pass can only find an escape whose `%`
    // came out of the first, and that `%` is always a `%25`.
    if path.contains("%25") {
        return Err(WardenError::Validation(format!(
            "path '{path}' contains an encoded '%' (%25); double percent-encoding is refused"
        )));
    }
    // `percent_decode_str` leaves any other `%` as it is, but servers differ
    // on what follows: IIS and ASP.NET decode `%u005c` to `\` and `%u002e`
    // to `.`. The allow-list can't see what such a server will route.
    if !well_formed_escapes(path) {
        return Err(WardenError::Validation(format!(
            "path '{path}' has a '%' that is not followed by two hex digits"
        )));
    }
    let decoded = decode_path(path)?;
    if preset.allowed_paths.is_empty() {
        return Ok(());
    }
    for pat in &preset.allowed_paths {
        if pat == &*decoded {
            return Ok(());
        }
        if let Ok(rx) = mcp_warden_core::config::anchored_regex(pat)
            && rx.is_match(&decoded)
        {
            return Ok(());
        }
    }
    Err(WardenError::Validation(format!(
        "path '{path}' not allowed by preset '{}'",
        preset.name
    )))
}

/// Every `%` in `path` starts an escape of exactly two hex digits.
fn well_formed_escapes(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.iter().enumerate().all(|(i, &b)| {
        b != b'%'
            || matches!(bytes.get(i + 1..i + 3), Some([h, l])
                if h.is_ascii_hexdigit() && l.is_ascii_hexdigit())
    })
}

/// Percent-decode `path` for allow-list matching.
///
/// Upstreams may decode `%2F` before routing (nginx does by default), so
/// `/repos/o/x%2Fcollaborators` can reach a route `/repos/o/[^/]+` never
/// approved; patterns therefore see the decoded path. Anything an upstream
/// could split, merge or cut differently once decoded is refused: empty
/// segments (slash merging), `.`/`..`, `\`, control characters (NUL
/// truncation, header splitting) and invalid UTF-8. The raw path is still
/// what gets sent — `build_url` checks that.
fn decode_path(path: &str) -> Result<std::borrow::Cow<'_, str>> {
    let decoded = percent_decode_str(path).decode_utf8().map_err(|_| {
        WardenError::Validation(format!(
            "path '{path}' is not valid UTF-8 once percent-decoded"
        ))
    })?;
    // Decoding never removes a `/`, so this also covers a raw `//`.
    if decoded.contains("//") {
        return Err(WardenError::Validation(format!(
            "path '{path}' contains an empty segment (`//`)"
        )));
    }
    if decoded.contains('\\')
        || decoded.chars().any(char::is_control)
        || decoded.split('/').any(|seg| seg == "." || seg == "..")
    {
        return Err(WardenError::Validation(format!(
            "path '{path}' contains dot segments, backslashes or control \
             characters once percent-decoded"
        )));
    }
    Ok(decoded)
}

/// Join `base_url` and the agent-supplied path.
///
/// Validate method + path and build the request URL from `base_url`.
pub(crate) fn validated_url(preset: &Preset, method: &str, path: &str) -> Result<Url> {
    validate_request(preset, method, path)?;
    let base = preset.base_url.as_deref().ok_or_else(|| {
        WardenError::Validation(format!("preset '{}' has no base_url", preset.name))
    })?;
    build_url(base, path)
}

/// Defence in depth for `validate_request`: the URL that gets sent must carry
/// exactly the path that was validated. If parsing would normalise or
/// re-encode it in any way (dot segments, `\\`, spaces, `?`…), refuse.
pub fn build_url(base: &str, path: &str) -> Result<Url> {
    let mut url = Url::parse(base).map_err(|e| WardenError::Validation(e.to_string()))?;
    let new_path = format!("{}{}", url.path().trim_end_matches('/'), path);
    url.set_path(&new_path);
    if url.path() != new_path {
        return Err(WardenError::Validation(format!(
            "path '{path}' would be rewritten by URL normalisation — send it \
             percent-encoded, without dot segments; put query parameters in `query`"
        )));
    }
    Ok(url)
}

pub async fn execute(
    exec: &ActionExecutor,
    preset: &Preset,
    req: HttpRequest,
) -> Result<HttpResponse> {
    let method_upper = req.method.to_uppercase();
    let summary = crate::executor::summary::http(&method_upper, &req.path);
    let request = Request::Http {
        method: &method_upper,
        path: &req.path,
    };
    let mut url = check_request(preset, &request)
        .and_then(|()| validated_url(preset, &method_upper, &req.path))
        .inspect_err(|e| exec.record_refused(&preset.name, "proxy_http", &summary, e))?;
    let event_id = exec
        .authorise(preset, "proxy_http", &summary, false)
        .await?;

    let secret = match &preset.auth {
        Some(Auth::Bearer { secret })
        | Some(Auth::Header { secret, .. })
        | Some(Auth::Basic { secret, .. }) => {
            exec.keychain
                .get(secret)?
                .ok_or_else(|| WardenError::MissingSecret {
                    preset: preset.name.clone(),
                    secret: secret.clone(),
                })?
        }
        None => return Err(WardenError::Validation("preset missing auth".into())),
    };

    if let Some(q) = &req.query {
        let mut pairs = url.query_pairs_mut();
        for (k, v) in q {
            pairs.append_pair(k, v);
        }
    }

    let client = http_client()?;
    let method = method_upper
        .parse::<reqwest::Method>()
        .map_err(|_| WardenError::Validation(format!("bad method {method_upper}")))?;
    let mut builder = client.request(method, url);
    builder = inject_auth(builder, &preset.auth, &secret);
    if let Some(body) = req.body {
        builder = builder.json(&body);
    }

    // `secret` stays alive until the body has been scrubbed of it below.
    let resp = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            let _ = exec.audit.record_outcome(
                event_id,
                AuditOutcome::Err {
                    message: e.to_string(),
                },
            );
            return Err(WardenError::Executor(e.to_string()));
        }
    };
    let status = resp.status().as_u16();
    // At most `max_response_bytes` of it; `null` if it isn't JSON.
    let (mut body, mut notice) = super::response::read_body(resp, preset).await;
    // An upstream that reflects the request would otherwise hand the agent
    // the credential (invariants 1–2).
    let redacted = CredentialForms::http(&preset.auth, &secret).scrub(&mut body);
    drop(secret);
    if let Some(selected) = super::response::select_fields(&body, preset) {
        body = selected;
        notice = Some("only this preset's response_fields are returned".into());
    }
    if redacted > 0 {
        tracing::warn!(
            "preset '{}': the upstream response echoed the credential; redacted {redacted} \
             occurrence(s) before returning it to the agent",
            preset.name
        );
    }
    exec.audit
        .record_outcome(event_id, AuditOutcome::Ok { status })?;
    Ok(HttpResponse {
        status,
        body,
        notice,
    })
}

/// Redirects are never followed: a hop could leave `base_url`'s host —
/// reqwest strips `Authorization` cross-origin but not custom auth headers
/// (`Auth::Header`) — or land on a path the allow-list never approved.
/// The 3xx is returned to the agent as-is.
fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .user_agent(format!("mcp-warden/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| WardenError::Executor(e.to_string()))
}

fn inject_auth(
    b: reqwest::RequestBuilder,
    auth: &Option<Auth>,
    secret: &Secret,
) -> reqwest::RequestBuilder {
    match auth {
        Some(Auth::Bearer { .. }) => b.bearer_auth(secret.expose()),
        Some(Auth::Header { name, prefix, .. }) => {
            let value = match prefix {
                Some(p) => format!("{p}{}", secret.expose()),
                None => secret.expose().to_string(),
            };
            b.header(name, value)
        }
        Some(Auth::Basic { username, .. }) => b.basic_auth(username, Some(secret.expose())),
        None => b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_warden_core::config::{ApprovalPolicy, Auth, Preset, PresetType};

    fn p() -> Preset {
        Preset {
            name: "p".into(),
            preset_type: PresetType::Http,
            description: "x".into(),
            base_url: Some("https://api.example.com".into()),
            auth: Some(Auth::Bearer { secret: "k".into() }),
            allowed_paths: vec!["/users".into(), "/users/[a-z0-9]+".into()],
            allowed_methods: vec!["GET".into(), "POST".into()],
            approval: ApprovalPolicy::Auto,
            approval_window_seconds: None,
            host: None,
            user: None,
            port: None,
            secret: None,
            allowed_commands: vec![],
            timeout_seconds: None,
            known_hosts: None,
            allow_sftp: false,
            sftp_allowed_paths: vec![],
            database: None,
            queries: vec![],
            expires_at: None,
            max_response_bytes: None,
            response_fields: vec![],
        }
    }

    #[test]
    fn rejects_method_not_in_allowlist() {
        let err = validate_request(&p(), "DELETE", "/users").unwrap_err();
        assert!(err.to_string().contains("method"));
    }

    #[test]
    fn rejects_path_not_matching_allowlist() {
        let err = validate_request(&p(), "GET", "/admin").unwrap_err();
        assert!(err.to_string().contains("not allowed"));
    }

    #[test]
    fn alternation_in_path_pattern_stays_anchored() {
        let mut q = p();
        q.allowed_paths = vec!["/user|/repos/[a-z]+".into()];
        validate_request(&q, "GET", "/user").unwrap();
        validate_request(&q, "GET", "/repos/abc").unwrap();
        for evil in ["/user/keys", "/admin/repos/abc"] {
            assert!(
                validate_request(&q, "GET", evil).is_err(),
                "should reject: {evil}"
            );
        }
    }

    #[test]
    fn rejects_encoded_traversal_and_backslashes() {
        let mut q = p();
        q.allowed_paths = vec!["/users/.*".into()];
        for evil in [
            "/users/%2e%2e/admin",
            "/users/%2E%2E/admin",
            "/users/.%2e/admin",
            "/users/x%5cadmin",
            "/users/x\\admin",
            "/users/./admin",
        ] {
            assert!(
                validate_request(&q, "GET", evil).is_err(),
                "should reject: {evil}"
            );
        }
    }

    #[test]
    fn rejects_double_percent_encoding() {
        // One decode pass leaves `%2e%2e` / `%2F`, which the allow-list
        // takes for ordinary characters; an upstream that decodes twice
        // (a proxy in front of an app) sees `..` or `/`.
        let mut q = p();
        q.allowed_paths = vec!["/users/.*".into(), "/repos/o/[^/]+".into()];
        for evil in [
            "/users/%252e%252e/admin",
            "/users/%252E%252E/admin",
            "/users/%25%32%65%25%32%65/admin",
            "/users/%25252e%25252e/admin",
            "/repos/o/x%252Fcollaborators",
            // A literal `%` is refused too: it can't be told apart.
            "/users/100%25",
        ] {
            let err = validate_request(&q, "GET", evil).unwrap_err();
            assert!(err.to_string().contains("%25"), "{evil}: {err}");
        }
    }

    #[test]
    fn rejects_malformed_percent_escapes() {
        // `percent_decode_str` leaves `%` alone unless two hex digits follow,
        // so `%u005c` reached the allow-list as text — but IIS and ASP.NET
        // decode the non-standard `%uXXXX` to `\` / `.`.
        let mut q = p();
        q.allowed_paths = vec!["/users/.*".into()];
        for evil in [
            "/users/%u005cadmin",
            "/users/%U005Cadmin",
            "/users/%u002e%u002e/admin",
            "/users/a%zz",
            "/users/a%2",
            "/users/a%",
            "/users/%%32%65",
        ] {
            let err = validate_request(&q, "GET", evil).unwrap_err();
            assert!(err.to_string().contains("two hex digits"), "{evil}: {err}");
        }
        validate_request(&q, "GET", "/users/a%2Db%7E").unwrap();
    }

    #[test]
    fn accepts_encoded_slash_for_namespaced_ids() {
        // GitLab-style APIs require `group%2Fproject` as one path segment.
        // Patterns see the decoded path, so the id spans two segments there;
        // what gets sent is still the raw, encoded path.
        let mut q = p();
        q.allowed_paths = vec!["/projects/[^/]+/[^/]+".into()];
        validate_request(&q, "GET", "/projects/group%2Fproject").unwrap();
        let u = build_url("https://gitlab.example/api/v4", "/projects/group%2Fproject").unwrap();
        assert_eq!(u.path(), "/api/v4/projects/group%2Fproject");
    }

    #[test]
    fn encoded_slash_counts_as_a_separator_for_the_allow_list() {
        // An upstream that decodes `%2F` before routing (nginx does by
        // default) sees two segments, so the allow-list must too.
        let mut q = p();
        q.allowed_paths = vec!["/projects/[^/]+".into()];
        assert!(validate_request(&q, "GET", "/projects/group%2Fproject").is_err());
        q.allowed_paths = vec!["/repos/ermoluk/[^/]+".into()];
        for evil in [
            "/repos/ermoluk/x%2Fcollaborators",
            "/repos/ermoluk/x%2fcollaborators",
        ] {
            let err = validate_request(&q, "GET", evil).unwrap_err();
            assert!(err.to_string().contains("not allowed"), "{evil}: {err}");
        }
    }

    #[test]
    fn exact_pattern_matches_the_decoded_path() {
        // `+` makes this a different regex, so only the exact comparison
        // can match it, and it has to compare against the decoded path.
        let mut q = p();
        q.allowed_paths = vec!["/files/a+b".into()];
        validate_request(&q, "GET", "/files/a%2Bb").unwrap();
    }

    #[test]
    fn rejects_empty_segments_raw_or_decoded() {
        // Upstreams that merge slashes would route a different path than
        // the allow-list saw. Empty allowed_paths: only the structural
        // checks stand between these and the upstream.
        let mut q = p();
        q.allowed_paths = vec![];
        for evil in [
            "/user//repos",
            "//user/repos",
            "/user/%2Frepos",
            "/user%2F%2Frepos",
        ] {
            assert!(
                validate_request(&q, "GET", evil).is_err(),
                "should reject: {evil}"
            );
        }
    }

    #[test]
    fn rejects_decoded_control_chars_and_invalid_utf8() {
        let mut q = p();
        q.allowed_paths = vec![];
        for evil in [
            "/users/a%00b",
            "/users/a%0ab",
            "/users/a%0D%0Ab",
            "/users/a%7fb",
            "/users/a%ff",
            "/users/a%c3%28",
        ] {
            assert!(
                validate_request(&q, "GET", evil).is_err(),
                "should reject: {evil}"
            );
        }
    }

    #[test]
    fn rejects_dot_segments_that_appear_only_after_decoding() {
        let mut q = p();
        q.allowed_paths = vec![];
        for evil in ["/users/a%2F.%2Fb", "/users/a%2F.", "/users/.%2Fb"] {
            assert!(
                validate_request(&q, "GET", evil).is_err(),
                "should reject: {evil}"
            );
        }
    }

    #[test]
    fn accepts_ordinary_encoded_characters() {
        let mut q = p();
        q.allowed_paths = vec!["/search/[^/]+".into()];
        validate_request(&q, "GET", "/search/a%20b").unwrap();
        validate_request(&q, "GET", "/search/%D0%BF%D1%80%D0%B8").unwrap();
    }

    #[test]
    fn build_url_joins_base_path_and_request_path() {
        let u = build_url("https://api.github.com", "/user/repos").unwrap();
        assert_eq!(u.as_str(), "https://api.github.com/user/repos");
        let u = build_url("https://x.example/v1/", "/items/42").unwrap();
        assert_eq!(u.path(), "/v1/items/42");
    }

    #[test]
    fn build_url_refuses_any_path_rewritten_by_normalisation() {
        // Defence in depth: even if validation were bypassed, what gets sent
        // must be byte-for-byte what was validated, inside base_url's path.
        for evil in [
            "/%2e%2e/internal",
            "/a/%2E%2E/%2e%2e/internal",
            "/a b",
            "/a?x=1",
        ] {
            assert!(
                build_url("https://x.example/v1", evil).is_err(),
                "should reject: {evil}"
            );
        }
    }

    #[test]
    fn accepts_allowed_path_exact() {
        validate_request(&p(), "GET", "/users").unwrap();
    }

    #[test]
    fn accepts_allowed_path_regex() {
        validate_request(&p(), "GET", "/users/abc").unwrap();
    }

    #[test]
    fn rejects_path_traversal() {
        let err = validate_request(&p(), "GET", "/users/../admin").unwrap_err();
        assert!(err.to_string().contains("traversal"));
    }

    #[test]
    fn rejects_absolute_path_with_scheme() {
        let err = validate_request(&p(), "GET", "https://attacker.com/x").unwrap_err();
        assert!(err.to_string().contains("scheme"));
    }

    #[tokio::test]
    async fn redirects_are_not_followed_so_credentials_stay_put() {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let attacker = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&attacker)
            .await;
        let api = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/steal", attacker.uri())),
            )
            .mount(&api)
            .await;

        let resp = http_client()
            .unwrap()
            .get(format!("{}/users", api.uri()))
            .header("X-Api-Key", "SUPERSECRET")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 302);
        // MockServer verifies `.expect(0)` on drop: the key never left `api`.
    }

    // Credential echo (invariants 1–2): an upstream that reflects the
    // request must not hand the injected credential to the agent.

    use serde_json::{Value, json};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const REDACTED: &str = "[redacted by mcp-warden]";

    /// An upstream that answers every request with `respond(request)`.
    async fn echo_server(
        respond: impl Fn(&wiremock::Request) -> Value + Send + Sync + 'static,
    ) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(wiremock::matchers::any())
            .respond_with(move |req: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_json(respond(req))
            })
            .mount(&server)
            .await;
        server
    }

    /// httpbin's `/headers`: every request header, reflected as JSON.
    fn echo_headers(req: &wiremock::Request) -> Value {
        let headers: serde_json::Map<String, Value> = req
            .headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap().into()))
            .collect();
        json!({ "headers": headers, "origin": "203.0.113.7" })
    }

    fn bearer_of(req: &wiremock::Request) -> String {
        let value = req.headers["authorization"].to_str().unwrap();
        value.strip_prefix("Bearer ").unwrap().to_string()
    }

    /// `GET path` through `execute`, with `auth` bound to `secret`. The
    /// preset is `auto`, so the approval transport is never asked.
    async fn call_upstream(
        server: &MockServer,
        auth: Auth,
        secret: &str,
        path: &str,
    ) -> HttpResponse {
        use crate::approval::always_deny::AlwaysDeny;
        use mcp_warden_core::audit::sqlite_sink::LocalSqlite;
        use mcp_warden_core::keychain::KeychainStore;
        use mcp_warden_core::keychain::memory::InMemoryKeychain;
        use std::sync::Arc;

        let keychain = InMemoryKeychain::new();
        keychain.set("k", Secret::new(secret.into())).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let exec = ActionExecutor::new(
            Arc::new(keychain),
            Arc::new(AlwaysDeny),
            None,
            Arc::new(LocalSqlite::open(&dir.path().join("audit.db")).unwrap()),
        );
        let mut preset = p();
        preset.base_url = Some(server.uri());
        preset.auth = Some(auth);
        preset.allowed_paths = vec![];
        let req = HttpRequest {
            preset_name: preset.name.clone(),
            path: path.into(),
            method: "GET".into(),
            body: None,
            query: None,
        };
        execute(&exec, &preset, req).await.unwrap()
    }

    /// `GET path` through `execute` against `server`, with the preset
    /// adjusted by `tweak`.
    async fn call_preset(
        server: &MockServer,
        path: &str,
        tweak: impl FnOnce(&mut Preset),
    ) -> HttpResponse {
        use crate::approval::always_deny::AlwaysDeny;
        use mcp_warden_core::audit::sqlite_sink::LocalSqlite;
        use mcp_warden_core::keychain::KeychainStore;
        use mcp_warden_core::keychain::memory::InMemoryKeychain;
        use std::sync::Arc;

        let keychain = InMemoryKeychain::new();
        keychain.set("k", Secret::new("test-token".into())).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let exec = ActionExecutor::new(
            Arc::new(keychain),
            Arc::new(AlwaysDeny),
            None,
            Arc::new(LocalSqlite::open(&dir.path().join("audit.db")).unwrap()),
        );
        let mut preset = p();
        preset.base_url = Some(server.uri());
        preset.auth = Some(Auth::Bearer { secret: "k".into() });
        preset.allowed_paths = vec![];
        tweak(&mut preset);
        let req = HttpRequest {
            preset_name: preset.name.clone(),
            path: path.into(),
            method: "GET".into(),
            body: None,
            query: None,
        };
        execute(&exec, &preset, req).await.unwrap()
    }

    #[tokio::test]
    async fn body_over_max_response_bytes_is_withheld_but_status_returned() {
        let big = json!({ "data": "x".repeat(2_000) });
        let server = echo_server(move |_| big.clone()).await;
        let resp = call_preset(&server, "/big", |p| p.max_response_bytes = Some(100)).await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, Value::Null);
        assert!(
            resp.notice
                .unwrap()
                .contains("max_response_bytes (100 bytes)")
        );

        let resp = call_preset(&server, "/big", |p| p.max_response_bytes = Some(10_000)).await;
        assert_eq!(resp.body["data"].as_str().unwrap().len(), 2_000);
        assert_eq!(resp.notice, None);
    }

    #[tokio::test]
    async fn only_response_fields_are_returned() {
        let server = echo_server(
            |_| json!({ "id": 1, "name": "repo", "owner": { "login": "o", "email": "e" } }),
        )
        .await;
        let resp = call_preset(&server, "/repo", |p| {
            p.response_fields = vec!["id".into(), "owner.login".into()];
        })
        .await;
        assert_eq!(resp.body, json!({ "id": 1, "owner": { "login": "o" } }));
        assert!(resp.notice.unwrap().contains("response_fields"));
    }

    #[tokio::test]
    async fn fields_are_selected_after_the_credential_is_scrubbed() {
        let server = echo_server(echo_headers).await;
        let resp = call_preset(&server, "/headers", |p| {
            p.response_fields = vec!["headers.authorization".into()];
        })
        .await;
        assert_eq!(
            resp.body,
            json!({ "headers": { "authorization": "Bearer [redacted by mcp-warden]" } })
        );
    }

    /// The header value the upstream actually received.
    async fn sent_header(server: &MockServer, name: &str) -> String {
        let requests = server.received_requests().await.unwrap();
        requests[0].headers[name].to_str().unwrap().to_string()
    }

    /// Every key, string and number in `v`: all the text the agent sees.
    fn texts(v: &Value) -> Vec<String> {
        match v {
            Value::String(s) => vec![s.clone()],
            Value::Number(n) => vec![n.to_string()],
            Value::Array(items) => items.iter().flat_map(texts).collect(),
            Value::Object(map) => map
                .iter()
                .flat_map(|(k, v)| std::iter::once(k.clone()).chain(texts(v)))
                .collect(),
            Value::Null | Value::Bool(_) => vec![],
        }
    }

    fn assert_absent(body: &Value, form: &str) {
        for text in texts(body) {
            assert!(
                !text.contains(form),
                "{form:?} reached the agent in {text:?}"
            );
        }
    }

    #[tokio::test]
    async fn bearer_token_echoed_by_upstream_is_redacted() {
        let token = "test-bearer-token-0123456789";
        let server = echo_server(echo_headers).await;
        let resp = call_upstream(
            &server,
            Auth::Bearer { secret: "k".into() },
            token,
            "/headers",
        )
        .await;

        assert_eq!(
            sent_header(&server, "authorization").await,
            format!("Bearer {token}")
        );
        assert_eq!(resp.status, 200);
        assert_absent(&resp.body, token);
        assert_eq!(
            resp.body["headers"]["authorization"],
            format!("Bearer {REDACTED}")
        );
        assert_eq!(resp.body["origin"], "203.0.113.7");
        let ua = resp.body["headers"]["user-agent"].as_str().unwrap();
        assert!(ua.starts_with("mcp-warden/"), "{ua}");
    }

    #[tokio::test]
    async fn header_auth_echo_is_redacted_together_with_its_prefix() {
        let key = "test-header-key-0123456789";
        let server = echo_server(echo_headers).await;
        let auth = Auth::Header {
            name: "X-Api-Key".into(),
            secret: "k".into(),
            prefix: Some("Token ".into()),
        };
        let resp = call_upstream(&server, auth, key, "/headers").await;

        assert_eq!(
            sent_header(&server, "x-api-key").await,
            format!("Token {key}")
        );
        assert_absent(&resp.body, key);
        assert_eq!(resp.body["headers"]["x-api-key"], REDACTED);
        assert_eq!(resp.body["origin"], "203.0.113.7");
    }

    #[tokio::test]
    async fn basic_auth_echo_is_redacted_raw_and_base64() {
        // `deploy:Basic-Pa55word!` is 22 bytes, so its base64 ends in `==`.
        let password = "Basic-Pa55word!";
        let server = echo_server(move |req| {
            let mut body = echo_headers(req);
            let header = req.headers["authorization"].to_str().unwrap();
            let encoded = header.strip_prefix("Basic ").unwrap();
            // A debug endpoint that also dumps the credentials it decoded.
            body["credentials"] = json!({ "user": "deploy", "password": password });
            body["unpadded"] = encoded.trim_end_matches('=').into();
            body
        })
        .await;
        let auth = Auth::Basic {
            username: "deploy".into(),
            secret: "k".into(),
        };
        let resp = call_upstream(&server, auth, password, "/anything").await;

        let sent = sent_header(&server, "authorization").await;
        let encoded = sent.strip_prefix("Basic ").unwrap();
        assert!(encoded.ends_with("=="), "{encoded}");
        for form in [password, encoded, encoded.trim_end_matches('=')] {
            assert_absent(&resp.body, form);
        }
        assert_eq!(
            resp.body["headers"]["authorization"],
            format!("Basic {REDACTED}")
        );
        assert_eq!(resp.body["credentials"]["password"], REDACTED);
        assert_eq!(resp.body["credentials"]["user"], "deploy");
        assert_eq!(resp.body["unpadded"], REDACTED);
    }

    #[tokio::test]
    async fn percent_encoded_echo_is_redacted_whatever_the_encoder() {
        use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

        // Lowercase only, so lowercasing the encoded form changes just the
        // hex digits.
        let token = "tok/with+plus=eq and space&amp";
        let encodings = |token: &str| {
            let upper = utf8_percent_encode(token, NON_ALPHANUMERIC).to_string();
            let form: String = url::form_urlencoded::byte_serialize(token.as_bytes()).collect();
            let partial = token.replace('/', "%2f").replace(' ', "%20");
            [upper.to_lowercase(), upper, form, partial]
        };
        let server = echo_server(move |req| {
            let [lower, upper, form, partial] = encodings(&bearer_of(req));
            json!({
                "upper": format!("https://example.test/cb?t={upper}"),
                "lower": format!("https://example.test/cb?t={lower}"),
                "form": format!("t={form}&next=%2Fhome"),
                "partial": format!("https://example.test/cb?t={partial}"),
            })
        })
        .await;
        let resp = call_upstream(&server, Auth::Bearer { secret: "k".into() }, token, "/cb").await;

        assert_absent(&resp.body, token);
        for form in encodings(token) {
            assert_absent(&resp.body, &form);
        }
        let url = format!("https://example.test/cb?t={REDACTED}");
        assert_eq!(resp.body["upper"], url);
        assert_eq!(resp.body["lower"], url);
        assert_eq!(resp.body["partial"], url);
        assert_eq!(resp.body["form"], format!("t={REDACTED}&next=%2Fhome"));
    }

    #[tokio::test]
    async fn credential_is_redacted_in_keys_arrays_and_longer_strings() {
        let token = "test-shape-token-0123456789";
        let server = echo_server(|req| {
            let token = bearer_of(req);
            json!({
                "by_token": { token.clone(): { "owner": "ci" } },
                "seen": ["first", token.clone(), { "deep": [format!("x {token} y")] }],
                "message": format!("invalid token {token}, try again"),
                "count": 3,
            })
        })
        .await;
        let resp = call_upstream(&server, Auth::Bearer { secret: "k".into() }, token, "/me").await;

        assert_absent(&resp.body, token);
        assert_eq!(
            resp.body["by_token"],
            json!({ REDACTED: { "owner": "ci" } })
        );
        assert_eq!(
            resp.body["seen"],
            json!(["first", REDACTED, { "deep": [format!("x {REDACTED} y")] }])
        );
        assert_eq!(
            resp.body["message"],
            format!("invalid token {REDACTED}, try again")
        );
        assert_eq!(resp.body["count"], 3);
    }

    #[tokio::test]
    async fn response_without_the_credential_comes_back_byte_for_byte() {
        // Canonical JSON (sorted keys, no whitespace), so serialising the
        // parsed body must reproduce it exactly. Near misses stay as they
        // are: the token cut short, the scheme word, `%` and `+` that
        // decode to something else.
        const RAW: &str = r#"{"a":[1,2.5,-3,null,true,false],"auth":"Bearer","nested":{"empty":{},"list":[]},"pct":"100%25 sure, a+b","prefix":"test-exact-token-012345678","unicode":"привет ✓"}"#;
        let token = "test-exact-token-0123456789";
        let server = MockServer::start().await;
        Mock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(200).set_body_raw(RAW, "application/json"))
            .mount(&server)
            .await;
        let resp = call_upstream(&server, Auth::Bearer { secret: "k".into() }, token, "/me").await;

        assert_eq!(serde_json::to_string(&resp.body).unwrap(), RAW);
    }
}
