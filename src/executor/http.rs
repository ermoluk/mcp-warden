use crate::executor::ActionExecutor;
use mcp_warden_core::audit::AuditOutcome;
use mcp_warden_core::config::{Auth, Preset};
use mcp_warden_core::error::{Result, WardenError};
use mcp_warden_core::secret::Secret;
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
    // `%2f` stays allowed: without dots it cannot climb, and GitLab-style
    // APIs need it for namespaced ids.
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
    if preset.allowed_paths.is_empty() {
        return Ok(());
    }
    for pat in &preset.allowed_paths {
        if pat == path {
            return Ok(());
        }
        if let Ok(rx) = mcp_warden_core::config::anchored_regex(pat) {
            if rx.is_match(path) {
                return Ok(());
            }
        }
    }
    Err(WardenError::Validation(format!(
        "path '{path}' not allowed by preset '{}'",
        preset.name
    )))
}

/// Join `base_url` and the agent-supplied path.
///
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
    validate_request(preset, &method_upper, &req.path)?;
    let base = preset.base_url.as_deref().ok_or_else(|| {
        WardenError::Validation(format!("preset '{}' has no base_url", preset.name))
    })?;
    let mut url = build_url(base, &req.path)?;
    let summary = format!("{method_upper} {}", req.path);
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
    drop(secret);

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
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    exec.audit
        .record_outcome(event_id, AuditOutcome::Ok { status })?;
    Ok(HttpResponse { status, body })
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
    fn accepts_encoded_slash_for_namespaced_ids() {
        // GitLab-style APIs require `group%2Fproject` as one path segment.
        let mut q = p();
        q.allowed_paths = vec!["/projects/[^/]+".into()];
        validate_request(&q, "GET", "/projects/group%2Fproject").unwrap();
        build_url("https://gitlab.example/api/v4", "/projects/group%2Fproject").unwrap();
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
}
