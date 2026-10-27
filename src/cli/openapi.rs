//! Bootstrap a preset from an OpenAPI 3.0/3.1 spec.
//!
//! Given a JSON or YAML OpenAPI spec (file path or http(s) URL), extract:
//! - the first server URL → preset `base_url`
//! - the union of operation methods → `allowed_methods`
//! - the operation paths (literal, with `{param}` placeholders preserved) →
//!   `allowed_paths`
//! - the first Bearer or APIKey security scheme → auth choice
//!
//! Defaults to `approval = "prompt"` because we don't want to auto-approve
//! a wide-open generated preset.

use mcp_warden_core::config::{ApprovalPolicy, Auth, Preset, PresetType};
use mcp_warden_core::error::{Result, WardenError};
use openapiv3::{OpenAPI, ReferenceOr, SecurityScheme};
use std::collections::BTreeSet;
use std::path::Path;

const MAX_SPEC_BYTES: usize = 50 * 1024 * 1024; // 50 MB safety cap

#[derive(Debug)]
pub struct FromOpenapiOptions<'a> {
    pub source: &'a str,
    pub name_override: Option<&'a str>,
    pub secret_name: Option<&'a str>,
    pub base_url_override: Option<&'a str>,
    pub method_filter: Option<&'a [String]>,
    pub tag_filter: Option<&'a [String]>,
    pub approval: ApprovalPolicy,
}

/// Result of parsing a spec — a preset plus metadata about what was found.
pub struct Bootstrapped {
    pub preset: Preset,
    pub spec_title: String,
    pub spec_version: String,
    pub operation_count: usize,
    pub source: String,
}

pub async fn from_source(opts: FromOpenapiOptions<'_>) -> Result<Bootstrapped> {
    let bytes = fetch(opts.source).await?;
    let api = parse_spec(&bytes, opts.source)?;
    build_preset(api, opts)
}

async fn fetch(source: &str) -> Result<Vec<u8>> {
    if source.starts_with("http://") || source.starts_with("https://") {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| WardenError::Validation(format!("http client: {e}")))?;
        let resp = client
            .get(source)
            .send()
            .await
            .map_err(|e| WardenError::Validation(format!("fetch failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(WardenError::Validation(format!(
                "fetch returned HTTP {}",
                resp.status()
            )));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| WardenError::Validation(format!("read body: {e}")))?;
        if bytes.len() > MAX_SPEC_BYTES {
            return Err(WardenError::Validation(format!(
                "spec too large ({} bytes, cap {} MB)",
                bytes.len(),
                MAX_SPEC_BYTES / 1024 / 1024
            )));
        }
        Ok(bytes.to_vec())
    } else {
        // Treat as filesystem path. Reject anything outside $HOME or /tmp to
        // avoid trickery (e.g. reading /etc/* via a fake spec arg).
        let path = Path::new(source);
        let canonical = path
            .canonicalize()
            .map_err(|e| WardenError::Validation(format!("cannot resolve path: {e}")))?;
        let home = std::env::var("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("/"));
        if !(canonical.starts_with(&home) || canonical.starts_with("/tmp")) {
            return Err(WardenError::Validation(
                "path must be under $HOME or /tmp/".into(),
            ));
        }
        let bytes = std::fs::read(&canonical).map_err(WardenError::Io)?;
        if bytes.len() > MAX_SPEC_BYTES {
            return Err(WardenError::Validation(format!(
                "spec too large ({} bytes, cap {} MB)",
                bytes.len(),
                MAX_SPEC_BYTES / 1024 / 1024
            )));
        }
        Ok(bytes)
    }
}

fn parse_spec(bytes: &[u8], source: &str) -> Result<OpenAPI> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| WardenError::Validation(format!("spec is not utf-8: {e}")))?;
    let is_yaml = source.ends_with(".yaml")
        || source.ends_with(".yml")
        || !text.trim_start().starts_with('{');
    let api: OpenAPI = if is_yaml {
        serde_yaml::from_str(text)
            .map_err(|e| WardenError::Validation(format!("yaml parse failed: {e}")))?
    } else {
        serde_json::from_str(text)
            .map_err(|e| WardenError::Validation(format!("json parse failed: {e}")))?
    };
    Ok(api)
}

fn build_preset(api: OpenAPI, opts: FromOpenapiOptions<'_>) -> Result<Bootstrapped> {
    let base_url = opts
        .base_url_override
        .map(String::from)
        .or_else(|| api.servers.first().map(|s| s.url.clone()))
        .ok_or_else(|| {
            WardenError::Validation(
                "spec has no servers[] and no --base-url provided — cannot pick base URL".into(),
            )
        })?;

    let preset_name = opts
        .name_override
        .map(String::from)
        .unwrap_or_else(|| kebab_case(&api.info.title));

    let tag_filter: Option<BTreeSet<&str>> = opts
        .tag_filter
        .map(|tags| tags.iter().map(|s| s.as_str()).collect());
    let method_filter: Option<BTreeSet<String>> = opts
        .method_filter
        .map(|ms| ms.iter().map(|m| m.to_uppercase()).collect());

    let mut paths: BTreeSet<String> = BTreeSet::new();
    let mut methods: BTreeSet<String> = BTreeSet::new();
    let mut op_count: usize = 0;

    for (path, item) in &api.paths.paths {
        let ReferenceOr::Item(item) = item else {
            continue;
        };
        for (method, op) in operations(item) {
            if let Some(filter) = &method_filter
                && !filter.contains(&method)
            {
                continue;
            }
            if let Some(tags) = &tag_filter {
                let op_tags: BTreeSet<&str> = op.tags.iter().map(|s| s.as_str()).collect();
                if op_tags.is_disjoint(tags) {
                    continue;
                }
            }
            paths.insert(path.clone());
            methods.insert(method.clone());
            op_count += 1;
        }
    }

    if op_count == 0 {
        return Err(WardenError::Validation(
            "no operations matched the filters — preset would be empty".into(),
        ));
    }

    let auth = pick_auth(&api, opts.secret_name);

    let preset = Preset {
        name: preset_name,
        preset_type: PresetType::Http,
        description: format!(
            "Generated from OpenAPI spec: {} (v{}) — {} operations",
            api.info.title, api.info.version, op_count
        ),
        base_url: Some(base_url),
        auth,
        allowed_paths: paths.into_iter().collect(),
        allowed_methods: methods.into_iter().collect(),
        approval: opts.approval,
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
    };
    Ok(Bootstrapped {
        spec_title: api.info.title,
        spec_version: api.info.version,
        operation_count: op_count,
        source: opts.source.to_string(),
        preset,
    })
}

fn operations(item: &openapiv3::PathItem) -> Vec<(String, &openapiv3::Operation)> {
    let mut out: Vec<(String, &openapiv3::Operation)> = Vec::new();
    if let Some(op) = &item.get {
        out.push(("GET".into(), op));
    }
    if let Some(op) = &item.post {
        out.push(("POST".into(), op));
    }
    if let Some(op) = &item.put {
        out.push(("PUT".into(), op));
    }
    if let Some(op) = &item.patch {
        out.push(("PATCH".into(), op));
    }
    if let Some(op) = &item.delete {
        out.push(("DELETE".into(), op));
    }
    if let Some(op) = &item.head {
        out.push(("HEAD".into(), op));
    }
    if let Some(op) = &item.options {
        out.push(("OPTIONS".into(), op));
    }
    out
}

fn pick_auth(api: &OpenAPI, secret_name: Option<&str>) -> Option<Auth> {
    let secret = secret_name.unwrap_or("api_token").to_string();
    let Some(components) = &api.components else {
        return None;
    };
    for (_, scheme) in &components.security_schemes {
        let ReferenceOr::Item(scheme) = scheme else {
            continue;
        };
        match scheme {
            SecurityScheme::HTTP { scheme: s, .. } if s.eq_ignore_ascii_case("bearer") => {
                return Some(Auth::Bearer { secret });
            }
            SecurityScheme::APIKey { name, location, .. } => {
                if matches!(location, openapiv3::APIKeyLocation::Header) {
                    return Some(Auth::Header {
                        name: name.clone(),
                        secret,
                        prefix: None,
                    });
                }
            }
            _ => {}
        }
    }
    None
}

fn kebab_case(s: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for ch in s.chars() {
        if ch.is_alphanumeric() {
            for c in ch.to_lowercase() {
                out.push(c);
            }
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PETSTORE_JSON: &str = r#"{
        "openapi": "3.0.0",
        "info": {"title": "Pet Store", "version": "1.0.0"},
        "servers": [{"url": "https://api.petstore.example.com/v1"}],
        "paths": {
            "/pets": {
                "get": {"tags": ["pets"], "responses": {"200": {"description": "ok"}}},
                "post": {"tags": ["pets"], "responses": {"201": {"description": "created"}}}
            },
            "/pets/{id}": {
                "get": {"tags": ["pets"], "responses": {"200": {"description": "ok"}}},
                "delete": {"tags": ["admin"], "responses": {"204": {"description": "ok"}}}
            },
            "/healthz": {
                "get": {"responses": {"200": {"description": "ok"}}}
            }
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer"}
            }
        }
    }"#;

    fn opts<'a>() -> FromOpenapiOptions<'a> {
        FromOpenapiOptions {
            source: "test://inline",
            name_override: None,
            secret_name: None,
            base_url_override: None,
            method_filter: None,
            tag_filter: None,
            approval: ApprovalPolicy::Prompt,
        }
    }

    #[test]
    fn parses_petstore_json() {
        let api = parse_spec(PETSTORE_JSON.as_bytes(), "test.json").unwrap();
        let b = build_preset(api, opts()).unwrap();
        assert_eq!(b.spec_title, "Pet Store");
        assert_eq!(
            b.preset.base_url.as_deref(),
            Some("https://api.petstore.example.com/v1")
        );
        let methods: BTreeSet<String> = b.preset.allowed_methods.iter().cloned().collect();
        assert!(methods.contains("GET"));
        assert!(methods.contains("POST"));
        assert!(methods.contains("DELETE"));
        let paths: BTreeSet<String> = b.preset.allowed_paths.iter().cloned().collect();
        assert!(paths.contains("/pets"));
        assert!(paths.contains("/pets/{id}"));
        assert!(paths.contains("/healthz"));
        match b.preset.auth.as_ref().unwrap() {
            Auth::Bearer { secret } => assert_eq!(secret, "api_token"),
            _ => panic!("expected Bearer"),
        }
    }

    #[test]
    fn method_filter_restricts() {
        let api = parse_spec(PETSTORE_JSON.as_bytes(), "test.json").unwrap();
        let methods = vec!["GET".to_string()];
        let mut o = opts();
        o.method_filter = Some(&methods);
        let b = build_preset(api, o).unwrap();
        assert_eq!(b.preset.allowed_methods, vec!["GET".to_string()]);
        assert!(!b.preset.allowed_paths.is_empty());
    }

    #[test]
    fn tag_filter_restricts() {
        let api = parse_spec(PETSTORE_JSON.as_bytes(), "test.json").unwrap();
        let tags = vec!["admin".to_string()];
        let mut o = opts();
        o.tag_filter = Some(&tags);
        let b = build_preset(api, o).unwrap();
        assert_eq!(b.preset.allowed_methods, vec!["DELETE".to_string()]);
        assert_eq!(b.preset.allowed_paths, vec!["/pets/{id}".to_string()]);
    }

    #[test]
    fn kebab_case_works() {
        assert_eq!(kebab_case("Pet Store"), "pet-store");
        assert_eq!(kebab_case("My API v2"), "my-api-v2");
        assert_eq!(kebab_case("  Slack Web API  "), "slack-web-api");
    }

    #[test]
    fn name_override_wins() {
        let api = parse_spec(PETSTORE_JSON.as_bytes(), "test.json").unwrap();
        let mut o = opts();
        o.name_override = Some("petstore-prod");
        let b = build_preset(api, o).unwrap();
        assert_eq!(b.preset.name, "petstore-prod");
    }
}
