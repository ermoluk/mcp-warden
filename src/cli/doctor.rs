use clap::Args;
use mcp_warden_core::config::{ApprovalPolicy, Auth, Config, Preset, PresetType};
use mcp_warden_core::error::Result;
use mcp_warden_core::keychain::KeychainStore;
use serde::Serialize;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Run safe read-only probes against each preset (currently HTTP only).
    #[arg(long)]
    pub deep: bool,
    /// Include presets with `approval = "prompt"`. Off by default to keep
    /// `--deep` non-interactive.
    #[arg(long)]
    pub include_prompt: bool,
    /// Probe timeout in seconds (HTTP only). Default 10.
    #[arg(long, default_value_t = 10)]
    pub timeout_seconds: u64,
    /// Output format: text (default) or json.
    #[arg(long, value_parser = ["text", "json"], default_value = "text")]
    pub format: String,
}

pub async fn run(args: DoctorArgs, config_dir: &Path, kc: &dyn KeychainStore) -> Result<()> {
    let cfg_path = config_dir.join("config.toml");
    let db_path = config_dir.join("audit.db");

    println!("mcp-warden v{}", env!("CARGO_PKG_VERSION"));
    println!("config dir: {}", config_dir.display());
    println!(
        "config:     {} ({})",
        cfg_path.display(),
        if cfg_path.exists() {
            "OK"
        } else {
            "MISSING — run `mcp-warden init`"
        }
    );
    println!(
        "audit db:   {} ({})",
        db_path.display(),
        if db_path.exists() {
            "OK"
        } else {
            "absent (created on first MCP call)"
        }
    );
    let names = kc.list_names().unwrap_or_default();
    println!("secrets:    {} stored", names.len());

    let cfg = if let Ok(raw) = std::fs::read_to_string(&cfg_path) {
        match toml::from_str::<Config>(&raw) {
            Ok(cfg) => match cfg.validate(kc) {
                Ok(()) => {
                    println!("validation: OK ({} preset(s))", cfg.preset.len());
                    Some(cfg)
                }
                Err(e) => {
                    println!("validation: FAIL — {e}");
                    None
                }
            },
            Err(e) => {
                println!("config parse: FAIL — {e}");
                None
            }
        }
    } else {
        None
    };

    #[cfg(target_os = "macos")]
    println!(
        "note (macos): unsigned binaries may degrade desktop notifications; the TUI fallback handles approval prompts."
    );

    if args.deep {
        if let Some(cfg) = cfg {
            println!();
            println!("--- deep probes ---");
            let results = run_probes(&cfg, kc, &args).await;
            match args.format.as_str() {
                "json" => {
                    println!("{}", serde_json::to_string_pretty(&results).unwrap());
                }
                _ => print_probe_table(&results),
            }
        } else {
            println!("(skipping --deep probes: config invalid)");
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct ProbeResult {
    pub preset: String,
    pub kind: &'static str,
    pub status: ProbeStatus,
    pub detail: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Ok,
    AuthOkEndpointMissing,
    AuthFailed,
    NetworkError,
    TlsError,
    Skipped,
}

impl ProbeStatus {
    fn label(&self) -> &'static str {
        match self {
            ProbeStatus::Ok => "ok",
            ProbeStatus::AuthOkEndpointMissing => "auth_ok_404",
            ProbeStatus::AuthFailed => "auth_failed",
            ProbeStatus::NetworkError => "network_error",
            ProbeStatus::TlsError => "tls_error",
            ProbeStatus::Skipped => "skipped",
        }
    }
}

async fn run_probes(cfg: &Config, kc: &dyn KeychainStore, args: &DoctorArgs) -> Vec<ProbeResult> {
    let mut out = Vec::with_capacity(cfg.preset.len());
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout_seconds))
        .build()
        .ok();

    for p in &cfg.preset {
        let kind = match p.preset_type {
            PresetType::Http => "http",
            PresetType::Ssh => "ssh",
            PresetType::Postgres => "postgres",
            PresetType::Mysql => "mysql",
            PresetType::Redis => "redis",
        };

        // Skip prompt-policy presets unless explicitly included.
        if matches!(p.approval, ApprovalPolicy::Prompt) && !args.include_prompt {
            out.push(ProbeResult {
                preset: p.name.clone(),
                kind,
                status: ProbeStatus::Skipped,
                detail: "approval=prompt — re-run with --include-prompt for interactive probe"
                    .into(),
            });
            continue;
        }
        if matches!(p.approval, ApprovalPolicy::Deny) {
            out.push(ProbeResult {
                preset: p.name.clone(),
                kind,
                status: ProbeStatus::Skipped,
                detail: "approval=deny".into(),
            });
            continue;
        }

        match p.preset_type {
            PresetType::Http => {
                let (status, detail) = probe_http(p, kc, client.as_ref()).await;
                out.push(ProbeResult {
                    preset: p.name.clone(),
                    kind,
                    status,
                    detail,
                });
            }
            PresetType::Ssh | PresetType::Postgres | PresetType::Mysql | PresetType::Redis => {
                out.push(ProbeResult {
                    preset: p.name.clone(),
                    kind,
                    status: ProbeStatus::Skipped,
                    detail: format!("{kind} probe not implemented in --deep MVP — HTTP only"),
                });
            }
        }
    }
    out
}

async fn probe_http(
    p: &Preset,
    kc: &dyn KeychainStore,
    client: Option<&reqwest::Client>,
) -> (ProbeStatus, String) {
    let Some(client) = client else {
        return (
            ProbeStatus::NetworkError,
            "could not build reqwest client".into(),
        );
    };
    let Some(base_url) = &p.base_url else {
        return (ProbeStatus::Skipped, "no base_url on preset".into());
    };
    if !p
        .allowed_methods
        .iter()
        .any(|m| m.eq_ignore_ascii_case("GET"))
    {
        return (
            ProbeStatus::Skipped,
            "GET not in allowed_methods — cannot run safe read-only probe".into(),
        );
    }

    let probe_path = pick_probe_path(&p.allowed_paths);
    let url = format!("{}{}", base_url.trim_end_matches('/'), probe_path);

    // Fetch the secret (if any) from keychain.
    let secret = if let Some(auth) = &p.auth {
        let secret_name = match auth {
            Auth::Bearer { secret } => Some(secret),
            Auth::Header { secret, .. } => Some(secret),
            Auth::Basic { secret, .. } => Some(secret),
        };
        match secret_name {
            Some(name) => match kc.get(name) {
                Ok(Some(s)) => Some(s),
                Ok(None) => {
                    return (
                        ProbeStatus::Skipped,
                        format!("secret '{name}' not found in keychain"),
                    );
                }
                Err(e) => {
                    return (ProbeStatus::Skipped, format!("keychain read failed: {e}"));
                }
            },
            None => None,
        }
    } else {
        None
    };

    let mut req = client.get(&url);
    if let (Some(auth), Some(secret)) = (&p.auth, secret.as_ref()) {
        req = inject_auth(req, auth, secret);
    }

    let started = Instant::now();
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            let lower = msg.to_lowercase();
            let status = if lower.contains("tls") || lower.contains("certificate") {
                ProbeStatus::TlsError
            } else {
                ProbeStatus::NetworkError
            };
            return (status, redact(&truncate(&msg, 200)));
        }
    };
    let elapsed = started.elapsed().as_millis();
    let code = resp.status();
    let body_snippet = match resp.text().await {
        Ok(t) => redact(&truncate(&t, 80)),
        Err(_) => String::new(),
    };

    let status = if code.is_success() {
        ProbeStatus::Ok
    } else if code.as_u16() == 401 || code.as_u16() == 403 {
        ProbeStatus::AuthFailed
    } else {
        ProbeStatus::AuthOkEndpointMissing
    };

    let body_part = if body_snippet.is_empty() {
        String::new()
    } else {
        format!(": {body_snippet}")
    };
    (
        status,
        format!(
            "GET {probe_path} → {} ({elapsed} ms){body_part}",
            code.as_u16()
        ),
    )
}

fn pick_probe_path(allowed_paths: &[String]) -> String {
    if allowed_paths.is_empty() {
        return "/".into();
    }
    let regex_chars = [
        '{', '}', '(', ')', '[', ']', '^', '$', '+', '*', '?', '|', '\\',
    ];
    for p in allowed_paths {
        if !p.chars().any(|c| regex_chars.contains(&c)) {
            return p.clone();
        }
    }
    "/".into()
}

fn inject_auth(
    b: reqwest::RequestBuilder,
    auth: &Auth,
    secret: &mcp_warden_core::secret::Secret,
) -> reqwest::RequestBuilder {
    match auth {
        Auth::Bearer { .. } => b.bearer_auth(secret.expose()),
        Auth::Header { name, prefix, .. } => {
            let value = match prefix {
                Some(p) => format!("{p}{}", secret.expose()),
                None => secret.expose().to_string(),
            };
            b.header(name, value)
        }
        Auth::Basic { username, .. } => b.basic_auth(username, Some(secret.expose())),
    }
}

fn truncate(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

/// Conservative redaction for snippets shown in probe output. Replaces
/// anything that looks like a credential or known sensitive key with
/// `<redacted>`. We're paranoid here on purpose — `doctor --deep` runs
/// against the user's real services, the snippet ends up in their
/// terminal, and a missed redaction is much worse than an over-eager one.
fn redact(s: &str) -> String {
    let lower = s.to_lowercase();
    let needles = [
        "bearer ",
        "password",
        "token",
        "secret",
        "api_key",
        "apikey",
        "authorization",
    ];
    if needles.iter().any(|n| lower.contains(n)) {
        return "<redacted>".into();
    }
    s.to_string()
}

fn print_probe_table(results: &[ProbeResult]) {
    let name_w = results
        .iter()
        .map(|r| r.preset.len())
        .max()
        .unwrap_or(8)
        .max(8);
    let kind_w = 6;
    let status_w = 14;
    println!(
        "{:<name_w$}  {:<kind_w$}  {:<status_w$}  Detail",
        "Preset", "Kind", "Status"
    );
    for r in results {
        println!(
            "{:<name_w$}  {:<kind_w$}  {:<status_w$}  {}",
            r.preset,
            r.kind,
            r.status.label(),
            r.detail,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_probe_path_prefers_literal() {
        assert_eq!(pick_probe_path(&[]), "/");
        assert_eq!(pick_probe_path(&["/users".into()]), "/users");
        assert_eq!(
            pick_probe_path(&["/users/[a-z]+".into(), "/healthz".into()]),
            "/healthz"
        );
        assert_eq!(pick_probe_path(&["/users/[a-z]+".into()]), "/");
    }

    #[test]
    fn redact_catches_common_secrets() {
        assert_eq!(redact("hello world"), "hello world");
        assert_eq!(redact("Bearer abc123"), "<redacted>");
        assert_eq!(redact("the api_key is wrong"), "<redacted>");
        assert_eq!(redact("Invalid token"), "<redacted>");
    }

    #[test]
    fn truncate_respects_unicode() {
        assert_eq!(truncate("abc", 10), "abc");
        let s = truncate("abcdefghij", 5);
        assert!(s.chars().count() <= 6);
    }
}
