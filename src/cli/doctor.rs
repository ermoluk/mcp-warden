use crate::cli::preset::unrestricted_paths_warning;
use crate::executor::ActionExecutor;
use crate::executor::credential_echo::CredentialForms;
use clap::Args;
use mcp_warden_core::audit::AuditOutcome;
use mcp_warden_core::audit::sqlite_sink::LocalSqlite;
use mcp_warden_core::config::{ApprovalPolicy, Config, Preset, PresetType};
use mcp_warden_core::error::Result;
use mcp_warden_core::keychain::KeychainStore;
use serde::Serialize;
use std::path::Path;
use std::sync::Arc;
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

pub async fn run(args: DoctorArgs, config_dir: &Path, store: Arc<dyn KeychainStore>) -> Result<()> {
    let kc = store.as_ref();
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
    if db_path.exists() {
        println!("audit chain: {}", audit_chain_status(&db_path, kc));
    }
    let names: Vec<String> = kc
        .list_names()
        .unwrap_or_default()
        .into_iter()
        .filter(|n| !mcp_warden_core::stamp::is_reserved_name(n))
        .collect();
    println!("secrets:    {} stored", names.len());
    match crate::executor::lock::read(&config_dir.join(crate::executor::lock::LOCK_FILE)) {
        Some(info) => println!(
            "lock:       LOCKED — {} (`mcp-warden unlock`)",
            info.describe()
        ),
        None => println!("lock:       not locked"),
    }

    let cfg = if let Ok(raw) = std::fs::read_to_string(&cfg_path) {
        match toml::from_str::<Config>(&raw) {
            Ok(cfg) => {
                let valid = match cfg.validate(kc) {
                    Ok(()) => {
                        println!("validation: OK ({} preset(s))", cfg.preset.len());
                        true
                    }
                    Err(e) => {
                        println!("validation: FAIL — {e}");
                        false
                    }
                };
                // Scope warnings are about the config itself, so they are
                // shown even when the keychain check fails.
                for w in cfg.preset.iter().filter_map(unrestricted_paths_warning) {
                    println!("warning:    {w}");
                }
                for w in access_warnings(&cfg, kc, chrono::Utc::now()) {
                    println!("warning:    {w}");
                }
                for w in cfg.preset.iter().flat_map(pattern_warnings) {
                    println!("warning:    {w}");
                }
                for w in cfg.preset.iter().flat_map(command_warnings) {
                    println!("warning:    {w}");
                }
                for w in cfg.preset.iter().flat_map(query_warnings) {
                    println!("warning:    {w}");
                }
                valid.then_some(cfg)
            }
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
        "note (macos): `prompt` presets ask in a native dialog titled \"mcp-warden — approval requested\"."
    );

    if args.deep {
        if let Some(cfg) = cfg {
            println!();
            println!("--- deep probes ---");
            // Probes use real credentials: each goes through the approval
            // policy and the audit log like a `proxy_http` call, so a
            // `prompt` preset asks a human first (with --include-prompt).
            let transports = crate::cli::mcp::build_approval(&cfg, kc, config_dir)?;
            std::fs::create_dir_all(config_dir).map_err(mcp_warden_core::error::WardenError::Io)?;
            let audit = Arc::new(LocalSqlite::open(&db_path)?);
            let exec = ActionExecutor::new(
                store.clone(),
                transports.primary,
                transports.fallback,
                audit,
            )
            .with_lock(config_dir.join(crate::executor::lock::LOCK_FILE))
            .with_state_dir(config_dir.to_path_buf());
            let results = run_probes(&cfg, kc, &args, &exec).await;
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
    /// Config scope warnings for this preset (e.g. no `allowed_paths`).
    pub warnings: Vec<String>,
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

async fn run_probes(
    cfg: &Config,
    kc: &dyn KeychainStore,
    args: &DoctorArgs,
    exec: &ActionExecutor,
) -> Vec<ProbeResult> {
    let mut out = Vec::with_capacity(cfg.preset.len());
    // Never follow redirects with credentials attached, and never send a
    // plain-http (loopback) probe through a proxy — see executor/http.rs.
    let build = |plain: bool| {
        crate::executor::http::direct_if_plain(reqwest::Client::builder(), plain)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(args.timeout_seconds))
            .build()
            .ok()
    };
    let (client, direct) = (build(false), build(true));

    for p in &cfg.preset {
        let kind = match p.preset_type {
            PresetType::Http => "http",
            PresetType::Ssh => "ssh",
            PresetType::Postgres => "postgres",
            PresetType::Mysql => "mysql",
            PresetType::Redis => "redis",
        };
        let warnings: Vec<String> = unrestricted_paths_warning(p).into_iter().collect();

        // Skip prompt-policy presets unless explicitly included.
        if matches!(p.approval, ApprovalPolicy::Prompt) && !args.include_prompt {
            out.push(ProbeResult {
                preset: p.name.clone(),
                kind,
                status: ProbeStatus::Skipped,
                detail: "approval=prompt — re-run with --include-prompt for interactive probe"
                    .into(),
                warnings,
            });
            continue;
        }
        if matches!(p.approval, ApprovalPolicy::Deny) {
            out.push(ProbeResult {
                preset: p.name.clone(),
                kind,
                status: ProbeStatus::Skipped,
                detail: "approval=deny".into(),
                warnings,
            });
            continue;
        }

        match p.preset_type {
            PresetType::Http => {
                let summary = format!(
                    "doctor --deep probe: GET {}",
                    pick_probe_path(&p.allowed_paths)
                );
                let event = exec
                    .check_lock(&p.name, "doctor_probe", &summary)
                    .await
                    .and(exec.authorise(p, "doctor_probe", &summary, false).await);
                let event = match event {
                    Ok(id) => id,
                    Err(e) => {
                        out.push(ProbeResult {
                            preset: p.name.clone(),
                            kind,
                            status: ProbeStatus::Skipped,
                            detail: format!("not probed: {e}"),
                            warnings,
                        });
                        continue;
                    }
                };
                let plain = p
                    .base_url
                    .as_deref()
                    .is_some_and(|u| u.starts_with("http://"));
                let probe_client = if plain { &direct } else { &client };
                let (status, detail) =
                    probe_http(p, kc, exec.state_dir.as_deref(), probe_client.as_ref()).await;
                let _ = exec.audit.record_outcome(
                    event,
                    match status {
                        ProbeStatus::Ok => AuditOutcome::Ok { status: 200 },
                        _ => AuditOutcome::Err {
                            message: detail.clone(),
                        },
                    },
                );
                out.push(ProbeResult {
                    preset: p.name.clone(),
                    kind,
                    status,
                    detail,
                    warnings,
                });
            }
            PresetType::Ssh | PresetType::Postgres | PresetType::Mysql | PresetType::Redis => {
                out.push(ProbeResult {
                    preset: p.name.clone(),
                    kind,
                    status: ProbeStatus::Skipped,
                    detail: format!("{kind} probe not implemented in --deep MVP — HTTP only"),
                    warnings,
                });
            }
        }
    }
    out
}

/// One line on the audit log's hash chain and its keychain anchor; the
/// details are `mcp-warden audit verify`'s.
pub(crate) fn audit_chain_status(db: &Path, kc: &dyn KeychainStore) -> String {
    use mcp_warden_core::audit::AuditSink;
    use mcp_warden_core::audit::anchor::{self, AnchorCheck};
    let sink = match mcp_warden_core::audit::sqlite_sink::LocalSqlite::open(db) {
        Ok(s) => s,
        Err(e) => return format!("cannot open the audit log: {e}"),
    };
    let report = match sink.verify_chain() {
        Ok(r) => r,
        Err(e) => return format!("cannot check: {e}"),
    };
    if let Some(first) = report.problems.first() {
        return format!(
            "BROKEN — {} (`mcp-warden audit verify` lists everything)",
            crate::cli::audit::for_terminal(first, 160)
        );
    }
    let anchor = match anchor::check(kc, &sink, db) {
        Ok(AnchorCheck::NotAnchored) => "not anchored yet".to_string(),
        Ok(AnchorCheck::Anchored { seq, .. }) => format!("anchored through record {seq}"),
        Ok(AnchorCheck::Removed { seq }) => {
            format!("BROKEN — records up to the anchored {seq} are gone")
        }
        Ok(AnchorCheck::Rewritten { seq }) => {
            format!("BROKEN — rewritten before the anchored record {seq}")
        }
        Err(e) => format!("anchor unreadable: {e}"),
    };
    format!("intact, {} records; {anchor}", report.records)
}

async fn probe_http(
    p: &Preset,
    kc: &dyn KeychainStore,
    state_dir: Option<&Path>,
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

    // The credential, if the preset has one; put on the request and turned
    // into scrub forms the way proxy_http does.
    let mut req = client.get(&url);
    let forms = match &p.auth {
        Some(_) => match crate::executor::auth::load(kc, p) {
            Ok(mut credential) => {
                // OAuth2 mints a token, as a real call would.
                if let Err(e) = credential.prepare(kc, state_dir, p).await {
                    let e = credential.forms().scrub_error(e);
                    return (
                        ProbeStatus::AuthFailed,
                        redact(&truncate(&e.to_string(), 200)),
                    );
                }
                req = credential.apply(req);
                credential.forms()
            }
            Err(mcp_warden_core::error::WardenError::MissingSecret { secret, .. }) => {
                return (
                    ProbeStatus::Skipped,
                    format!("secret '{secret}' not found in keychain"),
                );
            }
            Err(e) => {
                return (ProbeStatus::Skipped, format!("keychain read failed: {e}"));
            }
        },
        None => CredentialForms::raw(&mcp_warden_core::secret::Secret::new(String::new())),
    };
    let scrubbed = |mut text: String| {
        forms.scrub_text(&mut text);
        text
    };

    let started = Instant::now();
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            let msg = scrubbed(crate::executor::http::error_text(e));
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
    // At most 64 KiB of it: the snippet is 80 characters.
    let body_snippet = match read_prefix(resp, 64 * 1024).await {
        Some(t) => redact(&truncate(&scrubbed(t), 80)),
        None => String::new(),
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

/// The first `max` bytes of the body, as text.
async fn read_prefix(mut resp: reqwest::Response, max: usize) -> Option<String> {
    let mut buf = Vec::new();
    while buf.len() < max {
        match resp.chunk().await {
            Ok(Some(chunk)) => buf.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(_) => return None,
        }
    }
    buf.truncate(max);
    Some(String::from_utf8_lossy(&buf).into_owned())
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

/// Named Redis queries whose command can run code on the server, rewrite
/// its configuration, wipe or move data, or read it back wholesale — the
/// agent picks the arguments, so such a query is close to raw access.
/// mcp-warden runs only the named queries; this only points them out.
pub(crate) fn query_warnings(p: &Preset) -> Vec<String> {
    const RISKY: &[&str] = &[
        "EVAL",
        "EVALSHA",
        "EVAL_RO",
        "EVALSHA_RO",
        "FCALL",
        "FCALL_RO",
        "FUNCTION",
        "SCRIPT",
        "CONFIG",
        "MODULE",
        "DEBUG",
        "ACL",
        "FLUSHALL",
        "FLUSHDB",
        "SHUTDOWN",
        "REPLICAOF",
        "SLAVEOF",
        "MIGRATE",
        "RESTORE",
        "KEYS",
        "SAVE",
        "BGSAVE",
        "BGREWRITEAOF",
        "CLIENT",
    ];
    if p.preset_type != PresetType::Redis {
        return Vec::new();
    }
    p.queries
        .iter()
        .filter_map(|q| {
            let command = q.template.split_whitespace().next()?.to_ascii_uppercase();
            RISKY.contains(&command.as_str()).then(|| {
                format!(
                    "preset '{}': named query '{}' runs `{command}`, which can run code, change \
                     the server's configuration or reach every key; the agent chooses its \
                     arguments",
                    p.name, q.name
                )
            })
        })
        .collect()
}

/// `allowed_commands` patterns that let the agent turn an argument into an
/// option of its own: wherever a pattern takes an argument after a space, a
/// class that can match `-` there (`[a-z0-9_-]+`, `\S+`, `.*`, `[^ ]+`)
/// admits `systemctl status -Hevil`, `git checkout -f`, `tar --to-command=…`.
/// Options the author wrote out (` -n `, ` --tail `) are not flagged. A
/// heuristic: it looks only at what directly follows a space, not inside
/// groups such as ` (a|[a-z-]+)`.
pub(crate) fn pattern_warnings(p: &Preset) -> Vec<String> {
    p.allowed_commands
        .iter()
        .filter_map(|pattern| {
            if argument_may_start_with_dash(pattern) {
                Some(format!(
                    "preset '{}': allowed_commands pattern '{pattern}' lets an argument start \
                     with '-', so the agent can pass options of its own (e.g. `-Hhost`, \
                     `--upload-pack=…`); start it with a character that cannot be one, \
                     e.g. `[a-z0-9][a-z0-9._-]*`",
                    p.name
                ))
            } else if has_catch_all(pattern) {
                Some(format!(
                    "preset '{}': allowed_commands pattern '{pattern}' ends in a catch-all \
                     (`.*`, `.+`, `\\S+`, `[^ ]+`), which also admits arguments you did not \
                     list, e.g. `git pull --upload-pack=…`; list the exact commands, or use \
                     named commands ([[preset.commands]]) with typed parameters",
                    p.name
                ))
            } else {
                None
            }
        })
        .collect()
}

/// Whether `pattern` repeats `.`, `\S` or `[^ ]` (`*` or `+`) anywhere:
/// any of them lets the agent append words of its own.
fn has_catch_all(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let repeated = |at: usize| matches!(bytes.get(at), Some(b'*' | b'+'));
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if bytes.get(i + 1) == Some(&b'S') && repeated(i + 2) => return true,
            b'\\' => i += 2,
            b'.' if repeated(i + 1) => return true,
            b'[' if pattern[i..].starts_with("[^ ]") && repeated(i + 4) => return true,
            _ => i += 1,
        }
    }
    false
}

/// Named commands whose template destroys data or rewrites permissions:
/// each deserves narrow parameters and a prompt.
pub(crate) fn command_warnings(p: &Preset) -> Vec<String> {
    p.commands
        .iter()
        .filter_map(|c| {
            let mut words = c.template.split(' ').peekable();
            if words.peek() == Some(&"sudo") {
                words.next();
                while words.peek().is_some_and(|w| w.starts_with('-')) {
                    words.next();
                }
            }
            let program = words.next()?;
            let recursive = words.any(|w| w == "-R" || w == "-r" || w == "--recursive");
            let what = match program {
                "rm" | "shred" => "deletes files",
                "dd" => "writes raw devices or files",
                p if p.starts_with("mkfs") => "formats a filesystem",
                "chmod" | "chown" if recursive => "rewrites permissions recursively",
                _ => return None,
            };
            Some(format!(
                "preset '{}': command '{}' runs `{program}`, which {what}; keep its parameters \
                 as narrow as possible and its approval at \"prompt\"",
                p.name, c.name
            ))
        })
        .collect()
}

/// Whether some atom right after a space in `pattern` — a class, `.`, `\S`
/// or `\W` — can match `-`.
fn argument_may_start_with_dash(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b' ' => {
                let rest = &pattern[i + 1..];
                let atom = if rest.starts_with('[') {
                    class_end(rest).map(|end| &rest[..end])
                } else if rest.starts_with("\\S") || rest.starts_with("\\W") {
                    Some(&rest[..2])
                } else if rest.starts_with('.') {
                    Some(".")
                } else {
                    None
                };
                if atom
                    .and_then(|a| regex::Regex::new(&format!("^(?:{a})$")).ok())
                    .is_some_and(|rx| rx.is_match("-"))
                {
                    return true;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    false
}

/// Length of the character class `[...]` at the start of `s`, if it closes.
fn class_end(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 1;
    if bytes.get(i) == Some(&b'^') {
        i += 1;
    }
    // A `]` right after `[` or `[^` is a literal.
    if bytes.get(i) == Some(&b']') {
        i += 1;
    }
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b']' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

/// Presets whose `preset grant` window has ended, and wrapped servers whose
/// keys are missing from the keychain.
fn access_warnings(
    cfg: &Config,
    kc: &dyn KeychainStore,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<String> {
    let mut out = Vec::new();
    // `auto` holds only where a human confirmed the preset as it is now;
    // the MCP server runs the others as `prompt`.
    let mut served = cfg.preset.clone();
    out.extend(mcp_warden_core::stamp::demote_unconfirmed_auto(
        &mut served,
        kc,
    ));
    for s in &cfg.server {
        let program = match crate::cli::run::program(s) {
            Ok(program) => program,
            Err(e) => {
                out.push(format!("{e}; `mcp-warden run {}` will refuse", s.name));
                continue;
            }
        };
        let confirmed = mcp_warden_core::stamp::check(
            kc,
            &mcp_warden_core::stamp::server_stamp_name(&s.name),
            &mcp_warden_core::stamp::server_fingerprint(s, &program),
        )
        .is_ok_and(|c| c == mcp_warden_core::stamp::Confirmation::Confirmed);
        if !confirmed {
            out.push(format!(
                "server '{}': not confirmed in its current form, so `mcp-warden run {}` asks \
                 for approval before it starts",
                s.name, s.name
            ));
        }
    }
    for p in &cfg.preset {
        if crate::executor::policy::check_expiry(p, now).is_err() {
            out.push(format!(
                "preset '{}': access has expired (`mcp-warden preset grant {} --for 1h`)",
                p.name, p.name
            ));
        }
    }
    for s in &cfg.server {
        for var in &s.env {
            let entry = s.secret_name(var);
            if !matches!(kc.get(&entry), Ok(Some(_))) {
                out.push(format!(
                    "server '{}': keychain has no '{entry}', so `mcp-warden run {}` will refuse",
                    s.name, s.name
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_warden_core::approval::ApprovalDecision;

    #[test]
    fn access_warnings_flag_expired_presets_and_missing_server_keys() {
        use mcp_warden_core::keychain::memory::InMemoryKeychain;
        use mcp_warden_core::secret::Secret;
        let now = chrono::Utc::now();
        let mut cfg: Config = toml::from_str(
            r#"
            [[preset]]
            name = "gh"
            type = "http"
            description = "x"
            base_url = "https://api.github.com"
            approval = "prompt"

            [[server]]
            name = "github"
            command = "npx"
            env = ["A", "B"]
            "#,
        )
        .unwrap();
        // A program that exists on every platform the tests run on.
        let program = std::env::current_exe().unwrap();
        cfg.server[0].command = program.display().to_string();
        cfg.preset[0].expires_at = Some(now - chrono::Duration::minutes(1));
        let kc = InMemoryKeychain::new();
        kc.set("server/github/A", Secret::new("v".into())).unwrap();
        let w = access_warnings(&cfg, &kc, now);
        assert_eq!(w.len(), 3, "{w:?}");
        assert!(w[0].contains("server 'github': not confirmed"));
        assert!(w[1].contains("'gh': access has expired"));
        assert!(w[2].contains("'server/github/B'"));

        cfg.preset[0].expires_at = Some(now + chrono::Duration::hours(1));
        kc.set("server/github/B", Secret::new("v".into())).unwrap();
        mcp_warden_core::stamp::record(
            &kc,
            &mcp_warden_core::stamp::server_stamp_name("github"),
            &mcp_warden_core::stamp::server_fingerprint(&cfg.server[0], &program),
        )
        .unwrap();
        assert!(access_warnings(&cfg, &kc, now).is_empty());

        // An auto preset that nobody confirmed is reported too.
        cfg.preset[0].approval = ApprovalPolicy::Auto;
        let w = access_warnings(&cfg, &kc, now);
        assert!(w[0].contains("has not been confirmed"), "{w:?}");
    }

    fn ssh_with(patterns: &[&str]) -> Preset {
        let mut p: Preset = toml::from_str(
            r#"
            name = "box"
            type = "ssh"
            description = "x"
            host = "h"
            user = "u"
            secret = "k"
            approval = "prompt"
            "#,
        )
        .unwrap();
        p.allowed_commands = patterns.iter().map(|s| s.to_string()).collect();
        p
    }

    #[test]
    fn risky_redis_queries_are_flagged() {
        let mut p: Preset = toml::from_str(
            r#"
            name = "cache"
            type = "redis"
            description = "x"
            host = "localhost"
            secret = "k"
            approval = "prompt"
            [[queries]]
            name = "get"
            template = "GET"
            [[queries]]
            name = "run"
            template = "eval"
            [[queries]]
            name = "pw"
            template = "CONFIG"
            "#,
        )
        .unwrap();
        let w = query_warnings(&p);
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(
            w[0].contains("'run' runs `EVAL`") && w[1].contains("`CONFIG`"),
            "{w:?}"
        );
        p.preset_type = PresetType::Postgres;
        assert!(query_warnings(&p).is_empty());
    }

    #[test]
    fn arguments_that_may_be_options_are_flagged() {
        for loose in [
            "^systemctl status [a-z0-9_-]+$",
            "git checkout [-a-z]+",
            "git checkout [a-z\\-]+",
            "git pull .*",
            "git checkout \\S+",
            "cat [^ ]+",
        ] {
            let w = pattern_warnings(&ssh_with(&[loose]));
            assert_eq!(w.len(), 1, "{loose}: {w:?}");
            assert!(w[0].contains("start with '-'"), "{w:?}");
        }
        for tight in [
            "^systemctl status [a-z0-9][a-z0-9_-]*$",
            "^docker compose (pull|up -d|ps|logs --tail \\d+)$",
            "^tail -n [0-9]+ /var/log/app/[a-z0-9._-]+$",
            "journalctl -u app -n [1-9][0-9]{0,2}",
            "git checkout [\\w/]+",
            "uptime",
        ] {
            assert!(pattern_warnings(&ssh_with(&[tight])).is_empty(), "{tight}");
        }
    }

    #[test]
    fn doctor_reports_the_audit_chain() {
        use mcp_warden_core::audit::AuditSink;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("audit.db");
        let sink = mcp_warden_core::audit::sqlite_sink::LocalSqlite::open(&db).unwrap();
        sink.record_pending("p", "proxy_http", "GET /").unwrap();
        let kc = mcp_warden_core::keychain::memory::InMemoryKeychain::new();
        assert_eq!(
            audit_chain_status(&db, &kc),
            "intact, 2 records; not anchored yet"
        );
        mcp_warden_core::audit::anchor::advance(&kc, &sink, &db, None).unwrap();
        assert_eq!(
            audit_chain_status(&db, &kc),
            "intact, 2 records; anchored through record 2"
        );
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch("UPDATE events SET summary = 'x' WHERE id = 1")
            .unwrap();
        assert!(audit_chain_status(&db, &kc).starts_with("BROKEN — event 1 changed"));
    }

    #[test]
    fn catch_all_patterns_are_flagged() {
        for loose in ["git pull.*", "ls -la.+", "cat /var/log/\\S+", "echo x[^ ]*"] {
            let w = pattern_warnings(&ssh_with(&[loose]));
            assert_eq!(w.len(), 1, "{loose}: {w:?}");
            assert!(w[0].contains("catch-all"), "{w:?}");
        }
        for fine in [
            "cat /var/log/app\\.log",
            "git pull",
            "tail -n [0-9]+ app\\.log",
        ] {
            assert!(pattern_warnings(&ssh_with(&[fine])).is_empty(), "{fine}");
        }
    }

    #[test]
    fn destructive_command_templates_are_flagged() {
        let cfg: mcp_warden_core::config::Config =
            toml::from_str(include_str!("../../tests/fixtures/named_commands.toml")).unwrap();
        let mut p = cfg.preset[0].clone();
        assert!(
            command_warnings(&p).is_empty(),
            "{:?}",
            command_warnings(&p)
        );
        let set = |p: &mut Preset, template: &str| {
            p.commands[2].template = template.into();
            command_warnings(p)
        };
        for template in [
            "rm {path}",
            "sudo -n rm -f {path}",
            "dd if=/dev/zero of={path}",
            "mkfs.ext4 {path}",
            "chmod -R 777 {path}",
            "sudo chown -R app {path}",
        ] {
            let w = set(&mut p, template);
            assert_eq!(w.len(), 1, "{template}: {w:?}");
            assert!(w[0].contains("command 'trash_file'"), "{w:?}");
        }
        for template in [
            "chmod 644 {path}",
            "cat {path}",
            "mv {path} /srv/app/.trash/",
        ] {
            assert!(set(&mut p, template).is_empty(), "{template}");
        }
    }

    /// The patterns the docs recommend refuse option injection, and doctor
    /// has nothing to say about them.
    #[test]
    fn documented_command_patterns_admit_no_options() {
        let mut patterns = Vec::new();
        for doc in [
            include_str!("../../docs/presets-cookbook.md"),
            include_str!("../../docs/ssh-hardening.md"),
            include_str!("../../README.md"),
        ] {
            for block in doc.split("```toml").skip(1) {
                let block = block.split("```").next().unwrap();
                let Ok(value) = toml::from_str::<toml::Value>(block) else {
                    continue;
                };
                for preset in value
                    .get("preset")
                    .and_then(|v| v.as_array())
                    .into_iter()
                    .flatten()
                {
                    for pat in preset
                        .get("allowed_commands")
                        .and_then(|v| v.as_array())
                        .into_iter()
                        .flatten()
                    {
                        patterns.push(pat.as_str().unwrap().to_string());
                    }
                }
            }
        }
        assert!(patterns.len() >= 8, "{patterns:?}");
        let refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
        let p = ssh_with(&refs);
        assert_eq!(pattern_warnings(&p), Vec::<String>::new());
        for evil in ["systemctl status -Hevil", "systemctl status --user"] {
            assert!(
                crate::executor::ssh::validate_command(&p, evil).is_err(),
                "{evil}"
            );
        }
    }

    /// The named commands the docs show pass startup validation.
    #[test]
    fn documented_named_commands_validate() {
        let mut checked = 0;
        for (file, doc) in [
            (
                "docs/presets-cookbook.md",
                include_str!("../../docs/presets-cookbook.md"),
            ),
            (
                "docs/design/named-commands.md",
                include_str!("../../docs/design/named-commands.md"),
            ),
        ] {
            for block in doc.split("```toml").skip(1) {
                let block = block.split("```").next().unwrap();
                let Ok(cfg) = toml::from_str::<Config>(block) else {
                    continue;
                };
                for p in cfg.preset.iter().filter(|p| !p.commands.is_empty()) {
                    mcp_warden_core::commands::validate_preset(p)
                        .unwrap_or_else(|e| panic!("{file}: {e}"));
                    assert!(command_warnings(p).is_empty(), "{file}");
                    checked += p.commands.len();
                }
            }
        }
        assert!(checked >= 6, "only {checked} documented commands");
    }

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

    /// `doctor --deep --format json` can be run by an agent with a shell, so
    /// a probe of an upstream that reflects the credential must not print
    /// it — whether or not the snippet happens to contain a keyword.
    #[tokio::test]
    async fn a_reflected_credential_is_not_printed() {
        use mcp_warden_core::keychain::KeychainStore;
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(|req: &wiremock::Request| {
                let key = req
                    .headers
                    .get("x-key")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "seen": key }))
            })
            .mount(&server)
            .await;
        let cfg: Config = toml::from_str(&format!(
            r#"
[[preset]]
name = "echo"
type = "http"
description = ""
base_url = "{}"
auth = {{ type = "header", name = "X-Key", secret = "k" }}
allowed_methods = ["GET"]
allowed_paths = ["/me"]
approval = "auto"
"#,
            server.uri()
        ))
        .unwrap();
        let kc = mcp_warden_core::keychain::memory::InMemoryKeychain::new();
        kc.set(
            "k",
            mcp_warden_core::secret::Secret::new("s3cr3t-VALUE-xyz".into()),
        )
        .unwrap();
        let args = DoctorArgs {
            deep: true,
            include_prompt: false,
            timeout_seconds: 5,
            format: "json".into(),
        };
        let (exec, _dir, _) = probe_executor(ApprovalDecision::Denied);
        let json = serde_json::to_string(&run_probes(&cfg, &kc, &args, &exec).await).unwrap();
        assert!(json.contains("200"), "{json}");
        crate::testutil::assert_no_secret("doctor --deep", &json, "s3cr3t-VALUE-xyz");
    }

    fn probe_executor(
        decision: ApprovalDecision,
    ) -> (
        ActionExecutor,
        tempfile::TempDir,
        Arc<crate::testutil::CountingApproval>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let approval = crate::testutil::CountingApproval::new(decision);
        let exec = ActionExecutor::new(
            Arc::new(mcp_warden_core::keychain::memory::InMemoryKeychain::new()),
            approval.clone(),
            None,
            Arc::new(LocalSqlite::open(&dir.path().join("audit.db")).unwrap()),
        );
        (exec, dir, approval)
    }

    /// `--include-prompt` used to probe `prompt` presets — with the real
    /// credential — without asking anyone, and printed the start of the
    /// response. An agent with a shell could run it. Now each such probe
    /// asks first, and nothing is sent when the answer is no.
    #[tokio::test]
    async fn probing_a_prompt_preset_asks_first() {
        use mcp_warden_core::keychain::KeychainStore;
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("private"))
            .expect(0)
            .mount(&server)
            .await;
        let cfg: Config = toml::from_str(&format!(
            r#"
[[preset]]
name = "gh"
type = "http"
description = ""
base_url = "{}"
auth = {{ type = "bearer", secret = "k" }}
allowed_methods = ["GET"]
allowed_paths = ["/user/repos"]
approval = "prompt"
"#,
            server.uri()
        ))
        .unwrap();
        let kc = mcp_warden_core::keychain::memory::InMemoryKeychain::new();
        kc.set("k", mcp_warden_core::secret::Secret::new("tok".into()))
            .unwrap();
        let args = DoctorArgs {
            deep: true,
            include_prompt: true,
            timeout_seconds: 5,
            format: "json".into(),
        };
        let (exec, _dir, approval) = probe_executor(ApprovalDecision::Denied);
        let json = serde_json::to_value(run_probes(&cfg, &kc, &args, &exec).await).unwrap();
        assert_eq!(approval.calls(), 1);
        assert_eq!(json[0]["status"], "skipped", "{json}");
        assert!(
            json[0]["detail"].as_str().unwrap().contains("denied"),
            "{json}"
        );
        let shown = approval.shown.lock().unwrap();
        assert_eq!(shown[0].summary, "doctor --deep probe: GET /user/repos");
    }

    #[tokio::test]
    async fn probe_results_carry_open_paths_warning() {
        let cfg: Config = toml::from_str(
            r#"
[[preset]]
name = "open"
type = "http"
description = ""
base_url = "https://api.github.com"
auth = { type = "bearer", secret = "gh_pat" }
allowed_methods = ["GET"]
approval = "deny"

[[preset]]
name = "narrow"
type = "http"
description = ""
base_url = "https://api.github.com"
auth = { type = "bearer", secret = "gh_pat" }
allowed_methods = ["GET"]
allowed_paths = ["/user/repos"]
approval = "deny"
"#,
        )
        .unwrap();
        let args = DoctorArgs {
            deep: true,
            include_prompt: false,
            timeout_seconds: 1,
            format: "json".into(),
        };
        let kc = mcp_warden_core::keychain::memory::InMemoryKeychain::new();
        let (exec, _dir, _) = probe_executor(ApprovalDecision::Denied);

        let json = serde_json::to_value(run_probes(&cfg, &kc, &args, &exec).await).unwrap();

        let open = json[0]["warnings"].as_array().unwrap();
        assert_eq!(open.len(), 1, "{json}");
        assert!(
            open[0]
                .as_str()
                .unwrap()
                .starts_with("preset 'open' has no allowed_paths"),
            "{json}"
        );
        assert_eq!(json[1]["warnings"], serde_json::json!([]), "{json}");
    }

    #[test]
    fn truncate_respects_unicode() {
        assert_eq!(truncate("abc", 10), "abc");
        let s = truncate("abcdefghij", 5);
        assert!(s.chars().count() <= 6);
    }
}
