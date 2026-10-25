use crate::web::server::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use chrono::Utc;
use mcp_warden_core::audit::sqlite_sink::LocalSqlite;
use mcp_warden_core::audit::{AuditDecision, AuditEvent, AuditOutcome, AuditSink};
use mcp_warden_core::config::{ApprovalPolicy, Config, Preset, PresetType};
use std::collections::HashMap;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// HTML escape helper
// ---------------------------------------------------------------------------

/// Escape `<`, `>`, `&`, `"`, `'` so dynamic values are safe in HTML context.
///
/// SECURITY: Every piece of user-controlled or file-derived data rendered into
/// HTML must pass through this function. Never interpolate raw strings into the
/// HTML templates below.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

// ---------------------------------------------------------------------------
// Minimal shared layout
// ---------------------------------------------------------------------------

fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{title} — mcp-warden</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; }}
    body {{ font-family: system-ui, sans-serif; margin: 0; padding: 0;
            background: #f8f9fa; color: #212529; }}
    header {{ background: #1a1a2e; color: #fff; padding: 0.8rem 1.5rem;
              display: flex; align-items: center; gap: 1rem; }}
    header a {{ color: #a8d8ea; text-decoration: none; font-weight: 600; }}
    header a:hover {{ text-decoration: underline; }}
    nav {{ display: flex; gap: 1rem; margin-left: auto; }}
    main {{ padding: 1.5rem; max-width: 1100px; margin: 0 auto; }}
    h1 {{ font-size: 1.4rem; margin: 0 0 1rem; }}
    h2 {{ font-size: 1.1rem; margin: 1.5rem 0 0.5rem; color: #495057; }}
    table {{ border-collapse: collapse; width: 100%; background: #fff;
             border-radius: 6px; overflow: hidden;
             box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
    th {{ background: #e9ecef; text-align: left; padding: 0.55rem 0.8rem;
          font-size: 0.82rem; text-transform: uppercase; letter-spacing: .04em; }}
    td {{ padding: 0.5rem 0.8rem; border-top: 1px solid #dee2e6;
          font-size: 0.9rem; vertical-align: top; }}
    tr:hover td {{ background: #f1f3f5; }}
    .badge {{ display: inline-block; padding: 0.15rem 0.45rem; border-radius: 3px;
              font-size: 0.78rem; font-weight: 600; }}
    .badge-auto  {{ background: #d1fae5; color: #065f46; }}
    .badge-prompt{{ background: #fef3c7; color: #92400e; }}
    .badge-deny  {{ background: #fee2e2; color: #991b1b; }}
    .badge-ok    {{ background: #d1fae5; color: #065f46; }}
    .badge-err   {{ background: #fee2e2; color: #991b1b; }}
    .badge-http  {{ background: #dbeafe; color: #1e40af; }}
    .badge-ssh   {{ background: #ede9fe; color: #4c1d95; }}
    .badge-db    {{ background: #fce7f3; color: #9d174d; }}
    .stat-grid {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }}
    .stat {{ background: #fff; border-radius: 6px; padding: 1rem 1.5rem;
             box-shadow: 0 1px 3px rgba(0,0,0,.1); min-width: 160px; }}
    .stat .value {{ font-size: 2rem; font-weight: 700; color: #1a1a2e; }}
    .stat .label {{ font-size: 0.8rem; color: #868e96; margin-top: 0.2rem; }}
    a {{ color: #1971c2; }}
    a:hover {{ color: #1864ab; }}
    .back {{ margin-bottom: 1rem; display: inline-block; }}
    dl {{ display: grid; grid-template-columns: 180px 1fr; gap: 0.4rem 1rem;
          background: #fff; padding: 1rem 1.2rem; border-radius: 6px;
          box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
    dt {{ font-weight: 600; color: #495057; font-size: 0.88rem; }}
    dd {{ margin: 0; font-size: 0.9rem; word-break: break-all; }}
    .empty {{ color: #868e96; font-style: italic; }}
  </style>
</head>
<body>
  <header>
    <a href="/">mcp-warden</a>
    <nav>
      <a href="/presets">Presets</a>
      <a href="/audit">Audit log</a>
    </nav>
  </header>
  <main>
    {body}
  </main>
</body>
</html>"#,
        title = esc(title),
        body = body,
    )
}

// ---------------------------------------------------------------------------
// Error response helper
// ---------------------------------------------------------------------------

fn err_page(status: StatusCode, msg: &str) -> Response {
    let body = format!(
        "<h1>Error {}</h1><p>{}</p><p><a href=\"/\">Back to dashboard</a></p>",
        status.as_u16(),
        esc(msg),
    );
    (status, Html(page("Error", &body))).into_response()
}

// ---------------------------------------------------------------------------
// Route helpers
// ---------------------------------------------------------------------------

fn approval_badge(p: ApprovalPolicy) -> &'static str {
    match p {
        ApprovalPolicy::Auto => r#"<span class="badge badge-auto">auto</span>"#,
        ApprovalPolicy::Prompt => r#"<span class="badge badge-prompt">prompt</span>"#,
        ApprovalPolicy::Deny => r#"<span class="badge badge-deny">deny</span>"#,
    }
}

fn type_badge(t: PresetType) -> &'static str {
    match t {
        PresetType::Http => r#"<span class="badge badge-http">http</span>"#,
        PresetType::Ssh => r#"<span class="badge badge-ssh">ssh</span>"#,
        PresetType::Postgres | PresetType::Mysql | PresetType::Redis => {
            r#"<span class="badge badge-db">db</span>"#
        }
    }
}

fn type_label(t: PresetType) -> &'static str {
    match t {
        PresetType::Http => "http",
        PresetType::Ssh => "ssh",
        PresetType::Postgres => "postgres",
        PresetType::Mysql => "mysql",
        PresetType::Redis => "redis",
    }
}

fn decision_label(d: Option<AuditDecision>) -> &'static str {
    match d {
        Some(AuditDecision::Approved) => "approved",
        Some(AuditDecision::Denied) => "denied",
        Some(AuditDecision::Auto) => "auto",
        Some(AuditDecision::Timeout) => "timeout",
        Some(AuditDecision::Windowed) => "windowed",
        None => "—",
    }
}

fn outcome_cell(o: &Option<AuditOutcome>) -> String {
    match o {
        Some(AuditOutcome::Ok { status }) => {
            format!(r#"<span class="badge badge-ok">{}</span>"#, status)
        }
        Some(AuditOutcome::Err { message }) => format!(
            r#"<span class="badge badge-err">err: {}</span>"#,
            esc(message)
        ),
        None => "—".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /` — Dashboard with stat summary and links.
pub async fn index(State(state): State<Arc<AppState>>) -> Response {
    // Count presets (best-effort, no keychain validation here).
    let preset_count = match try_load_config_raw(&state.config_path) {
        Ok(cfg) => cfg.preset.len(),
        Err(_) => 0,
    };

    // Count audit events in the last 24 h.
    let audit_24h = if state.audit_db.exists() {
        match LocalSqlite::open(&state.audit_db) {
            Ok(sink) => {
                let since = Utc::now() - chrono::Duration::hours(24);
                sink.since(since).map(|v| v.len()).unwrap_or(0)
            }
            Err(_) => 0,
        }
    } else {
        0
    };

    let body = format!(
        r#"<h1>Dashboard</h1>
<div class="stat-grid">
  <div class="stat">
    <div class="value">{preset_count}</div>
    <div class="label">Presets configured</div>
  </div>
  <div class="stat">
    <div class="value">{audit_24h}</div>
    <div class="label">Audit events (last 24 h)</div>
  </div>
</div>
<p>
  <a href="/presets">View presets →</a> &nbsp;|&nbsp;
  <a href="/audit">View audit log →</a>
</p>"#
    );
    Html(page("Dashboard", &body)).into_response()
}

/// `GET /presets` — HTML table of all configured presets.
pub async fn presets_list(State(state): State<Arc<AppState>>) -> Response {
    let cfg = match try_load_config_raw(&state.config_path) {
        Ok(c) => c,
        Err(e) => return err_page(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };

    if cfg.preset.is_empty() {
        let body = r#"<h1>Presets</h1>
<p class="empty">No presets configured. Add presets to your <code>config.toml</code>.</p>"#;
        return Html(page("Presets", body)).into_response();
    }

    let mut rows = String::new();
    for p in &cfg.preset {
        rows.push_str(&format!(
            r#"<tr>
  <td><a href="/presets/{name}">{name}</a></td>
  <td>{kind}</td>
  <td>{approval}</td>
  <td>{desc}</td>
</tr>"#,
            name = esc(&p.name),
            kind = type_badge(p.preset_type),
            approval = approval_badge(p.approval),
            desc = esc(&p.description),
        ));
    }

    let body = format!(
        r#"<h1>Presets <small>({count})</small></h1>
<table>
  <thead>
    <tr>
      <th>Name</th><th>Kind</th><th>Approval</th><th>Description</th>
    </tr>
  </thead>
  <tbody>{rows}</tbody>
</table>"#,
        count = cfg.preset.len(),
        rows = rows,
    );
    Html(page("Presets", &body)).into_response()
}

/// `GET /presets/:name` — Detail page for a single preset.
///
/// SECURITY: Secret values are never shown — only the secret reference name
/// (e.g. `gh_pat`). The `auth`, `secret`, etc. fields in `Preset` hold the
/// keychain entry name, not the secret value itself. We render only that name.
pub async fn preset_detail(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Response {
    let cfg = match try_load_config_raw(&state.config_path) {
        Ok(c) => c,
        Err(e) => return err_page(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };

    let preset = match cfg.preset.into_iter().find(|p| p.name == name) {
        Some(p) => p,
        None => {
            return err_page(
                StatusCode::NOT_FOUND,
                &format!("Preset '{}' not found.", esc(&name)),
            );
        }
    };

    let body = format!(
        r#"<a class="back" href="/presets">← All presets</a>
<h1>{name}</h1>
{detail}"#,
        name = esc(&preset.name),
        detail = render_preset_detail(&preset),
    );
    Html(page(&format!("Preset: {}", esc(&preset.name)), &body)).into_response()
}

fn render_preset_detail(p: &Preset) -> String {
    // Build a key/value list of non-sensitive fields.
    let mut rows = String::new();
    let add = |rows: &mut String, label: &str, value: &str| {
        rows.push_str(&format!("<dt>{}</dt><dd>{}</dd>", esc(label), esc(value)));
    };

    add(&mut rows, "Type", type_label(p.preset_type));
    add(
        &mut rows,
        "Approval",
        match p.approval {
            ApprovalPolicy::Auto => "auto",
            ApprovalPolicy::Prompt => "prompt",
            ApprovalPolicy::Deny => "deny",
        },
    );
    add(&mut rows, "Description", &p.description);

    if let Some(url) = &p.base_url {
        add(&mut rows, "Base URL", url);
    }
    if let Some(host) = &p.host {
        add(&mut rows, "Host", host);
    }
    if let Some(user) = &p.user {
        add(&mut rows, "User", user);
    }
    if let Some(port) = p.port {
        add(&mut rows, "Port", &port.to_string());
    }
    if !p.allowed_methods.is_empty() {
        add(&mut rows, "Allowed methods", &p.allowed_methods.join(", "));
    }
    if !p.allowed_paths.is_empty() {
        add(&mut rows, "Allowed paths", &p.allowed_paths.join(", "));
    }
    if !p.allowed_commands.is_empty() {
        add(
            &mut rows,
            "Allowed commands (regex)",
            &p.allowed_commands.join(", "),
        );
    }
    if let Some(win) = p.approval_window_seconds {
        add(&mut rows, "Approval window (s)", &win.to_string());
    }
    if let Some(db) = &p.database {
        add(&mut rows, "Database", db);
    }
    if !p.queries.is_empty() {
        let names: Vec<&str> = p.queries.iter().map(|q| q.name.as_str()).collect();
        add(&mut rows, "Named queries", &names.join(", "));
    }

    // SECURITY: Show only the secret reference name (keychain key), never the value.
    // `p.secret` is the keychain entry name; `p.auth` contains a keychain entry name.
    // Neither is the actual secret value.
    if let Some(ref secret_ref) = p.secret {
        rows.push_str(&format!(
            "<dt>{}</dt><dd><code>{}</code> <em>(keychain ref, not value)</em></dd>",
            esc("Secret ref"),
            esc(secret_ref),
        ));
    }
    if let Some(ref auth) = p.auth {
        use mcp_warden_core::config::Auth;
        let secret_ref = match auth {
            Auth::Bearer { secret } => secret.as_str(),
            Auth::Header { secret, .. } => secret.as_str(),
            Auth::Basic { secret, .. } => secret.as_str(),
        };
        rows.push_str(&format!(
            "<dt>{}</dt><dd><code>{}</code> <em>(keychain ref, not value)</em></dd>",
            esc("Auth secret ref"),
            esc(secret_ref),
        ));
    }

    format!("<dl>{rows}</dl>")
}

/// `GET /audit?limit=N` — Recent audit log entries.
pub async fn audit_log(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let limit: usize = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(100)
        .min(1000);

    if !state.audit_db.exists() {
        let body = r#"<h1>Audit log</h1>
<p class="empty">No audit database yet — it is created on first MCP tool call.</p>"#;
        return Html(page("Audit log", body)).into_response();
    }

    let sink = match LocalSqlite::open(&state.audit_db) {
        Ok(s) => s,
        Err(e) => return err_page(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let events: Vec<AuditEvent> = match sink.recent(limit) {
        Ok(v) => v,
        Err(e) => return err_page(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    if events.is_empty() {
        let body = r#"<h1>Audit log</h1>
<p class="empty">No events recorded yet.</p>"#;
        return Html(page("Audit log", body)).into_response();
    }

    let mut rows = String::new();
    for e in &events {
        rows.push_str(&format!(
            r#"<tr>
  <td>{id}</td>
  <td style="white-space:nowrap">{ts}</td>
  <td><a href="/presets/{preset}">{preset}</a></td>
  <td>{action}</td>
  <td>{summary}</td>
  <td>{decision}</td>
  <td>{outcome}</td>
</tr>"#,
            id = e.id,
            ts = esc(&e.created_at.format("%Y-%m-%d %H:%M:%S").to_string()),
            preset = esc(&e.preset),
            action = esc(&e.action),
            // SECURITY: The summary field is already redacted by the audit
            // recording path (audit::redact). We additionally HTML-escape it here.
            summary = esc(&e.summary),
            decision = esc(decision_label(e.decision)),
            outcome = outcome_cell(&e.outcome),
        ));
    }

    let body = format!(
        r#"<h1>Audit log <small>(last {limit})</small></h1>
<p>
  <a href="/audit?limit=50">50</a> |
  <a href="/audit?limit=100">100</a> |
  <a href="/audit?limit=500">500</a>
</p>
<table>
  <thead>
    <tr>
      <th>#</th><th>Time (UTC)</th><th>Preset</th><th>Action</th>
      <th>Summary</th><th>Decision</th><th>Outcome</th>
    </tr>
  </thead>
  <tbody>{rows}</tbody>
</table>"#,
        limit = limit,
        rows = rows,
    );
    Html(page("Audit log", &body)).into_response()
}

// ---------------------------------------------------------------------------
// Config loading (no keychain validation — read-only display)
// ---------------------------------------------------------------------------

/// Load config.toml without keychain validation, for display purposes only.
///
/// This avoids requiring keychain access (which would trigger OS prompts) just
/// to browse the web UI. Secret values are never loaded or displayed.
fn try_load_config_raw(path: &std::path::Path) -> Result<Config, String> {
    if !path.exists() {
        return Err(format!(
            "Config file not found at {}. Run `mcp-warden init` first.",
            path.display()
        ));
    }
    let raw = std::fs::read_to_string(path).map_err(|e| format!("Could not read config: {e}"))?;
    toml::from_str(&raw).map_err(|e| format!("Config parse error: {e}"))
}
