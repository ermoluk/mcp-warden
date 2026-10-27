use crate::executor::policy::{Request, Verdict, simulate};
use clap::{Args, Subcommand};
use mcp_warden_core::config::{ApprovalPolicy, Auth, Config, NamedQuery, Preset, PresetType};
use mcp_warden_core::error::{Result, WardenError};
use mcp_warden_core::keychain::KeychainStore;
use std::fs;
use std::path::Path;

#[derive(Debug, Subcommand)]
pub enum PresetCmd {
    /// Add a new preset to the config file.
    Add(Box<AddArgs>),
    /// Add a named query to an existing db preset (postgres / mysql / redis).
    AddQuery(AddQueryArgs),
    /// List defined presets (name + type + approval policy).
    List,
    /// Validate a preset against the current config and keychain, or —
    /// given a request — say whether that call would be allowed and why,
    /// without sending it (`preset test gh GET /user`, `--command`, …).
    Test(TestArgs),
    /// Give time-limited access to a preset: calls are refused once the
    /// window ends. Takes effect when the MCP server next starts.
    Grant(GrantArgs),
    /// End access to a preset now. Takes effect when the MCP server next
    /// starts; `mcp-warden lock` stops running servers immediately.
    Revoke { name: String },
    /// Generate a preset from a built-in template for common APIs
    /// (github-read, notion-read, openai-chat, …). Use `--list` to see
    /// available templates.
    Scaffold(ScaffoldArgs),
    /// Bootstrap a preset from an OpenAPI 3.0/3.1 spec (URL or file).
    /// Extracts base URL, paths and methods from the spec; picks the first
    /// Bearer or APIKey-Header security scheme if present.
    FromOpenapi(FromOpenapiArgs),
}

#[derive(Debug, Args)]
pub struct ScaffoldArgs {
    /// Template name (e.g. `github-read`). Omit and pass `--list` to see options.
    #[arg(value_name = "TEMPLATE", required_unless_present_any = ["list", "list_json"])]
    pub template: Option<String>,
    /// Print available templates and exit.
    #[arg(long, conflicts_with_all = ["template", "name", "secret_name"])]
    pub list: bool,
    /// Print available templates as JSON and exit.
    #[arg(long, conflicts_with_all = ["template", "name", "secret_name"])]
    pub list_json: bool,
    /// Name for the resulting preset (defaults to the template name).
    #[arg(long)]
    pub name: Option<String>,
    /// Keychain secret name to bind (defaults to the template's default — see `--list`).
    #[arg(long)]
    pub secret_name: Option<String>,
    /// Print the generated TOML to stdout instead of writing to the config file.
    #[arg(long)]
    pub dry_run: bool,
    /// Overwrite an existing preset with the same name.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct FromOpenapiArgs {
    /// OpenAPI spec source: file path or http(s) URL.
    pub source: String,
    /// Override the preset name (default: derived from spec info.title).
    #[arg(long)]
    pub name: Option<String>,
    /// Keychain secret name to bind (default: api_token).
    #[arg(long)]
    pub secret_name: Option<String>,
    /// Override the spec's `servers[0].url`.
    #[arg(long)]
    pub base_url: Option<String>,
    /// Restrict to these methods (comma-separated, e.g. GET,POST).
    #[arg(long, value_delimiter = ',')]
    pub method_filter: Vec<String>,
    /// Restrict to operations carrying any of these tags.
    #[arg(long, value_delimiter = ',')]
    pub tag_filter: Vec<String>,
    /// Approval policy for the generated preset.
    #[arg(long, value_parser = ["auto", "prompt", "deny"], default_value = "prompt")]
    pub approval: String,
    /// Print the generated TOML to stdout instead of writing to the config file.
    #[arg(long)]
    pub dry_run: bool,
    /// Overwrite an existing preset with the same name.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct AddArgs {
    pub name: String,
    #[arg(long, value_parser = ["http", "ssh", "postgres", "mysql", "redis"])]
    pub r#type: String,
    #[arg(long, default_value = "")]
    pub description: String,
    // HTTP-only
    #[arg(long)]
    pub base_url: Option<String>,
    #[arg(long, value_name = "SECRET_NAME")]
    pub auth_bearer: Option<String>,
    #[arg(long, value_delimiter = ',')]
    pub allowed_methods: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    pub allowed_paths: Vec<String>,
    // SSH / DB
    #[arg(long)]
    pub host: Option<String>,
    #[arg(long)]
    pub user: Option<String>,
    #[arg(long)]
    pub port: Option<u16>,
    /// Secret name (private-key for SSH, password for DB).
    #[arg(long)]
    pub secret: Option<String>,
    // SSH-only
    #[arg(long, value_delimiter = ',')]
    pub allowed_commands: Vec<String>,
    #[arg(long)]
    pub allow_sftp: bool,
    #[arg(long, value_delimiter = ',')]
    pub sftp_allowed_paths: Vec<String>,
    #[arg(long)]
    pub known_hosts: Option<String>,
    /// Optional command/connection timeout in seconds.
    #[arg(long)]
    pub timeout_seconds: Option<u64>,
    // DB-only
    #[arg(long)]
    pub database: Option<String>,
    // Approval
    #[arg(long, value_parser = ["auto", "prompt", "deny"], default_value = "prompt")]
    pub approval: String,
    /// Required when `--approval auto` (spec §9.4 — auto disables the prompt).
    #[arg(long)]
    pub confirm_auto: bool,
}

#[derive(Debug, Args)]
pub struct AddQueryArgs {
    /// Existing preset (must be type postgres / mysql / redis).
    pub preset: String,
    pub query_name: String,
    /// SQL template (`SELECT * FROM users WHERE id = $1`) for SQL, or
    /// command name (`GET`, `LPUSH`) for Redis.
    #[arg(long)]
    pub template: String,
    /// Comma-separated parameter types in positional order. Example: `int8,text`.
    #[arg(long, value_delimiter = ',')]
    pub param_types: Vec<String>,
    /// Mark the query as read-only (audit hint, not enforced).
    #[arg(long)]
    pub readonly: bool,
}

pub async fn run(cmd: PresetCmd, config_path: &Path, kc: &dyn KeychainStore) -> Result<()> {
    match cmd {
        PresetCmd::Add(args) => add(*args, config_path, kc),
        PresetCmd::AddQuery(args) => add_query(args, config_path, kc),
        PresetCmd::List => list(config_path),
        PresetCmd::Test(args) => test_preset(args, config_path, kc),
        PresetCmd::Grant(args) => grant(args, config_path),
        PresetCmd::Revoke { name } => revoke(&name, config_path),
        PresetCmd::Scaffold(args) => scaffold(args, config_path),
        PresetCmd::FromOpenapi(args) => from_openapi(args, config_path).await,
    }
}

fn scaffold(args: ScaffoldArgs, config_path: &Path) -> Result<()> {
    use crate::cli::preset_templates::{TEMPLATES, find};

    if args.list_json {
        let items: Vec<_> = TEMPLATES
            .iter()
            .map(|t| {
                serde_json::json!({
                    "name": t.name,
                    "description": t.description,
                    "default_secret_name": t.default_secret_name,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&items).unwrap());
        return Ok(());
    }

    if args.list {
        println!("Available templates:");
        for t in TEMPLATES {
            println!(
                "  {:<22} {}  (default secret: {})",
                t.name, t.description, t.default_secret_name
            );
        }
        return Ok(());
    }

    let template_name = args.template.as_deref().ok_or_else(|| {
        WardenError::Validation("template name is required (or pass --list)".into())
    })?;

    let template = find(template_name).ok_or_else(|| {
        WardenError::Validation(format!(
            "unknown template '{template_name}' (try `mcp-warden preset scaffold --list`)"
        ))
    })?;

    let preset_name = args.name.as_deref().unwrap_or(template.name).to_string();
    let secret_name = args
        .secret_name
        .as_deref()
        .unwrap_or(template.default_secret_name)
        .to_string();

    let preset = (template.build)(&preset_name, &secret_name);
    let open_paths_warning = unrestricted_paths_warning(&preset);

    if args.dry_run {
        let open_paths_comment = open_paths_comment(&preset, template.open_paths_note);
        let wrapper = ScaffoldWrapper {
            preset: vec![preset],
        };
        let rendered =
            toml::to_string_pretty(&wrapper).map_err(|e| WardenError::Config(e.to_string()))?;
        println!("# Generated from template '{}'", template.name);
        println!("# Secret '{secret_name}' must exist in the keychain:");
        println!("#   mcp-warden secret add {secret_name}");
        if let Some(comment) = open_paths_comment {
            print!("{comment}");
        }
        println!();
        print!("{rendered}");
        return Ok(());
    }

    let raw = fs::read_to_string(config_path).map_err(WardenError::Io)?;
    let mut cfg: Config = toml::from_str(&raw).map_err(|e| WardenError::Config(e.to_string()))?;
    if let Some(existing_idx) = cfg.preset.iter().position(|p| p.name == preset_name) {
        if !args.force {
            return Err(WardenError::Validation(format!(
                "preset '{preset_name}' already exists — pass --force to overwrite"
            )));
        }
        cfg.preset[existing_idx] = preset;
    } else {
        cfg.preset.push(preset);
    }
    let rendered = toml::to_string_pretty(&cfg).map_err(|e| WardenError::Config(e.to_string()))?;
    fs::write(config_path, rendered).map_err(WardenError::Io)?;
    eprintln!(
        "✓ scaffolded preset '{}' from template '{}'. Add the secret next:",
        preset_name, template.name
    );
    eprintln!("    mcp-warden secret add {secret_name}");
    if let Some(w) = open_paths_warning {
        eprintln!("warning: {w}");
    }
    Ok(())
}

async fn from_openapi(args: FromOpenapiArgs, config_path: &Path) -> Result<()> {
    use crate::cli::openapi::{FromOpenapiOptions, from_source};
    let approval = match args.approval.as_str() {
        "auto" => ApprovalPolicy::Auto,
        "deny" => ApprovalPolicy::Deny,
        _ => ApprovalPolicy::Prompt,
    };
    let method_filter = if args.method_filter.is_empty() {
        None
    } else {
        Some(args.method_filter.as_slice())
    };
    let tag_filter = if args.tag_filter.is_empty() {
        None
    } else {
        Some(args.tag_filter.as_slice())
    };
    let bootstrapped = from_source(FromOpenapiOptions {
        source: &args.source,
        name_override: args.name.as_deref(),
        secret_name: args.secret_name.as_deref(),
        base_url_override: args.base_url.as_deref(),
        method_filter,
        tag_filter,
        approval,
    })
    .await?;

    if args.dry_run {
        let wrapper = OpenapiWrapper {
            preset: vec![bootstrapped.preset],
        };
        let rendered =
            toml::to_string_pretty(&wrapper).map_err(|e| WardenError::Config(e.to_string()))?;
        println!(
            "# Generated from OpenAPI spec '{}' v{} ({} operations)",
            bootstrapped.spec_title, bootstrapped.spec_version, bootstrapped.operation_count
        );
        println!("# Source: {}", bootstrapped.source);
        println!();
        print!("{rendered}");
        return Ok(());
    }

    let raw = fs::read_to_string(config_path).map_err(WardenError::Io)?;
    let mut cfg: Config = toml::from_str(&raw).map_err(|e| WardenError::Config(e.to_string()))?;
    let preset_name = bootstrapped.preset.name.clone();
    if let Some(idx) = cfg.preset.iter().position(|p| p.name == preset_name) {
        if !args.force {
            return Err(WardenError::Validation(format!(
                "preset '{preset_name}' already exists — pass --force to overwrite"
            )));
        }
        cfg.preset[idx] = bootstrapped.preset;
    } else {
        cfg.preset.push(bootstrapped.preset);
    }
    let rendered = toml::to_string_pretty(&cfg).map_err(|e| WardenError::Config(e.to_string()))?;
    fs::write(config_path, rendered).map_err(WardenError::Io)?;
    eprintln!(
        "✓ scaffolded preset '{}' from {} ({} operations).",
        preset_name, bootstrapped.source, bootstrapped.operation_count
    );
    Ok(())
}

#[derive(serde::Serialize)]
struct ScaffoldWrapper {
    preset: Vec<Preset>,
}

#[derive(serde::Serialize)]
struct OpenapiWrapper {
    preset: Vec<Preset>,
}

fn add(args: AddArgs, config_path: &Path, kc: &dyn KeychainStore) -> Result<()> {
    if args.approval == "auto" && !args.confirm_auto {
        return Err(WardenError::Validation(
            "approval=auto requires --confirm-auto (auto-approve disables the prompt — see spec §9.4)"
                .into(),
        ));
    }
    let raw = fs::read_to_string(config_path).map_err(WardenError::Io)?;
    let mut cfg: Config = toml::from_str(&raw).map_err(|e| WardenError::Config(e.to_string()))?;
    if cfg.preset.iter().any(|p| p.name == args.name) {
        return Err(WardenError::Validation(format!(
            "preset '{}' already exists",
            args.name
        )));
    }
    let auth = args.auth_bearer.map(|s| Auth::Bearer { secret: s });
    let preset_type = match args.r#type.as_str() {
        "http" => PresetType::Http,
        "ssh" => PresetType::Ssh,
        "postgres" => PresetType::Postgres,
        "mysql" => PresetType::Mysql,
        "redis" => PresetType::Redis,
        other => {
            return Err(WardenError::Validation(format!(
                "unknown preset type '{other}'"
            )));
        }
    };
    let preset = Preset {
        name: args.name.clone(),
        preset_type,
        description: args.description,
        base_url: args.base_url,
        auth,
        allowed_paths: args.allowed_paths,
        allowed_methods: args.allowed_methods,
        approval: match args.approval.as_str() {
            "auto" => ApprovalPolicy::Auto,
            "deny" => ApprovalPolicy::Deny,
            _ => ApprovalPolicy::Prompt,
        },
        approval_window_seconds: None,
        host: args.host,
        user: args.user,
        port: args.port,
        secret: args.secret,
        allowed_commands: args.allowed_commands,
        timeout_seconds: args.timeout_seconds,
        known_hosts: args.known_hosts,
        allow_sftp: args.allow_sftp,
        sftp_allowed_paths: args.sftp_allowed_paths,
        database: args.database,
        queries: vec![],
        expires_at: None,
    };
    if let Some(w) = unrestricted_paths_warning(&preset) {
        eprintln!("warning: {w}");
    }
    cfg.preset.push(preset);
    cfg.validate(kc)?;
    let toml_str = toml::to_string_pretty(&cfg).map_err(|e| WardenError::Config(e.to_string()))?;
    fs::write(config_path, toml_str).map_err(WardenError::Io)?;
    eprintln!("Added preset '{}'.", args.name);
    Ok(())
}

/// Warning for an HTTP preset with no `allowed_paths`, which lets the agent
/// reach every path under `base_url`. Existing configs rely on that, so it
/// is surfaced by `doctor`, `preset add` and `preset scaffold`, not refused.
pub(crate) fn unrestricted_paths_warning(p: &Preset) -> Option<String> {
    if !matches!(p.preset_type, PresetType::Http) || !p.allowed_paths.is_empty() {
        return None;
    }
    Some(format!(
        "preset '{}' has no allowed_paths: every path under {} is allowed. \
         Narrow it to the paths the agent needs (exact strings or full-match regexes, \
         e.g. \"/users/[^/]+\")",
        p.name,
        p.base_url.as_deref().unwrap_or("base_url"),
    ))
}

/// TOML comment for `scaffold --dry-run` above a preset with no
/// `allowed_paths`: what that allows, how patterns match, and the
/// template's own example and token advice.
fn open_paths_comment(preset: &Preset, note: &[&str]) -> Option<String> {
    if !preset.allowed_paths.is_empty() {
        return None;
    }
    let mut out = format!(
        "#\n# No allowed_paths: every path under {} is allowed",
        preset.base_url.as_deref().unwrap_or("base_url"),
    );
    if matches!(preset.approval, ApprovalPolicy::Auto) {
        out.push_str(",\n# and approval = \"auto\" means no prompt either");
    }
    out.push_str(
        ".\n# To narrow it, list exact paths or full-match regexes. Patterns are anchored\n\
         # as ^(?:…)$, never prefixes; use [^/]+ for one path segment, not .* — e.g.:\n",
    );
    for line in note {
        out.push_str("# ");
        out.push_str(line);
        out.push('\n');
    }
    Some(out)
}

fn list(config_path: &Path) -> Result<()> {
    let raw = match fs::read_to_string(config_path) {
        Ok(r) => r,
        Err(_) => {
            println!("(no presets)");
            return Ok(());
        }
    };
    let cfg: Config = toml::from_str(&raw).map_err(|e| WardenError::Config(e.to_string()))?;
    if cfg.preset.is_empty() {
        println!("(no presets)");
        return Ok(());
    }
    for p in &cfg.preset {
        let kind = match p.preset_type {
            PresetType::Http => "http",
            PresetType::Ssh => "ssh",
            PresetType::Postgres => "postgres",
            PresetType::Mysql => "mysql",
            PresetType::Redis => "redis",
        };
        println!("{:24} {:8} {:?}", p.name, kind, p.approval);
    }
    Ok(())
}

fn add_query(args: AddQueryArgs, config_path: &Path, kc: &dyn KeychainStore) -> Result<()> {
    let raw = fs::read_to_string(config_path).map_err(WardenError::Io)?;
    let mut cfg: Config = toml::from_str(&raw).map_err(|e| WardenError::Config(e.to_string()))?;
    let preset = cfg
        .preset
        .iter_mut()
        .find(|p| p.name == args.preset)
        .ok_or_else(|| WardenError::PresetNotFound(args.preset.clone()))?;
    if !matches!(
        preset.preset_type,
        PresetType::Postgres | PresetType::Mysql | PresetType::Redis
    ) {
        return Err(WardenError::Validation(format!(
            "preset '{}' is not a database preset",
            args.preset
        )));
    }
    if preset.queries.iter().any(|q| q.name == args.query_name) {
        return Err(WardenError::Validation(format!(
            "named query '{}' already exists in preset '{}'",
            args.query_name, args.preset
        )));
    }
    preset.queries.push(NamedQuery {
        name: args.query_name.clone(),
        template: args.template,
        param_types: args.param_types,
        readonly: args.readonly,
    });
    cfg.validate(kc)?;
    let toml_str = toml::to_string_pretty(&cfg).map_err(|e| WardenError::Config(e.to_string()))?;
    fs::write(config_path, toml_str).map_err(WardenError::Io)?;
    eprintln!(
        "Added named query '{}' to preset '{}'.",
        args.query_name, args.preset
    );
    Ok(())
}

#[derive(Debug, Args)]
pub struct GrantArgs {
    /// Preset to grant access to.
    pub name: String,
    /// How long access lasts: `90s`, `30m`, `1h`, `2h30m`, `7d` (at most 30d).
    #[arg(
        long = "for",
        value_name = "DURATION",
        required_unless_present = "permanent",
        conflicts_with = "permanent"
    )]
    pub duration: Option<String>,
    /// Remove the time limit instead.
    #[arg(long)]
    pub permanent: bool,
}

/// Longest access window `preset grant` hands out.
const MAX_GRANT_SECONDS: i64 = 30 * 86_400;

/// Parse a duration like `90s`, `30m`, `1h`, `2h30m` or `7d`.
fn parse_duration(s: &str) -> Result<chrono::Duration> {
    let bad = || {
        WardenError::Validation(format!(
            "duration '{s}': expected e.g. 90s, 30m, 1h, 2h30m or 7d"
        ))
    };
    let mut total: i64 = 0;
    let mut digits = String::new();
    for c in s.trim().chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let unit = match c {
            's' => 1,
            'm' => 60,
            'h' => 3_600,
            'd' => 86_400,
            _ => return Err(bad()),
        };
        let n: i64 = digits.parse().map_err(|_| bad())?;
        digits.clear();
        total = n
            .checked_mul(unit)
            .and_then(|secs| total.checked_add(secs))
            .ok_or_else(bad)?;
    }
    if !digits.is_empty() || total == 0 {
        return Err(bad());
    }
    if total > MAX_GRANT_SECONDS {
        return Err(WardenError::Validation(format!(
            "duration '{s}' is longer than the 30d maximum"
        )));
    }
    Ok(chrono::Duration::seconds(total))
}

/// Read-modify-write a preset's `expires_at`, like `mcp-warden approval`.
fn set_expiry(
    config_path: &Path,
    name: &str,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<()> {
    let raw = fs::read_to_string(config_path).map_err(WardenError::Io)?;
    let mut cfg: Config = toml::from_str(&raw).map_err(|e| WardenError::Config(e.to_string()))?;
    let p = cfg
        .preset
        .iter_mut()
        .find(|p| p.name == name)
        .ok_or_else(|| WardenError::PresetNotFound(name.into()))?;
    p.expires_at = expires_at;
    let toml_str = toml::to_string_pretty(&cfg).map_err(|e| WardenError::Config(e.to_string()))?;
    fs::write(config_path, toml_str).map_err(WardenError::Io)
}

fn now_secs() -> chrono::DateTime<chrono::Utc> {
    use chrono::SubsecRound;
    chrono::Utc::now().trunc_subsecs(0)
}

fn grant(args: GrantArgs, config_path: &Path) -> Result<()> {
    let Some(duration) = args.duration.as_deref() else {
        set_expiry(config_path, &args.name, None)?;
        eprintln!(
            "Access to '{}' no longer has a time limit. Restart the MCP server for it to take effect.",
            args.name
        );
        return Ok(());
    };
    let until = now_secs() + parse_duration(duration)?;
    set_expiry(config_path, &args.name, Some(until))?;
    eprintln!(
        "Access to '{}' now ends at {}. Restart the MCP server for it to take effect.",
        args.name,
        until.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    );
    Ok(())
}

fn revoke(name: &str, config_path: &Path) -> Result<()> {
    set_expiry(config_path, name, Some(now_secs()))?;
    eprintln!(
        "Access to '{name}' has ended. Running MCP servers keep it until they restart; \
         `mcp-warden lock` stops them now."
    );
    Ok(())
}

#[derive(Debug, Args)]
pub struct TestArgs {
    /// Preset to test.
    pub name: String,
    /// HTTP method of a `proxy_http` call to simulate (with PATH).
    #[arg(requires = "path")]
    pub method: Option<String>,
    /// HTTP path of the simulated call, e.g. `/repos/OWNER/REPO`.
    pub path: Option<String>,
    /// Simulate `ssh_exec` with this command.
    #[arg(long, conflicts_with_all = ["method", "get", "put", "query"])]
    pub command: Option<String>,
    /// Simulate an SFTP download.
    #[arg(long, num_args = 2, value_names = ["REMOTE", "LOCAL"], conflicts_with_all = ["method", "put", "query"])]
    pub get: Option<Vec<String>>,
    /// Simulate an SFTP upload.
    #[arg(long, num_args = 2, value_names = ["REMOTE", "LOCAL"], conflicts_with_all = ["method", "query"])]
    pub put: Option<Vec<String>>,
    /// Simulate `db_query` with this named query.
    #[arg(long, conflicts_with = "method")]
    pub query: Option<String>,
    /// Number of parameters passed with `--query`.
    #[arg(long, default_value_t = 0, requires = "query")]
    pub params: usize,
    /// Output format for a simulated call: `text` or `json`.
    #[arg(long, default_value = "text")]
    pub format: String,
}

impl TestArgs {
    fn request(&self) -> Option<Request<'_>> {
        if let (Some(method), Some(path)) = (&self.method, &self.path) {
            return Some(Request::Http { method, path });
        }
        if let Some(command) = &self.command {
            return Some(Request::Ssh { command });
        }
        if let Some([remote, local]) = self.get.as_deref().or(self.put.as_deref()) {
            return Some(Request::Sftp { remote, local });
        }
        self.query.as_deref().map(|query| Request::Db {
            query,
            params: self.params,
        })
    }
}

fn test_preset(args: TestArgs, config_path: &Path, kc: &dyn KeychainStore) -> Result<()> {
    let raw = fs::read_to_string(config_path).map_err(WardenError::Io)?;
    let cfg: Config = toml::from_str(&raw).map_err(|e| WardenError::Config(e.to_string()))?;
    let Some(request) = args.request() else {
        cfg.validate(kc)?;
        let p = cfg
            .find(&args.name)
            .ok_or_else(|| WardenError::PresetNotFound(args.name.clone()))?;
        eprintln!(
            "OK: preset '{}' validates against the current keychain.",
            p.name
        );
        return Ok(());
    };
    // A simulated call reads no secret and sends nothing; it only runs the
    // checks the server runs before it would ask for approval.
    let p = cfg
        .find(&args.name)
        .ok_or_else(|| WardenError::PresetNotFound(args.name.clone()))?;
    let lock_path = config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(crate::executor::lock::LOCK_FILE);
    let verdict = if crate::executor::lock::is_present(&lock_path) {
        Verdict::Refused(WardenError::Locked.to_string())
    } else {
        simulate(p, &request, chrono::Utc::now())
    };
    let allowed = matches!(verdict, Verdict::Allowed { .. });
    if args.format == "json" {
        println!("{}", verdict_json(p, &request, &verdict));
    } else {
        println!("{}", verdict_line(&verdict));
    }
    if !allowed {
        // The verdict is the output; exit 1 so scripts can branch on it.
        std::process::exit(1);
    }
    Ok(())
}

fn verdict_line(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Allowed {
            policy: ApprovalPolicy::Auto,
            ..
        } => "ALLOWED — runs without asking (auto)".into(),
        Verdict::Allowed { window_seconds, .. } => match window_seconds {
            Some(n) => format!(
                "ALLOWED — would ask for approval (prompt; {} available)",
                crate::approval::window_label(*n).to_lowercase()
            ),
            None => "ALLOWED — would ask for approval (prompt)".into(),
        },
        Verdict::Refused(why) => format!("REFUSED — {why}"),
    }
}

fn verdict_json(preset: &Preset, request: &Request, verdict: &Verdict) -> serde_json::Value {
    let (allowed, policy, window, reason) = match verdict {
        Verdict::Allowed {
            policy,
            window_seconds,
        } => (true, Some(*policy), *window_seconds, None),
        Verdict::Refused(why) => (false, None, None, Some(why.as_str())),
    };
    serde_json::json!({
        "preset": preset.name,
        "tool": request.tool(),
        "allowed": allowed,
        "approval": policy,
        "approval_window_seconds": window,
        "reason": reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use mcp_warden_core::keychain::memory::InMemoryKeychain;
    use mcp_warden_core::secret::Secret;

    #[derive(Parser)]
    struct AddCli {
        #[command(flatten)]
        add: AddArgs,
    }

    fn parse_add() -> AddArgs {
        let argv = [
            "add",
            "github-read",
            "--type",
            "http",
            "--base-url",
            "https://api.github.com",
            "--auth-bearer",
            "gh_pat",
            "--allowed-methods",
            "GET",
        ];
        AddCli::try_parse_from(argv).unwrap().add
    }

    fn presets(raw: &str) -> Vec<Preset> {
        toml::from_str::<Config>(raw).unwrap().preset
    }

    const HTTP_OPEN: &str = r#"
[[preset]]
name = "open"
type = "http"
description = ""
approval = "prompt"
base_url = "https://api.github.com"
auth = { type = "bearer", secret = "gh_pat" }
allowed_methods = ["GET"]
"#;

    #[test]
    fn parse_duration_accepts_units_and_combinations() {
        let secs = |s: &str| parse_duration(s).unwrap().num_seconds();
        assert_eq!(secs("90s"), 90);
        assert_eq!(secs("30m"), 1_800);
        assert_eq!(secs("1h"), 3_600);
        assert_eq!(secs("2h30m"), 9_000);
        assert_eq!(secs("7d"), 604_800);
        assert_eq!(secs("30d"), 2_592_000);
    }

    #[test]
    fn parse_duration_rejects_bad_input() {
        for s in [
            "",
            "1",
            "h",
            "1x",
            "0m",
            "1h-5m",
            "31d",
            "99999999999999999d",
        ] {
            assert!(parse_duration(s).is_err(), "{s:?}");
        }
    }

    #[test]
    fn open_paths_warning_names_preset_and_base_url() {
        let p = &presets(HTTP_OPEN)[0];
        let w = unrestricted_paths_warning(p).expect("expected a warning");
        assert!(
            w.starts_with(
                "preset 'open' has no allowed_paths: every path under https://api.github.com is allowed"
            ),
            "{w}"
        );
    }

    #[test]
    fn open_paths_warning_skips_presets_with_paths() {
        let mut p = presets(HTTP_OPEN).remove(0);
        p.allowed_paths = vec!["/user/repos".into()];
        assert!(unrestricted_paths_warning(&p).is_none());
    }

    #[test]
    fn open_paths_warning_skips_non_http_presets() {
        let p = &presets(
            r#"
[[preset]]
name = "box"
type = "ssh"
description = ""
approval = "prompt"
host = "example.com"
user = "deploy"
secret = "key"
allowed_commands = ["uptime"]
"#,
        )[0];
        assert!(unrestricted_paths_warning(p).is_none());
    }

    #[test]
    fn add_http_without_allowed_paths_still_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        fs::write(&path, "").unwrap();
        let kc = InMemoryKeychain::new();
        kc.set("gh_pat", Secret::new("ghp_test".into())).unwrap();

        add(parse_add(), &path, &kc).unwrap();

        let cfg: Config = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(cfg.find("github-read").unwrap().allowed_paths.is_empty());
    }
}
