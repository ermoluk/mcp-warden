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
    /// Validate a preset against the current config and keychain.
    Test { name: String },
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
        PresetCmd::Test { name } => test_preset(&name, config_path, kc),
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

    if args.dry_run {
        let wrapper = ScaffoldWrapper {
            preset: vec![preset],
        };
        let rendered =
            toml::to_string_pretty(&wrapper).map_err(|e| WardenError::Config(e.to_string()))?;
        println!("# Generated from template '{}'", template.name);
        println!("# Secret '{secret_name}' must exist in the keychain:");
        println!("#   mcp-warden secret add {secret_name}");
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
    };
    cfg.preset.push(preset);
    cfg.validate(kc)?;
    let toml_str = toml::to_string_pretty(&cfg).map_err(|e| WardenError::Config(e.to_string()))?;
    fs::write(config_path, toml_str).map_err(WardenError::Io)?;
    eprintln!("Added preset '{}'.", args.name);
    Ok(())
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

fn test_preset(name: &str, config_path: &Path, kc: &dyn KeychainStore) -> Result<()> {
    let raw = fs::read_to_string(config_path).map_err(WardenError::Io)?;
    let cfg: Config = toml::from_str(&raw).map_err(|e| WardenError::Config(e.to_string()))?;
    cfg.validate(kc)?;
    let p = cfg
        .find(name)
        .ok_or_else(|| WardenError::PresetNotFound(name.into()))?;
    eprintln!(
        "OK: preset '{}' validates against the current keychain.",
        p.name
    );
    Ok(())
}
