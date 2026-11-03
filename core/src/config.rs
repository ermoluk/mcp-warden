use crate::error::{Result, WardenError};
use crate::keychain::KeychainStore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use url::Url;

/// Compile an allow-list pattern so it must match the WHOLE input.
///
/// The pattern is wrapped in a non-capturing group before anchoring, so an
/// alternation like `uptime|df -h` becomes `^(?:uptime|df -h)$` — not
/// `^uptime|df -h$`, which would match `rm -rf / ; df -h`.
pub fn anchored_regex(pattern: &str) -> std::result::Result<regex::Regex, regex::Error> {
    regex::Regex::new(&format!("^(?:{pattern})$"))
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Config {
    // Skipped when empty: `preset = []` at the top of a written config makes
    // every `[[preset]]` table added below it a TOML error.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preset: Vec<Preset>,
    /// Optional approval-transport configuration. When `approval.telegram`
    /// is set and a `[approval.telegram]` block is present, the binary
    /// selects the Telegram transport over the default desktop prompt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalConfig>,
    /// Other MCP servers that `mcp-warden run <name>` launches with their
    /// keys injected from the keychain instead of written in a client config.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub server: Vec<WrappedServer>,
}

/// An MCP server `mcp-warden run <name>` launches.
///
/// Its keys live in keychain entries of their own, `server/<name>/<VAR>`
/// (see `secret_name`): the config only lists variable names, so no edit to
/// it can point a server — or a command of someone's choosing — at a
/// preset's secret.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WrappedServer {
    pub name: String,
    pub command: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Environment variables `run` sets from this server's keychain entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
}

impl WrappedServer {
    /// The keychain entry that holds `var` for this server.
    pub fn secret_name(&self, var: &str) -> String {
        format!("server/{}/{var}", self.name)
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ApprovalConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telegram: Option<TelegramConfig>,
}

/// Telegram-transport settings. The bot token is never stored here — only the
/// name of the keychain entry that holds it. Add the secret with
/// `mcp-warden secret add <bot_token_secret>` before the binary starts.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TelegramConfig {
    /// Name of the keychain secret that holds the Telegram bot token.
    pub bot_token_secret: String,
    /// Numeric Telegram chat id authorised to approve requests.
    pub chat_id: i64,
    /// Optional per-prompt timeout in seconds (default 120).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
    /// Show the local prompt (the desktop dialog, or the TUI on a terminal)
    /// when a Telegram prompt times out. Off by default: Telegram is for
    /// when the agent may control the screen, and a local dialog is one it
    /// could click.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub desktop_fallback: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Preset {
    pub name: String,
    #[serde(rename = "type")]
    pub preset_type: PresetType,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<Auth>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_methods: Vec<String>,
    pub approval: ApprovalPolicy,
    /// Cap (in seconds) for an approve-for-window option in approval
    /// prompts. `None` (the default) means windowing is disabled for this
    /// preset — every call requires a fresh prompt. Only meaningful when
    /// `approval = "prompt"`; ignored for `auto` and `deny`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_window_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_commands: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
    // SSH/SFTP additions (v0.2.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_hosts: Option<String>,
    #[serde(default)]
    pub allow_sftp: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sftp_allowed_paths: Vec<String>,
    // DB additions (v0.2.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub queries: Vec<NamedQuery>,
    /// When access through this preset ends (`mcp-warden preset grant`).
    /// Calls after this instant are refused; `None` means no time limit.
    /// Written as an RFC 3339 string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// HTTP: largest response body `proxy_http` hands the agent, in bytes.
    /// A larger body is read no further and not returned. It can only lower
    /// mcp-warden's own ceiling (10 MiB of decoded body); `None` uses that.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<u64>,
    /// HTTP: the only JSON fields `proxy_http` returns — `id`,
    /// `owner.login`, `items[].title`, `[].name` (see `parse_field_path`).
    /// Empty: the whole body.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_fields: Vec<String>,
    /// SFTP: the only local directories `sftp_transfer` may read or write,
    /// absolute. Empty: anywhere under `$HOME`, `/tmp` and `/var/tmp`
    /// except the locations that hold credentials or run code.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_local_paths: Vec<String>,
    // Named commands (v0.6.0). Every new field stays out of the JSON while
    // unset: a stamp hashes the preset's JSON, and a field that appeared
    // there would void every confirmed `auto` preset on upgrade.
    /// SSH: largest stdout and stderr, each, that `ssh_exec` and `ssh_run`
    /// read, in bytes; the default for this preset's named commands. It can
    /// only lower mcp-warden's own ceiling (1 MiB); `None` uses that.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_bytes: Option<u64>,
    /// SSH: also offer each named command as its own MCP tool,
    /// `ssh_<preset>_<command>`. `ssh_run` works either way.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub expose_as_tools: bool,
    /// SSH: commands the agent runs by name with typed parameters
    /// (`ssh_run`), instead of composing a command line.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<NamedCommand>,
}

impl Preset {
    /// Every keychain entry this preset reads: its auth's, or its `secret`.
    pub fn secret_names(&self) -> Vec<&str> {
        match &self.auth {
            Some(auth) => auth.secrets(),
            None => self.secret.as_deref().into_iter().collect(),
        }
    }

    /// The entries `get_secret_for_env` may reveal for this preset.
    pub fn revealable_secrets(&self) -> Vec<&str> {
        match &self.auth {
            Some(auth) => auth.revealable(),
            None => self.secret_names(),
        }
    }

    /// Whether a call through this preset could run without a prompt: the
    /// preset's policy, or any named command's, is `auto`. Each counts only
    /// once a human confirmed the preset (`stamp::demote_unconfirmed_auto`).
    pub fn has_auto(&self) -> bool {
        self.approval == ApprovalPolicy::Auto
            || self
                .commands
                .iter()
                .any(|c| c.approval == Some(ApprovalPolicy::Auto))
    }
}

/// One step of a `response_fields` path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldStep {
    /// An object key.
    Key(String),
    /// Every element of an array (`[]`).
    Each,
}

/// Parse a `response_fields` entry: keys separated by `.`, each optionally
/// followed by `[]` for "every element" — `owner.login`, `items[].title`;
/// a leading `[]` addresses a top-level array (`[].name`).
pub fn parse_field_path(path: &str) -> Result<Vec<FieldStep>> {
    let bad = || {
        WardenError::Validation(format!(
            "response_fields entry '{path}': expected keys separated by '.', each optionally \
             followed by '[]' (e.g. `owner.login`, `items[].title`, `[].name`)"
        ))
    };
    let mut steps = Vec::new();
    for segment in path.split('.') {
        let mut name = segment;
        let mut arrays = 0;
        while let Some(rest) = name.strip_suffix("[]") {
            name = rest;
            arrays += 1;
        }
        if name.contains(['[', ']']) || (name.is_empty() && arrays == 0) {
            return Err(bad());
        }
        if !name.is_empty() {
            steps.push(FieldStep::Key(name.to_string()));
        }
        steps.extend(std::iter::repeat_n(FieldStep::Each, arrays));
    }
    Ok(steps)
}

/// A named, parameterised query template declared in a preset. The agent
/// can only invoke queries by name; arbitrary SQL/command text is never
/// accepted from the agent.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NamedQuery {
    pub name: String,
    pub template: String,
    #[serde(default)]
    pub param_types: Vec<String>,
    #[serde(default)]
    pub readonly: bool,
}

/// A command an SSH preset runs by name. The template is fixed; the agent
/// supplies only typed parameter values, each of which becomes one word of
/// the command (or, for `int` and `enum`, part of one).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamedCommand {
    pub name: String,
    pub description: String,
    /// Words separated by single spaces; `{param}` stands for a parameter.
    pub template: String,
    /// Ordered by name, so the preset's fingerprint is the same on every
    /// start.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, ParamSpec>,
    /// Overrides the preset's policy for this command. `auto` counts only
    /// once a human confirmed the preset (`preset confirm`); a preset set to
    /// `deny` refuses every command whatever this says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalPolicy>,
    /// Lowers the preset's `max_output_bytes` for this command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_bytes: Option<u64>,
}

/// What a named command's parameter accepts.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum ParamSpec {
    /// One word matching `pattern` (anchored).
    String { pattern: String },
    /// An absolute path matching `pattern` (anchored), with no `.` or `..`
    /// segment and no `//`.
    Path { pattern: String },
    /// A decimal integer from `min` to `max`.
    Int { min: u64, max: u64 },
    /// One of `values`, exactly.
    Enum { values: Vec<String> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PresetType {
    Http,
    Ssh,
    Postgres,
    Mysql,
    Redis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalPolicy {
    Auto,
    Prompt,
    Deny,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Auth {
    Bearer {
        secret: String,
    },
    Header {
        name: String,
        secret: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
    },
    Basic {
        username: String,
        secret: String,
    },
    /// The credential as a query parameter, `?<name>=<secret>`, as some
    /// APIs want (Google Maps `key=`). The agent cannot send a parameter of
    /// that name itself.
    Query {
        name: String,
        secret: String,
    },
    /// OAuth 2.0: a fresh access token from `token_url` for every call, sent
    /// as a bearer token. `client_secret` and `refresh_token` name keychain
    /// entries; the access token is never stored (invariant 8).
    Oauth2 {
        grant: OAuth2Grant,
        token_url: String,
        client_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_secret: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        refresh_token: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        scopes: Vec<String>,
        #[serde(default, skip_serializing_if = "ClientAuth::is_basic")]
        client_auth: ClientAuth,
    },
    /// AWS Signature Version 4, signed after every allow-list check.
    /// `access_key_id`, `secret_access_key` and `session_token` name
    /// keychain entries.
    #[serde(rename = "aws_sigv4")]
    AwsSigv4 {
        region: String,
        service: String,
        access_key_id: String,
        secret_access_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_token: Option<String>,
    },
}

/// How an OAuth2 preset gets its access token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuth2Grant {
    /// Exchange a stored refresh token; a rotated one replaces it.
    RefreshToken,
    /// The client's own credentials (machine-to-machine).
    ClientCredentials,
}

/// How the client authenticates to the token endpoint (RFC 6749 §2.3.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientAuth {
    /// HTTP Basic with the client id and secret.
    #[default]
    Basic,
    /// `client_id` and `client_secret` in the form body.
    Body,
}

impl ClientAuth {
    fn is_basic(&self) -> bool {
        *self == ClientAuth::Basic
    }
}

impl Auth {
    /// The keychain entries this auth reads, in a fixed order.
    pub fn secrets(&self) -> Vec<&str> {
        match self {
            Auth::Bearer { secret }
            | Auth::Header { secret, .. }
            | Auth::Basic { secret, .. }
            | Auth::Query { secret, .. } => vec![secret],
            Auth::Oauth2 {
                client_secret,
                refresh_token,
                ..
            } => client_secret
                .iter()
                .chain(refresh_token)
                .map(String::as_str)
                .collect(),
            Auth::AwsSigv4 {
                access_key_id,
                secret_access_key,
                session_token,
                ..
            } => [access_key_id, secret_access_key]
                .into_iter()
                .chain(session_token)
                .map(String::as_str)
                .collect(),
        }
    }

    /// The entries `get_secret_for_env` may reveal. Not an OAuth2 preset's:
    /// a refresh token in the agent's hands outlives the call, and once the
    /// provider rotates it, the stored copy no longer matches.
    pub fn revealable(&self) -> Vec<&str> {
        match self {
            Auth::Oauth2 { .. } => vec![],
            other => other.secrets(),
        }
    }
}

/// An OAuth2 preset's token endpoint and client. The endpoint receives the
/// client secret and the refresh token, so it gets the same transport rule
/// as `base_url`: https, or plain http only to loopback.
fn validate_oauth2(p: &Preset, auth: &Auth) -> Result<()> {
    let Auth::Oauth2 {
        grant,
        token_url,
        client_id,
        client_secret,
        refresh_token,
        scopes,
        ..
    } = auth
    else {
        return Ok(());
    };
    let refuse =
        |why: String| WardenError::Validation(format!("preset '{}': oauth2 {why}", p.name));
    let url = Url::parse(token_url).map_err(|e| refuse(format!("token_url parse: {e}")))?;
    let secure = match url.scheme() {
        "https" => true,
        "http" => url.host().is_some_and(|h| is_loopback(&h)),
        _ => false,
    };
    if !secure || url.host().is_none() {
        return Err(refuse(
            "token_url must be https (plain http only to localhost): it receives the client \
             secret and the refresh token"
                .into(),
        ));
    }
    if client_id.is_empty() || client_id.len() > 256 || client_id.chars().any(char::is_control) {
        return Err(refuse(
            "client_id must be 1-256 characters, no control characters".into(),
        ));
    }
    match grant {
        OAuth2Grant::RefreshToken if refresh_token.is_none() => {
            return Err(refuse(
                "grant = \"refresh_token\" needs refresh_token".into(),
            ));
        }
        OAuth2Grant::ClientCredentials if client_secret.is_none() => {
            return Err(refuse(
                "grant = \"client_credentials\" needs client_secret".into(),
            ));
        }
        OAuth2Grant::ClientCredentials if refresh_token.is_some() => {
            return Err(refuse(
                "grant = \"client_credentials\" takes no refresh_token".into(),
            ));
        }
        _ => {}
    }
    // RFC 6749 §3.3: scope tokens are printable ASCII without space, '"'
    // or '\'.
    if let Some(bad) = scopes.iter().find(|s| {
        s.is_empty()
            || !s
                .bytes()
                .all(|b| matches!(b, 0x21 | 0x23..=0x5B | 0x5D..=0x7E))
    }) {
        return Err(refuse(format!(
            "scope '{}' is not a valid scope token",
            bad.escape_debug()
        )));
    }
    Ok(())
}

/// `localhost`, 127.0.0.0/8 or `::1`: a host whose traffic cannot leave
/// this machine.
fn is_loopback(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(d) => d.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    }
}

impl Config {
    pub fn load_and_validate(path: &Path, kc: &dyn KeychainStore) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(WardenError::Io)?;
        let cfg: Self =
            toml::from_str(&raw).map_err(|e| WardenError::Config(format!("parse: {e}")))?;
        cfg.validate(kc)?;
        Ok(cfg)
    }

    pub fn validate(&self, kc: &dyn KeychainStore) -> Result<()> {
        self.validate_servers()?;
        let mut names = std::collections::HashSet::new();
        if let Some(dup) = self.preset.iter().find(|p| !names.insert(&p.name)) {
            return Err(WardenError::Validation(format!(
                "more than one preset named '{}'",
                dup.name
            )));
        }
        for p in &self.preset {
            if p.name.is_empty() {
                return Err(WardenError::Validation("preset name empty".into()));
            }
            // A preset naming a confirmation stamp (or the key that signs
            // them) could send it upstream or reveal it to the agent.
            if let Some(secret) = p
                .secret_names()
                .into_iter()
                .find(|s| crate::stamp::is_reserved_name(s))
            {
                return Err(WardenError::Validation(format!(
                    "preset '{}': keychain entry '{secret}' is reserved for mcp-warden's own \
                     records and cannot be a preset's secret",
                    p.name
                )));
            }
            if p.preset_type != PresetType::Ssh
                && (!p.commands.is_empty() || p.expose_as_tools || p.max_output_bytes.is_some())
            {
                return Err(WardenError::Validation(format!(
                    "preset '{}': commands, expose_as_tools and max_output_bytes are for ssh \
                     presets",
                    p.name
                )));
            }
            match p.preset_type {
                PresetType::Http => self.validate_http(p, kc)?,
                PresetType::Ssh => self.validate_ssh(p, kc)?,
                PresetType::Postgres | PresetType::Mysql | PresetType::Redis => {
                    self.validate_db(p, kc)?
                }
            }
        }
        crate::commands::validate_tool_names(&self.preset)?;
        self.validate_refresh_token_entries()?;
        if let Some(approval) = &self.approval
            && let Some(tg) = &approval.telegram
        {
            if tg.bot_token_secret.is_empty() {
                return Err(WardenError::Validation(
                    "approval.telegram.bot_token_secret is empty".into(),
                ));
            }
            if crate::stamp::is_reserved_name(&tg.bot_token_secret) {
                return Err(WardenError::Validation(format!(
                    "approval.telegram.bot_token_secret '{}' is reserved for mcp-warden's own \
                     records",
                    tg.bot_token_secret
                )));
            }
            if tg.chat_id == 0 {
                return Err(WardenError::Validation(
                    "approval.telegram.chat_id is zero — expected a numeric Telegram chat id"
                        .into(),
                ));
            }
            if kc.get(&tg.bot_token_secret)?.is_none() {
                return Err(WardenError::Validation(format!(
                    "approval.telegram.bot_token_secret refers to keychain entry '{}' which is not present — \
                     run: mcp-warden secret add {}",
                    tg.bot_token_secret, tg.bot_token_secret
                )));
            }
        }
        Ok(())
    }

    fn validate_http(&self, p: &Preset, kc: &dyn KeychainStore) -> Result<()> {
        let base = p.base_url.as_deref().ok_or_else(|| {
            WardenError::Validation(format!("preset '{}': base_url required for http", p.name))
        })?;
        let parsed = Url::parse(base).map_err(|e| {
            WardenError::Validation(format!("preset '{}': base_url parse: {e}", p.name))
        })?;
        match parsed.scheme() {
            "https" => {}
            // The credential would cross the network in clear text. Only a
            // connection that cannot leave this machine may skip TLS (as
            // for databases, R10); reach anything else over https or an
            // SSH tunnel to localhost.
            "http" if parsed.host().is_some_and(|h| is_loopback(&h)) => {}
            "http" => {
                return Err(WardenError::Validation(format!(
                    "preset '{}': base_url uses plain http to a host that is not loopback, so \
                     the credential would cross the network unencrypted; use https, or an \
                     SSH tunnel to localhost (`ssh -L 8080:localhost:80 host`, then \
                     base_url = \"http://localhost:8080\")",
                    p.name
                )));
            }
            other => {
                return Err(WardenError::Validation(format!(
                    "preset '{}': base_url scheme '{}' not allowed",
                    p.name, other
                )));
            }
        }
        if parsed.host().is_none() {
            return Err(WardenError::Validation(format!(
                "preset '{}': base_url missing host",
                p.name
            )));
        }
        if p.max_response_bytes == Some(0) {
            return Err(WardenError::Validation(format!(
                "preset '{}': max_response_bytes must be at least 1",
                p.name
            )));
        }
        for field in &p.response_fields {
            parse_field_path(field)
                .map_err(|e| WardenError::Validation(format!("preset '{}': {e}", p.name)))?;
        }
        for m in &p.allowed_methods {
            match m.as_str() {
                "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" => {}
                _ => {
                    return Err(WardenError::Validation(format!(
                        "preset '{}': method '{}' not allowed",
                        p.name, m
                    )));
                }
            }
        }
        let Some(auth) = &p.auth else {
            return Err(WardenError::Validation(format!(
                "preset '{}': auth required",
                p.name
            )));
        };
        if let Auth::Query { name, .. } = auth {
            if name.is_empty()
                || name.len() > 64
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
            {
                return Err(WardenError::Validation(format!(
                    "preset '{}': query auth name must be 1-64 of A-Z a-z 0-9 _ . -",
                    p.name
                )));
            }
            if parsed
                .query_pairs()
                .any(|(k, _)| k.eq_ignore_ascii_case(name))
            {
                return Err(WardenError::Validation(format!(
                    "preset '{}': base_url already has a '{name}' query parameter; the \
                     credential would be sent twice",
                    p.name
                )));
            }
        }
        if let Auth::Oauth2 { .. } = auth {
            validate_oauth2(p, auth)?;
        }
        if let Auth::AwsSigv4 {
            region, service, ..
        } = auth
        {
            for (field, value) in [("region", region), ("service", service)] {
                if value.is_empty()
                    || value.len() > 32
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                {
                    return Err(WardenError::Validation(format!(
                        "preset '{}': aws_sigv4 {field} must be 1-32 of a-z 0-9 -",
                        p.name
                    )));
                }
            }
        }
        let names = auth.secrets();
        if names
            .iter()
            .enumerate()
            .any(|(i, n)| names[..i].contains(n))
        {
            return Err(WardenError::Validation(format!(
                "preset '{}': each credential of its auth needs a keychain entry of its own",
                p.name
            )));
        }
        for secret in auth.secrets() {
            if kc.get(secret)?.is_none() {
                return Err(WardenError::MissingSecret {
                    preset: p.name.clone(),
                    secret: secret.to_string(),
                });
            }
        }
        Ok(())
    }

    fn validate_ssh(&self, p: &Preset, kc: &dyn KeychainStore) -> Result<()> {
        if p.host.is_none() {
            return Err(WardenError::Validation(format!(
                "preset '{}': ssh requires host",
                p.name
            )));
        }
        if p.user.is_none() {
            return Err(WardenError::Validation(format!(
                "preset '{}': ssh requires user",
                p.name
            )));
        }
        let secret_name = p.secret.as_deref().ok_or_else(|| {
            WardenError::Validation(format!(
                "preset '{}': ssh requires secret (private-key name)",
                p.name
            ))
        })?;
        if kc.get(secret_name)?.is_none() {
            return Err(WardenError::MissingSecret {
                preset: p.name.clone(),
                secret: secret_name.to_string(),
            });
        }
        for re in &p.allowed_commands {
            anchored_regex(re).map_err(|e| {
                WardenError::Validation(format!(
                    "preset '{}': bad command regex '{re}': {e}",
                    p.name
                ))
            })?;
        }
        crate::commands::validate_preset(p)?;
        if p.allow_sftp {
            for dir in &p.allowed_local_paths {
                if !Path::new(dir).is_absolute() {
                    return Err(WardenError::Validation(format!(
                        "preset '{}': allowed_local_paths must be absolute, got '{dir}'",
                        p.name
                    )));
                }
            }
            for prefix in &p.sftp_allowed_paths {
                if !prefix.starts_with('/') {
                    return Err(WardenError::Validation(format!(
                        "preset '{}': sftp_allowed_paths must be rooted (start with /), got '{prefix}'",
                        p.name
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_db(&self, p: &Preset, kc: &dyn KeychainStore) -> Result<()> {
        if p.host.is_none() {
            return Err(WardenError::Validation(format!(
                "preset '{}': db requires host",
                p.name
            )));
        }
        if p.user.is_none() {
            return Err(WardenError::Validation(format!(
                "preset '{}': db requires user",
                p.name
            )));
        }
        let secret_name = p.secret.as_deref().ok_or_else(|| {
            WardenError::Validation(format!(
                "preset '{}': db requires secret (password name)",
                p.name
            ))
        })?;
        if kc.get(secret_name)?.is_none() {
            return Err(WardenError::MissingSecret {
                preset: p.name.clone(),
                secret: secret_name.to_string(),
            });
        }
        if !matches!(p.preset_type, PresetType::Redis) && p.database.is_none() {
            return Err(WardenError::Validation(format!(
                "preset '{}': database name required",
                p.name
            )));
        }
        if p.queries.is_empty() {
            return Err(WardenError::Validation(format!(
                "preset '{}': at least one named query required (named-query allow-list)",
                p.name
            )));
        }
        for q in &p.queries {
            if q.name.is_empty() || q.template.is_empty() {
                return Err(WardenError::Validation(format!(
                    "preset '{}': named query has empty name or template",
                    p.name
                )));
            }
        }
        Ok(())
    }

    /// A refresh token's keychain entry is written when the provider
    /// rotates the token, so it may belong to that one preset only: a
    /// hostile token endpoint must not be able to overwrite another
    /// preset's credential, a wrapped server's key or the Telegram token.
    fn validate_refresh_token_entries(&self) -> Result<()> {
        for p in &self.preset {
            let Some(Auth::Oauth2 {
                refresh_token: Some(entry),
                ..
            }) = &p.auth
            else {
                continue;
            };
            let shared = self
                .preset
                .iter()
                .filter(|q| q.secret_names().contains(&entry.as_str()))
                .count()
                > 1
                || self
                    .server
                    .iter()
                    .any(|s| s.env.iter().any(|var| &s.secret_name(var) == entry))
                || self
                    .approval
                    .as_ref()
                    .and_then(|a| a.telegram.as_ref())
                    .is_some_and(|t| &t.bot_token_secret == entry);
            if shared {
                return Err(WardenError::Validation(format!(
                    "preset '{}': refresh_token entry '{entry}' is also used elsewhere; a \
                     rotated token is written back to it, so give it an entry of its own",
                    p.name
                )));
            }
        }
        Ok(())
    }

    pub fn find(&self, name: &str) -> Option<&Preset> {
        self.preset.iter().find(|p| p.name == name)
    }

    /// Check the shape of every `[[server]]` entry. Their secrets are not
    /// looked up here: they belong to `mcp-warden run`, which checks them
    /// when it launches the server.
    pub fn validate_servers(&self) -> Result<()> {
        let mut seen = std::collections::HashSet::new();
        for s in &self.server {
            if s.command.is_empty() {
                return Err(WardenError::Validation(
                    "every [[server]] needs a name and a command".into(),
                ));
            }
            let name_ok = !s.name.is_empty()
                && s.name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
            if !name_ok {
                return Err(WardenError::Validation(format!(
                    "server name '{}': use letters, digits, '_', '-' or '.'",
                    s.name
                )));
            }
            if !seen.insert(s.name.as_str()) {
                return Err(WardenError::Validation(format!(
                    "two [[server]] entries are named '{}'",
                    s.name
                )));
            }
            let mut vars = std::collections::HashSet::new();
            for var in &s.env {
                if !vars.insert(var.as_str()) {
                    return Err(WardenError::Validation(format!(
                        "server '{}' lists {var} twice",
                        s.name
                    )));
                }
                let mut chars = var.chars();
                let valid = chars
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                    && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
                if !valid {
                    return Err(WardenError::Validation(format!(
                        "server '{}': '{var}' is not a valid environment variable name",
                        s.name
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn find_server(&self, name: &str) -> Option<&WrappedServer> {
        self.server.iter().find(|s| s.name == name)
    }
}

pub fn config_path() -> PathBuf {
    directories::ProjectDirs::from("io", "mcp-warden", "mcp-warden")
        .map(|d| d.config_dir().join("config.toml"))
        .unwrap_or_else(|| PathBuf::from("./mcp-warden.toml"))
}

#[cfg(test)]
mod tests {

    fn servers(toml: &str) -> Result<()> {
        let cfg: Config = toml::from_str(toml).unwrap();
        cfg.validate_servers()
    }

    #[test]
    fn a_written_config_without_presets_takes_preset_tables_later() {
        let cfg: Config = toml::from_str("[[server]]\nname = \"a\"\ncommand = \"x\"\n").unwrap();
        let written = toml::to_string_pretty(&cfg).unwrap();
        assert!(!written.contains("preset"), "{written}");
        let appended = format!(
            "{written}\n[[preset]]\nname = \"p\"\ntype = \"http\"\ndescription = \"x\"\napproval = \"prompt\"\n"
        );
        let back: Config = toml::from_str(&appended).unwrap();
        assert_eq!(back.preset.len(), 1);
        assert_eq!(back.server.len(), 1);
    }

    #[test]
    fn response_limits_are_validated() {
        let kc = InMemoryKeychain::new();
        kc.set("k", Secret::new("v".into())).unwrap();
        let cfg = |extra: &str| -> Config {
            toml::from_str(&format!(
                "[[preset]]\nname = \"p\"\ntype = \"http\"\ndescription = \"x\"\n\
                 base_url = \"https://api.example.com\"\nauth = {{ type = \"bearer\", secret = \"k\" }}\n\
                 approval = \"prompt\"\n{extra}"
            ))
            .unwrap()
        };
        cfg("max_response_bytes = 1024\nresponse_fields = [\"id\", \"items[].title\"]")
            .validate(&kc)
            .unwrap();
        assert!(cfg("max_response_bytes = 0").validate(&kc).is_err());
        assert!(cfg("response_fields = [\"a..b\"]").validate(&kc).is_err());
    }

    #[test]
    fn field_paths_parse() {
        use FieldStep::{Each, Key};
        let key = |k: &str| Key(k.to_string());
        assert_eq!(parse_field_path("id").unwrap(), [key("id")]);
        assert_eq!(
            parse_field_path("owner.login").unwrap(),
            [key("owner"), key("login")]
        );
        assert_eq!(
            parse_field_path("items[].title").unwrap(),
            [key("items"), Each, key("title")]
        );
        assert_eq!(parse_field_path("[].name").unwrap(), [Each, key("name")]);
        assert_eq!(
            parse_field_path("grid[][]").unwrap(),
            [key("grid"), Each, Each]
        );
        for bad in ["", "a..b", "a.", ".a", "a[b", "a]", "a[0]", "a[]b"] {
            assert!(parse_field_path(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn server_entries_parse_and_validate() {
        let cfg: Config = toml::from_str(
            r#"
            [[server]]
            name = "github"
            command = "npx"
            args = ["-y", "@modelcontextprotocol/server-github"]
            env = ["GITHUB_PERSONAL_ACCESS_TOKEN"]
            "#,
        )
        .unwrap();
        cfg.validate_servers().unwrap();
        let s = cfg.find_server("github").unwrap();
        assert_eq!(s.args.len(), 2);
        assert_eq!(
            s.secret_name("GITHUB_PERSONAL_ACCESS_TOKEN"),
            "server/github/GITHUB_PERSONAL_ACCESS_TOKEN"
        );
    }

    #[test]
    fn server_entries_reject_bad_shapes() {
        let dup = r#"
            [[server]]
            name = "a"
            command = "x"
            [[server]]
            name = "a"
            command = "y"
        "#;
        assert!(servers(dup).is_err());
        assert!(servers("[[server]]\nname = \"a\"\ncommand = \"\"").is_err());
        for var in ["1ABC", "A-B", "A B", ""] {
            let t = format!("[[server]]\nname = \"a\"\ncommand = \"x\"\nenv = [\"{var}\"]");
            assert!(servers(&t).is_err(), "{var:?}");
        }
        assert!(
            servers("[[server]]\nname = \"a\"\ncommand = \"x\"\nenv = [\"A\", \"A\"]").is_err()
        );
        for name in ["", "a/b", "../x", "a b"] {
            let t = format!("[[server]]\nname = \"{name}\"\ncommand = \"x\"");
            assert!(servers(&t).is_err(), "{name:?}");
        }
    }

    use super::*;
    use crate::keychain::KeychainStore;
    use crate::keychain::memory::InMemoryKeychain;
    use crate::secret::Secret;

    #[test]
    fn parses_valid_config() {
        let toml_src = include_str!("../../tests/fixtures/valid_config.toml");
        let cfg: Config = toml::from_str(toml_src).unwrap();
        assert_eq!(cfg.preset.len(), 1);
        let p = &cfg.preset[0];
        assert_eq!(p.name, "github-read");
        assert!(matches!(p.preset_type, PresetType::Http));
        assert_eq!(p.approval, ApprovalPolicy::Auto);
    }

    #[test]
    fn refuses_missing_secret_reference() {
        let toml_src = include_str!("../../tests/fixtures/invalid_missing_secret.toml");
        let cfg: Config = toml::from_str(toml_src).unwrap();
        let kc = InMemoryKeychain::new();
        let err = cfg.validate(&kc).unwrap_err();
        assert_eq!(
            err.to_string(),
            "preset references missing secret: preset='stripe-api' secret='stripe_key_does_not_exist'"
        );
    }

    #[test]
    fn passes_validation_when_secret_present() {
        let toml_src = include_str!("../../tests/fixtures/valid_config.toml");
        let cfg: Config = toml::from_str(toml_src).unwrap();
        let kc = InMemoryKeychain::new();
        kc.set("gh_pat", Secret::new("ghp_x".into())).unwrap();
        cfg.validate(&kc).unwrap();
    }

    #[test]
    fn plain_http_is_refused_unless_the_host_is_loopback() {
        let cfg = |url: &str| -> Config {
            toml::from_str(&format!(
                r#"
                [[preset]]
                name = "p"
                type = "http"
                description = "x"
                base_url = "{url}"
                auth = {{ type = "bearer", secret = "x" }}
                allowed_methods = ["GET"]
                approval = "prompt"
                "#
            ))
            .unwrap()
        };
        let kc = InMemoryKeychain::new();
        kc.set("x", Secret::new("y".into())).unwrap();
        for remote in [
            "http://api.example.com",
            "http://192.168.1.10:3000",
            "http://10.0.0.1",
            "http://localhost.example.com",
            "http://evil.localhost",
            "http://[::ffff:127.0.0.1]",
            "http://0.0.0.0:8080",
        ] {
            let err = cfg(remote).validate(&kc).unwrap_err().to_string();
            assert!(err.contains("plain http"), "{remote}: {err}");
        }
        for local in [
            "http://localhost:8080",
            "http://LOCALHOST",
            "http://127.0.0.1:3000",
            "http://127.1.2.3",
            "http://[::1]:8080",
            "https://api.example.com",
        ] {
            cfg(local)
                .validate(&kc)
                .unwrap_or_else(|e| panic!("{local}: {e}"));
        }
    }

    /// `stamp/…` entries are mcp-warden's confirmations, not secrets: a
    /// preset that named one could send or reveal the stamp key.
    #[test]
    fn presets_cannot_use_a_reserved_keychain_name() {
        let kc = InMemoryKeychain::new();
        for name in [
            "stamp/key",
            "audit/anchor/0123456789abcdef",
            "audit/anchor/x",
        ] {
            kc.set(name, Secret::new("k".into())).unwrap();
        }
        for preset in [
            r#"
            [[preset]]
            name = "p"
            type = "http"
            description = "x"
            base_url = "https://example.com"
            auth = { type = "bearer", secret = "stamp/key" }
            allowed_methods = ["GET"]
            approval = "prompt"
            "#,
            r#"
            [[preset]]
            name = "p"
            type = "ssh"
            description = "x"
            host = "h"
            user = "u"
            secret = "stamp/key"
            approval = "prompt"
            "#,
            r#"
            [[preset]]
            name = "p"
            type = "http"
            description = "x"
            base_url = "https://example.com"
            auth = { type = "query", name = "key", secret = "audit/anchor/0123456789abcdef" }
            allowed_methods = ["GET"]
            approval = "prompt"
            "#,
            r#"
            [approval.telegram]
            bot_token_secret = "audit/anchor/x"
            chat_id = 42
            "#,
        ] {
            let cfg: Config = toml::from_str(preset).unwrap();
            let err = cfg.validate(&kc).unwrap_err().to_string();
            assert!(err.contains("reserved"), "{err}");
        }
    }

    /// Lookups take the first preset of a name, while `list_presets`, the
    /// web UI and approval windows would see both: refuse duplicates.
    #[test]
    fn duplicate_preset_names_are_refused() {
        let cfg: Config = toml::from_str(
            r#"
            [[preset]]
            name = "gh"
            type = "http"
            description = "read"
            base_url = "https://api.github.com"
            auth = { type = "bearer", secret = "x" }
            allowed_methods = ["GET"]
            approval = "prompt"

            [[preset]]
            name = "gh"
            type = "http"
            description = "write"
            base_url = "https://api.github.com"
            auth = { type = "bearer", secret = "x" }
            allowed_methods = ["DELETE"]
            approval = "auto"
            "#,
        )
        .unwrap();
        let kc = InMemoryKeychain::new();
        kc.set("x", Secret::new("y".into())).unwrap();
        let err = cfg.validate(&kc).unwrap_err().to_string();
        assert!(err.contains("more than one preset named 'gh'"), "{err}");
    }

    #[test]
    fn rejects_non_http_non_https_base_url() {
        let toml_src = r#"
            [[preset]]
            name = "bad"
            type = "http"
            description = "x"
            base_url = "file:///etc/passwd"
            auth = { type = "bearer", secret = "x" }
            allowed_methods = ["GET"]
            approval = "auto"
        "#;
        let cfg: Config = toml::from_str(toml_src).unwrap();
        let kc = InMemoryKeychain::new();
        kc.set("x", Secret::new("y".into())).unwrap();
        let err = cfg.validate(&kc).unwrap_err();
        assert!(err.to_string().contains("base_url scheme"));
    }

    // -------- v0.2.0 schema additions --------

    #[test]
    fn parses_ssh_preset_with_sftp() {
        let toml_src = include_str!("../../tests/fixtures/ssh_preset.toml");
        let cfg: Config = toml::from_str(toml_src).unwrap();
        let p = &cfg.preset[0];
        assert!(matches!(p.preset_type, PresetType::Ssh));
        assert_eq!(p.host.as_deref(), Some("deploy.example.com"));
        assert_eq!(p.user.as_deref(), Some("deploy"));
        assert!(p.allow_sftp);
        assert_eq!(p.sftp_allowed_paths.len(), 2);
        assert_eq!(p.allowed_commands.len(), 2);
    }

    #[test]
    fn parses_postgres_preset_with_named_queries() {
        let toml_src = include_str!("../../tests/fixtures/postgres_preset.toml");
        let cfg: Config = toml::from_str(toml_src).unwrap();
        let p = &cfg.preset[0];
        assert!(matches!(p.preset_type, PresetType::Postgres));
        assert_eq!(p.database.as_deref(), Some("analytics"));
        assert_eq!(p.queries.len(), 2);
        assert_eq!(p.queries[0].name, "find_user");
        assert_eq!(p.queries[0].param_types, vec!["int8"]);
        assert!(p.queries[0].readonly);
    }

    #[test]
    fn parses_redis_preset() {
        let toml_src = include_str!("../../tests/fixtures/redis_preset.toml");
        let cfg: Config = toml::from_str(toml_src).unwrap();
        let p = &cfg.preset[0];
        assert!(matches!(p.preset_type, PresetType::Redis));
        assert_eq!(p.queries.len(), 2);
        assert_eq!(p.queries[1].template, "SET");
    }

    #[test]
    fn ssh_preset_requires_host_user_secret() {
        let toml_src = r#"
            [[preset]]
            name = "bad"
            type = "ssh"
            description = "x"
            approval = "prompt"
        "#;
        let cfg: Config = toml::from_str(toml_src).unwrap();
        let kc = InMemoryKeychain::new();
        let err = cfg.validate(&kc).unwrap_err();
        assert!(err.to_string().contains("ssh"));
    }

    #[test]
    fn ssh_preset_rejects_unrooted_sftp_paths() {
        let toml_src = r#"
            [[preset]]
            name = "bad"
            type = "ssh"
            description = "x"
            host = "h"
            user = "u"
            secret = "k"
            allow_sftp = true
            sftp_allowed_paths = ["srv/app/"]
            approval = "prompt"
        "#;
        let cfg: Config = toml::from_str(toml_src).unwrap();
        let kc = InMemoryKeychain::new();
        kc.set("k", Secret::new("p".into())).unwrap();
        let err = cfg.validate(&kc).unwrap_err();
        assert!(err.to_string().contains("rooted"));
    }

    #[test]
    fn ssh_preset_rejects_bad_command_regex() {
        let toml_src = r#"
            [[preset]]
            name = "bad"
            type = "ssh"
            description = "x"
            host = "h"
            user = "u"
            secret = "k"
            allowed_commands = ["[unclosed"]
            approval = "prompt"
        "#;
        let cfg: Config = toml::from_str(toml_src).unwrap();
        let kc = InMemoryKeychain::new();
        kc.set("k", Secret::new("p".into())).unwrap();
        let err = cfg.validate(&kc).unwrap_err();
        assert!(err.to_string().contains("bad command regex"));
    }

    #[test]
    fn db_preset_requires_at_least_one_named_query() {
        let toml_src = r#"
            [[preset]]
            name = "bad"
            type = "postgres"
            description = "x"
            host = "h"
            user = "u"
            secret = "k"
            database = "app"
            approval = "prompt"
        "#;
        let cfg: Config = toml::from_str(toml_src).unwrap();
        let kc = InMemoryKeychain::new();
        kc.set("k", Secret::new("p".into())).unwrap();
        let err = cfg.validate(&kc).unwrap_err();
        assert!(err.to_string().contains("named quer"));
    }

    #[test]
    fn db_preset_passes_with_query_and_secret() {
        let toml_src = include_str!("../../tests/fixtures/postgres_preset.toml");
        let cfg: Config = toml::from_str(toml_src).unwrap();
        let kc = InMemoryKeychain::new();
        kc.set("analytics_pg_password", Secret::new("hunter2".into()))
            .unwrap();
        cfg.validate(&kc).unwrap();
    }

    #[test]
    fn approval_window_seconds_defaults_to_none() {
        let toml_src = include_str!("../../tests/fixtures/valid_config.toml");
        let cfg: Config = toml::from_str(toml_src).unwrap();
        assert_eq!(cfg.preset[0].approval_window_seconds, None);
    }

    #[test]
    fn approval_window_seconds_parses_when_present() {
        let toml_src = r#"
            [[preset]]
            name = "windowed"
            type = "http"
            description = "x"
            base_url = "https://api.example.com"
            auth = { type = "bearer", secret = "k" }
            allowed_methods = ["GET"]
            approval = "prompt"
            approval_window_seconds = 1800
        "#;
        let cfg: Config = toml::from_str(toml_src).unwrap();
        let kc = InMemoryKeychain::new();
        kc.set("k", Secret::new("v".into())).unwrap();
        cfg.validate(&kc).unwrap();
        assert_eq!(cfg.preset[0].approval_window_seconds, Some(1800));
    }

    #[test]
    fn approval_window_seconds_round_trips_through_toml() {
        let cfg = Config {
            approval: None,
            server: vec![],
            preset: vec![Preset {
                name: "p".into(),
                preset_type: PresetType::Http,
                description: "x".into(),
                base_url: Some("https://api.example.com".into()),
                auth: Some(Auth::Bearer { secret: "k".into() }),
                allowed_paths: vec![],
                allowed_methods: vec!["GET".into()],
                approval: ApprovalPolicy::Prompt,
                approval_window_seconds: Some(600),
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
                allowed_local_paths: vec![],
                max_output_bytes: None,
                expose_as_tools: false,
                commands: vec![],
            }],
        };
        let s = toml::to_string(&cfg).unwrap();
        assert!(s.contains("approval_window_seconds = 600"));
        let parsed: Config = toml::from_str(&s).unwrap();
        assert_eq!(parsed.preset[0].approval_window_seconds, Some(600));
    }

    #[test]
    fn redis_preset_does_not_require_database() {
        let toml_src = include_str!("../../tests/fixtures/redis_preset.toml");
        let cfg: Config = toml::from_str(toml_src).unwrap();
        let kc = InMemoryKeychain::new();
        kc.set("redis_password", Secret::new("p".into())).unwrap();
        cfg.validate(&kc).unwrap();
    }

    fn named_commands() -> Config {
        toml::from_str(include_str!("../../tests/fixtures/named_commands.toml")).unwrap()
    }

    #[test]
    fn named_commands_parse() {
        let cfg = named_commands();
        let p = &cfg.preset[0];
        assert!(p.expose_as_tools);
        assert_eq!(p.max_output_bytes, Some(65536));
        let names: Vec<_> = p.commands.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            ["tail_log", "restart", "trash_file", "checkout", "head_log"]
        );
        assert_eq!(
            p.commands[0].params["lines"],
            ParamSpec::Int { min: 1, max: 500 }
        );
        assert_eq!(p.commands[0].max_output_bytes, Some(262144));
        assert_eq!(
            p.commands[1].params["unit"],
            ParamSpec::Enum {
                values: vec!["app.service".into(), "worker.service".into()]
            }
        );
        assert!(matches!(
            p.commands[2].params["path"],
            ParamSpec::Path { .. }
        ));
        assert!(matches!(
            p.commands[3].params["tag"],
            ParamSpec::String { .. }
        ));
        assert_eq!(p.commands[0].approval, None);
    }

    #[test]
    fn named_commands_round_trip_through_toml() {
        let cfg = named_commands();
        let written = toml::to_string_pretty(&cfg).unwrap();
        let again: Config = toml::from_str(&written).unwrap();
        assert_eq!(
            serde_json::to_value(&again.preset).unwrap(),
            serde_json::to_value(&cfg.preset).unwrap()
        );
    }

    /// A typo in a command or a parameter must not be silently ignored:
    /// `pattrn` instead of `pattern` would leave a parameter unchecked.
    #[test]
    fn unknown_fields_in_commands_and_params_are_refused() {
        let base = include_str!("../../tests/fixtures/named_commands.toml");
        for (from, to) in [
            (
                "template = \"mv {path} /srv/app/.trash/\"",
                "template = \"mv {path} /srv/app/.trash/\"\nunknown = 1",
            ),
            ("type = \"path\", pattern", "type = \"path\", pattrn"),
            (
                "type = \"int\", min = 1, max = 500",
                "type = \"int\", min = 1, max = 500, step = 2",
            ),
            ("type = \"enum\"", "type = \"regex\""),
        ] {
            assert!(base.contains(from), "{from}");
            let edited = base.replacen(from, to, 1);
            assert!(toml::from_str::<Config>(&edited).is_err(), "accepted: {to}");
        }
    }

    /// Presets without commands serialise exactly as before 0.6.0, so their
    /// stamps stay valid.
    #[test]
    fn presets_without_commands_serialise_without_the_new_fields() {
        let cfg: Config =
            toml::from_str(include_str!("../../tests/fixtures/ssh_preset.toml")).unwrap();
        let json = serde_json::to_value(&cfg.preset[0]).unwrap();
        for field in ["max_output_bytes", "expose_as_tools", "commands"] {
            assert!(json.get(field).is_none(), "{field}");
        }
    }

    /// One bad command stops the server, naming the preset and the command
    /// (invariant 10).
    #[test]
    fn a_bad_named_command_refuses_the_whole_config() {
        let base = include_str!("../../tests/fixtures/named_commands.toml");
        let kc = InMemoryKeychain::new();
        kc.set("deploy_key", Secret::new("k".into())).unwrap();
        let ok: Config = toml::from_str(base).unwrap();
        ok.validate(&kc).unwrap();
        let bad: Config = toml::from_str(&base.replacen(
            "mv {path} /srv/app/.trash/",
            "mv {path} /srv/app/.trash/ ; id",
            1,
        ))
        .unwrap();
        let err = bad.validate(&kc).unwrap_err().to_string();
        assert!(
            err.contains("preset 'deploy': command 'trash_file'"),
            "{err}"
        );
    }

    #[test]
    fn named_commands_are_for_ssh_presets_only() {
        let mut cfg: Config =
            toml::from_str(include_str!("../../tests/fixtures/valid_config.toml")).unwrap();
        let commands = named_commands().preset[0].commands.clone();
        cfg.preset[0].commands = commands;
        let kc = InMemoryKeychain::new();
        for name in ["github_pat", "gh_pat", "k"] {
            kc.set(name, Secret::new("x".into())).unwrap();
        }
        let err = cfg.validate(&kc).unwrap_err().to_string();
        assert!(err.contains("are for ssh presets"), "{err}");
    }

    #[test]
    fn query_auth_names_are_checked() {
        let kc = InMemoryKeychain::new();
        kc.set("maps_key", Secret::new("x".into())).unwrap();
        let config = |base: &str, name: &str| -> Config {
            toml::from_str(&format!(
                r#"
                [[preset]]
                name = "maps"
                type = "http"
                description = "x"
                base_url = "{base}"
                auth = {{ type = "query", name = "{name}", secret = "maps_key" }}
                allowed_methods = ["GET"]
                approval = "prompt"
                "#
            ))
            .unwrap()
        };
        config("https://maps.example.com", "key")
            .validate(&kc)
            .unwrap();
        for (base, name) in [
            ("https://maps.example.com", ""),
            ("https://maps.example.com", "a b"),
            ("https://maps.example.com", "k&x"),
            ("https://maps.example.com?KEY=1", "key"),
        ] {
            assert!(config(base, name).validate(&kc).is_err(), "{base} {name:?}");
        }
    }

    #[test]
    fn oauth2_presets_are_checked() {
        let kc = InMemoryKeychain::new();
        for name in ["cs", "rt", "other"] {
            kc.set(name, Secret::new("x".into())).unwrap();
        }
        let config = |auth: &str, extra: &str| -> Config {
            toml::from_str(&format!(
                r#"
                [[preset]]
                name = "drive"
                type = "http"
                description = "x"
                base_url = "https://www.googleapis.com"
                allowed_methods = ["GET"]
                approval = "prompt"
                [preset.auth]
                type = "oauth2"
                client_id = "id"
                {auth}
                {extra}
                "#
            ))
            .unwrap()
        };
        let ok = r#"grant = "refresh_token"
            token_url = "https://oauth2.googleapis.com/token"
            client_secret = "cs"
            refresh_token = "rt""#;
        config(ok, "").validate(&kc).unwrap();
        config(
            r#"grant = "client_credentials"
            token_url = "http://localhost:8080/token"
            client_secret = "cs"
            scopes = ["a.read", "b:write"]"#,
            "",
        )
        .validate(&kc)
        .unwrap();
        for bad in [
            ok.replace(
                "https://oauth2.googleapis.com",
                "http://oauth2.googleapis.com",
            ),
            ok.replace("https://oauth2.googleapis.com/token", "file:///etc/token"),
            ok.replace("refresh_token = \"rt\"", ""),
            ok.replace("refresh_token = \"rt\"", "refresh_token = \"cs\""),
            ok.replace("\"refresh_token\"\n", "\"client_credentials\"\n"),
            ok.replace("refresh_token = \"rt\"", "refresh_token = \"missing\""),
            ok.replace("refresh_token = \"rt\"", "refresh_token = \"stamp/key\""),
            format!("{ok}\nscopes = [\"a b\"]"),
            format!("{ok}\nscopes = [\"\"]"),
        ] {
            assert!(config(&bad, "").validate(&kc).is_err(), "{bad}");
        }
        // The refresh token's entry is written on rotation: nothing else
        // may use it.
        let shared = format!(
            "{ok}\n[[preset]]\nname = \"other\"\ntype = \"http\"\ndescription = \"x\"\n\
             base_url = \"https://api.example.com\"\nallowed_methods = [\"GET\"]\n\
             approval = \"prompt\"\nauth = {{ type = \"bearer\", secret = \"rt\" }}"
        );
        let err = config(&shared, "").validate(&kc).unwrap_err().to_string();
        assert!(err.contains("also used elsewhere"), "{err}");
    }
}
