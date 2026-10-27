use crate::error::{Result, WardenError};
use crate::keychain::KeychainStore;
use serde::{Deserialize, Serialize};
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
    #[serde(default)]
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

/// An MCP server `mcp-warden run <name>` launches. The command is fixed here
/// so nobody — the agent included — can have a secret injected into a
/// command of their choosing.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WrappedServer {
    pub name: String,
    pub command: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Environment variable → name of the keychain entry that holds its value.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub env: std::collections::BTreeMap<String, String>,
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
        for p in &self.preset {
            if p.name.is_empty() {
                return Err(WardenError::Validation("preset name empty".into()));
            }
            match p.preset_type {
                PresetType::Http => self.validate_http(p, kc)?,
                PresetType::Ssh => self.validate_ssh(p, kc)?,
                PresetType::Postgres | PresetType::Mysql | PresetType::Redis => {
                    self.validate_db(p, kc)?
                }
            }
        }
        if let Some(approval) = &self.approval
            && let Some(tg) = &approval.telegram
        {
            if tg.bot_token_secret.is_empty() {
                return Err(WardenError::Validation(
                    "approval.telegram.bot_token_secret is empty".into(),
                ));
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
            "http" => tracing::warn!("preset '{}' uses plain http", p.name),
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
        let secret_name = match &p.auth {
            Some(Auth::Bearer { secret })
            | Some(Auth::Header { secret, .. })
            | Some(Auth::Basic { secret, .. }) => secret.clone(),
            None => {
                return Err(WardenError::Validation(format!(
                    "preset '{}': auth required",
                    p.name
                )));
            }
        };
        if kc.get(&secret_name)?.is_none() {
            return Err(WardenError::MissingSecret {
                preset: p.name.clone(),
                secret: secret_name,
            });
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
        if p.allow_sftp {
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

    pub fn find(&self, name: &str) -> Option<&Preset> {
        self.preset.iter().find(|p| p.name == name)
    }

    /// Check the shape of every `[[server]]` entry. Their secrets are not
    /// looked up here: they belong to `mcp-warden run`, which checks them
    /// when it launches the server.
    pub fn validate_servers(&self) -> Result<()> {
        let mut seen = std::collections::HashSet::new();
        for s in &self.server {
            if s.name.is_empty() || s.command.is_empty() {
                return Err(WardenError::Validation(
                    "every [[server]] needs a name and a command".into(),
                ));
            }
            if !seen.insert(s.name.as_str()) {
                return Err(WardenError::Validation(format!(
                    "two [[server]] entries are named '{}'",
                    s.name
                )));
            }
            for (var, secret) in &s.env {
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
                if secret.is_empty() {
                    return Err(WardenError::Validation(format!(
                        "server '{}': {var} names no keychain entry",
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
    fn server_entries_parse_and_validate() {
        let cfg: Config = toml::from_str(
            r#"
            [[server]]
            name = "github"
            command = "npx"
            args = ["-y", "@modelcontextprotocol/server-github"]
            env = { GITHUB_PERSONAL_ACCESS_TOKEN = "github_pat" }
            "#,
        )
        .unwrap();
        cfg.validate_servers().unwrap();
        let s = cfg.find_server("github").unwrap();
        assert_eq!(s.args.len(), 2);
        assert_eq!(s.env["GITHUB_PERSONAL_ACCESS_TOKEN"], "github_pat");
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
            let t =
                format!("[[server]]\nname = \"a\"\ncommand = \"x\"\nenv = {{ \"{var}\" = \"s\" }}");
            assert!(servers(&t).is_err(), "{var:?}");
        }
        assert!(servers("[[server]]\nname = \"a\"\ncommand = \"x\"\nenv = { A = \"\" }").is_err());
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
}
