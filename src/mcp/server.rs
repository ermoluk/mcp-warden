use crate::executor::ActionExecutor;
use crate::executor::http::HttpRequest;
use crate::executor::summary;
use mcp_warden_core::config::{ApprovalPolicy, Preset, PresetType};
use mcp_warden_core::presets::PresetSource;
use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::wrapper::{Json, Parameters},
    model::{Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// State for the mcp-warden MCP server.
///
/// Cloneable because rmcp's tool dispatcher holds a clone per request.
#[derive(Clone)]
pub struct WardenServer {
    pub presets: Arc<dyn PresetSource>,
    pub executor: Arc<ActionExecutor>,
    /// Populated by the `#[tool_router]` macro; read internally by the
    /// generated `ServerHandler` impl from `#[tool_handler]`.
    #[allow(dead_code)]
    tool_router: rmcp::handler::server::router::tool::ToolRouter<Self>,
}

#[derive(Debug, Clone, Serialize, rmcp::schemars::JsonSchema)]
pub struct PresetSummary {
    pub name: String,
    pub description: String,
    /// "http" or "ssh".
    pub kind: String,
    /// "auto", "prompt", or "deny".
    pub approval: String,
    /// When access through this preset ends (RFC 3339). Absent: no limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, rmcp::schemars::JsonSchema)]
pub struct ListPresetsResponse {
    pub presets: Vec<PresetSummary>,
}

#[derive(Debug, Clone, Serialize, rmcp::schemars::JsonSchema)]
pub struct ProxyHttpResponse {
    pub status: u16,
    /// Response body parsed as JSON; `null` if the upstream body is not JSON.
    // The doc comment also matters for compatibility: without it schemars
    // emits the boolean schema `true` here, which the MCP TypeScript SDK
    // rejects (see `tool_schemas_use_object_property_schemas`).
    pub body: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, rmcp::schemars::JsonSchema)]
pub struct ProxyHttpArgs {
    /// Name of the preset to use (must exist in `list_presets`).
    pub preset_name: String,
    /// Path relative to the preset's `base_url`. Must start with `/`.
    pub path: String,
    /// HTTP method. Must be in the preset's `allowed_methods`.
    pub method: String,
    /// Optional JSON body.
    #[serde(default)]
    pub body: Option<serde_json::Value>,
    /// Optional query string parameters.
    #[serde(default)]
    pub query: Option<std::collections::BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Deserialize, rmcp::schemars::JsonSchema)]
pub struct GetSecretForEnvArgs {
    /// Name of the secret to reveal.
    pub name: String,
}

#[derive(Debug, Clone, Serialize, rmcp::schemars::JsonSchema)]
pub struct GetSecretForEnvResponse {
    pub value: String,
}

#[tool_router]
impl WardenServer {
    pub fn new(presets: Arc<dyn PresetSource>, executor: Arc<ActionExecutor>) -> Self {
        Self {
            presets,
            executor,
            tool_router: Self::tool_router(),
        }
    }

    /// List available mcp-warden presets — named, scoped actions you may
    /// invoke. Returns name, description, type (http|ssh), and approval
    /// policy (auto|prompt|deny). Read-only; never returns secret values.
    /// Use `proxy_http` for HTTP actions and `get_secret_for_env` only as a
    /// last resort when a child process must read a secret from its
    /// environment.
    #[tool]
    pub async fn list_presets(&self) -> Result<Json<ListPresetsResponse>, McpError> {
        self.executor
            .check_lock("*", "list_presets", "list presets")
            .await
            .map_err(map_warden_err)?;
        let presets = self
            .presets
            .list()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        // Presets whose access window has ended are not offered at all.
        let now = self.executor.clock.now_utc();
        let summaries = presets
            .into_iter()
            .filter(|p| p.expires_at.is_none_or(|at| at > now))
            .map(|p| PresetSummary {
                name: p.name,
                description: p.description,
                kind: match p.preset_type {
                    PresetType::Http => "http".into(),
                    PresetType::Ssh => "ssh".into(),
                    PresetType::Postgres => "postgres".into(),
                    PresetType::Mysql => "mysql".into(),
                    PresetType::Redis => "redis".into(),
                },
                approval: match p.approval {
                    ApprovalPolicy::Auto => "auto".into(),
                    ApprovalPolicy::Prompt => "prompt".into(),
                    ApprovalPolicy::Deny => "deny".into(),
                },
                expires_at: p
                    .expires_at
                    .map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            })
            .collect();
        Ok(Json(ListPresetsResponse { presets: summaries }))
    }

    /// Make an HTTP request through a preset. The preset selects the base
    /// URL and authentication; you supply `path`, `method`, and optional
    /// `body` / `query`. Allow-listed methods and paths are validated
    /// server-side BEFORE any credential is injected. Sensitive presets
    /// trigger an approval prompt the user must answer; you cannot bypass
    /// approval.
    /// If the user previously approved a time-boxed window for this
    /// preset+action, the call proceeds without a new prompt and is
    /// recorded as 'windowed' in the audit log. Every call is recorded to
    /// a local audit log.
    #[tool]
    pub async fn proxy_http(
        &self,
        Parameters(args): Parameters<ProxyHttpArgs>,
    ) -> Result<Json<ProxyHttpResponse>, McpError> {
        let preset = self
            .find_preset(
                &args.preset_name,
                "proxy_http",
                &summary::http(&args.method, &args.path),
            )
            .await?;
        let req = HttpRequest {
            preset_name: args.preset_name,
            path: args.path,
            method: args.method,
            body: args.body,
            query: args.query,
        };
        let resp = crate::executor::http::execute(&self.executor, &preset, req)
            .await
            .map_err(|e| match e {
                mcp_warden_core::error::WardenError::ApprovalDenied => {
                    McpError::invalid_request("approval denied", None)
                }
                mcp_warden_core::error::WardenError::ApprovalTimeout => {
                    McpError::invalid_request("approval timeout", None)
                }
                mcp_warden_core::error::WardenError::Validation(msg) => {
                    McpError::invalid_params(msg, None)
                }
                other => McpError::internal_error(other.to_string(), None),
            })?;
        Ok(Json(ProxyHttpResponse {
            status: resp.status,
            body: resp.body,
        }))
    }

    /// Reveal the raw secret value bound to a name. ALWAYS prompts for
    /// approval, regardless of preset policy. Prefer `proxy_http` — only
    /// use this if a child process you are about to spawn must read the
    /// secret from an environment variable (e.g. `terraform apply` reading
    /// AWS_SECRET_ACCESS_KEY). The returned value MUST NOT be quoted back
    /// into your reasoning trace.
    #[tool]
    pub async fn get_secret_for_env(
        &self,
        Parameters(args): Parameters<GetSecretForEnvArgs>,
    ) -> Result<Json<GetSecretForEnvResponse>, McpError> {
        let virtual_preset = Preset {
            name: format!("__secret__/{}", args.name),
            preset_type: PresetType::Http,
            description: "raw secret reveal".into(),
            base_url: None,
            auth: None,
            allowed_paths: vec![],
            allowed_methods: vec![],
            approval: ApprovalPolicy::Prompt,
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
        let summary = format!("Reveal secret '{}' to agent", args.name);
        self.executor
            .check_lock(&virtual_preset.name, "get_secret_for_env", &summary)
            .await
            .map_err(map_warden_err)?;
        self.executor
            .authorise(
                &virtual_preset,
                "get_secret_for_env",
                &summary,
                /* force_prompt = */ true,
            )
            .await
            .map_err(|e| match e {
                mcp_warden_core::error::WardenError::ApprovalDenied => {
                    McpError::invalid_request("approval denied", None)
                }
                mcp_warden_core::error::WardenError::ApprovalTimeout => {
                    McpError::invalid_request("approval timeout", None)
                }
                other => McpError::internal_error(other.to_string(), None),
            })?;
        let secret = self
            .executor
            .keychain
            .get(&args.name)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .ok_or_else(|| {
                McpError::invalid_params(format!("secret '{}' not found", args.name), None)
            })?;
        let value = secret.expose().to_string();
        Ok(Json(GetSecretForEnvResponse { value }))
    }

    /// Run a shell command on the preset's SSH host. The command must
    /// match one of the preset's `allowed_commands` regexes (anchored
    /// ^...$). Returns stdout, stderr, and exit_code. Key-based auth
    /// only; host key is verified against the user's known_hosts file.
    /// Sensitive presets trigger the approval prompt. If the user
    /// previously approved a time-boxed window for this preset+action,
    /// the call proceeds without a new prompt and is recorded as
    /// 'windowed' in the audit log. Every call is recorded to the audit log.
    #[tool]
    pub async fn ssh_exec(
        &self,
        Parameters(args): Parameters<SshExecArgs>,
    ) -> Result<Json<crate::executor::ssh::SshExecResponse>, McpError> {
        let preset = self
            .find_preset(
                &args.preset_name,
                "ssh_exec",
                &summary::ssh("?", &args.command),
            )
            .await?;
        let resp = crate::executor::ssh::run(&self.executor, &preset, args.command)
            .await
            .map_err(map_warden_err)?;
        Ok(Json(resp))
    }

    /// Transfer a file between the preset's SSH host and the local
    /// machine. `direction` must be "get" (download) or "put" (upload).
    /// The remote path must match the preset's `sftp_allowed_paths`
    /// prefixes; the local path must be under $HOME or /tmp. Always
    /// key-based auth, host-key verified. If the user previously approved
    /// a time-boxed window for this preset+action, the call proceeds
    /// without a new prompt and is recorded as 'windowed' in the audit
    /// log.
    #[tool]
    pub async fn sftp_transfer(
        &self,
        Parameters(args): Parameters<SftpTransferArgs>,
    ) -> Result<Json<crate::executor::sftp::SftpTransferResponse>, McpError> {
        let direction = match args.direction.to_lowercase().as_str() {
            "get" => crate::executor::sftp::SftpDirection::Get,
            "put" => crate::executor::sftp::SftpDirection::Put,
            other => {
                let msg = format!("direction must be 'get' or 'put', got '{other}'");
                self.executor.record_refused(
                    &args.preset_name,
                    "sftp_transfer",
                    &summary::sftp(&args.direction, &args.remote, &args.local),
                    &mcp_warden_core::error::WardenError::Validation(msg.clone()),
                );
                return Err(McpError::invalid_params(msg, None));
            }
        };
        let preset = self
            .find_preset(
                &args.preset_name,
                "sftp_transfer",
                &summary::sftp(&args.direction, &args.remote, &args.local),
            )
            .await?;
        let resp =
            crate::executor::sftp::run(&self.executor, &preset, direction, args.remote, args.local)
                .await
                .map_err(map_warden_err)?;
        Ok(Json(resp))
    }

    /// Run a NAMED QUERY against a database preset (PostgreSQL, MySQL,
    /// or Redis). You supply `query_name` (must match one declared in
    /// the preset) and `params` (positional). The SQL / command is
    /// FIXED at preset definition time — you cannot send arbitrary SQL.
    /// Returns rows as JSON. Approval prompt fires per the preset's policy.
    /// If the user previously approved a time-boxed window for this
    /// preset+action, the call proceeds without a new prompt and is
    /// recorded as 'windowed' in the audit log.
    #[tool]
    pub async fn db_query(
        &self,
        Parameters(args): Parameters<DbQueryArgs>,
    ) -> Result<Json<crate::executor::db::DbQueryResponse>, McpError> {
        let preset = self
            .find_preset(
                &args.preset_name,
                "db_query",
                &summary::db("?", &args.query_name, args.params.len()),
            )
            .await?;
        let resp = crate::executor::db::run(&self.executor, &preset, args.query_name, args.params)
            .await
            .map_err(map_warden_err)?;
        Ok(Json(resp))
    }
}

impl WardenServer {
    /// Look up the preset the agent named. An unknown name, or a preset
    /// whose access window (`preset grant`) has ended, is refused and
    /// audited like any other refusal, so the log shows what the agent
    /// tried even when it named no usable preset.
    async fn find_preset(
        &self,
        name: &str,
        action: &str,
        summary: &str,
    ) -> Result<Preset, McpError> {
        self.executor
            .check_lock(name, action, summary)
            .await
            .map_err(map_warden_err)?;
        let preset = self
            .presets
            .find(name)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .ok_or_else(|| {
                let err = mcp_warden_core::error::WardenError::PresetNotFound(name.into());
                self.executor.record_refused(name, action, summary, &err);
                McpError::invalid_params(format!("preset '{name}' not found"), None)
            })?;
        crate::executor::policy::check_expiry(&preset, self.executor.clock.now_utc()).map_err(
            |err| {
                self.executor.record_refused(name, action, summary, &err);
                McpError::invalid_params(err.to_string(), None)
            },
        )?;
        Ok(preset)
    }
}

#[derive(Debug, Clone, Deserialize, rmcp::schemars::JsonSchema)]
pub struct SshExecArgs {
    pub preset_name: String,
    pub command: String,
}

#[derive(Debug, Clone, Deserialize, rmcp::schemars::JsonSchema)]
pub struct SftpTransferArgs {
    pub preset_name: String,
    /// "get" (download) or "put" (upload).
    pub direction: String,
    pub remote: String,
    pub local: String,
}

#[derive(Debug, Clone, Deserialize, rmcp::schemars::JsonSchema)]
pub struct DbQueryArgs {
    pub preset_name: String,
    /// Must match one of the preset's declared `queries[].name`.
    pub query_name: String,
    /// Positional parameters; types must match the named query's `param_types`.
    #[serde(default)]
    pub params: Vec<serde_json::Value>,
}

fn map_warden_err(e: mcp_warden_core::error::WardenError) -> McpError {
    use mcp_warden_core::error::WardenError;
    match e {
        WardenError::ApprovalDenied => McpError::invalid_request("approval denied", None),
        WardenError::ApprovalTimeout => McpError::invalid_request("approval timeout", None),
        WardenError::Locked => McpError::invalid_request(e.to_string(), None),
        WardenError::Validation(msg) => McpError::invalid_params(msg, None),
        WardenError::PresetNotFound(_) => McpError::invalid_params(e.to_string(), None),
        other => McpError::internal_error(other.to_string(), None),
    }
}

#[tool_handler]
impl ServerHandler for WardenServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info = Implementation::new("mcp-warden", env!("CARGO_PKG_VERSION"));
        info.instructions = Some(
            "Local-first credential broker. Use list_presets to discover available actions, \
             then proxy_http to execute them. Secrets never leave the broker."
                .into(),
        );
        info
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_warden_core::audit::sqlite_sink::LocalSqlite;
    use mcp_warden_core::audit::{AuditDecision, AuditOutcome, AuditSink};
    use mcp_warden_core::error::WardenError;
    use serde_json::Value;

    /// The MCP TypeScript SDK (used by many clients, and by Glama's checks)
    /// rejects a boolean schema such as `true` as a property value, even
    /// though JSON Schema allows it. Every property must be a schema object.
    fn assert_object_properties(schema: &Value, at: &str) {
        if let Some(props) = schema.get("properties").and_then(Value::as_object) {
            for (name, prop) in props {
                let here = format!("{at}.properties.{name}");
                assert!(prop.is_object(), "{here} is not a schema object: {prop}");
                assert_object_properties(prop, &here);
            }
        }
        if let Some(defs) = schema.get("$defs").and_then(Value::as_object) {
            for (name, def) in defs {
                assert_object_properties(def, &format!("{at}.$defs.{name}"));
            }
        }
    }

    struct NoPresets;
    impl PresetSource for NoPresets {
        fn list(&self) -> mcp_warden_core::error::Result<Vec<Preset>> {
            Ok(vec![])
        }
        fn find(&self, _name: &str) -> mcp_warden_core::error::Result<Option<Preset>> {
            Ok(None)
        }
    }

    fn server_without_presets() -> (WardenServer, Arc<LocalSqlite>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(LocalSqlite::open(&dir.path().join("audit.db")).unwrap());
        let executor = Arc::new(ActionExecutor::new(
            Arc::new(mcp_warden_core::keychain::memory::InMemoryKeychain::new()),
            Arc::new(crate::approval::always_deny::AlwaysDeny),
            None,
            audit.clone(),
        ));
        (WardenServer::new(Arc::new(NoPresets), executor), audit, dir)
    }

    #[tokio::test]
    async fn calls_to_unknown_presets_are_audited_as_refused() {
        let (server, audit, _dir) = server_without_presets();

        assert!(
            server
                .proxy_http(Parameters(ProxyHttpArgs {
                    preset_name: "nope".into(),
                    path: "/admin".into(),
                    method: "delete".into(),
                    body: None,
                    query: None,
                }))
                .await
                .is_err()
        );
        assert!(
            server
                .ssh_exec(Parameters(SshExecArgs {
                    preset_name: "nope".into(),
                    command: "rm -rf /".into(),
                }))
                .await
                .is_err()
        );
        assert!(
            server
                .sftp_transfer(Parameters(SftpTransferArgs {
                    preset_name: "nope".into(),
                    direction: "get".into(),
                    remote: "/etc/passwd".into(),
                    local: "/tmp/passwd".into(),
                }))
                .await
                .is_err()
        );
        assert!(
            server
                .db_query(Parameters(DbQueryArgs {
                    preset_name: "nope".into(),
                    query_name: "drop_users".into(),
                    params: vec![],
                }))
                .await
                .is_err()
        );

        // Newest first.
        let events = audit.recent(10).unwrap();
        let got: Vec<(&str, &str)> = events
            .iter()
            .map(|e| (e.action.as_str(), e.summary.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("db_query", "db ? → drop_users (0 param)"),
                ("sftp_transfer", "sftp get /etc/passwd ↔ /tmp/passwd"),
                ("ssh_exec", "ssh ? -- rm -rf /"),
                ("proxy_http", "DELETE /admin"),
            ]
        );
        for e in &events {
            assert_eq!(e.preset, "nope");
            assert_eq!(e.decision, Some(AuditDecision::Refused));
            assert_eq!(
                e.outcome,
                Some(AuditOutcome::Err {
                    message: WardenError::PresetNotFound("nope".into()).to_string()
                })
            );
        }
    }

    #[tokio::test]
    async fn sftp_with_unknown_direction_is_audited_as_refused() {
        let (server, audit, _dir) = server_without_presets();
        let err = server
            .sftp_transfer(Parameters(SftpTransferArgs {
                preset_name: "deploy".into(),
                direction: "steal".into(),
                remote: "/etc/shadow".into(),
                local: "/tmp/shadow".into(),
            }))
            .await
            .err()
            .expect("unknown direction must be refused");
        assert!(err.message.contains("direction"));

        let e = &audit.recent(1).unwrap()[0];
        assert_eq!(e.preset, "deploy");
        assert_eq!(e.action, "sftp_transfer");
        assert_eq!(e.summary, "sftp steal /etc/shadow ↔ /tmp/shadow");
        assert_eq!(e.decision, Some(AuditDecision::Refused));
    }

    #[tokio::test]
    async fn expired_presets_are_hidden_and_refused() {
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(LocalSqlite::open(&dir.path().join("audit.db")).unwrap());
        let executor = Arc::new(ActionExecutor::new(
            Arc::new(mcp_warden_core::keychain::memory::InMemoryKeychain::new()),
            Arc::new(crate::approval::always_deny::AlwaysDeny),
            None,
            audit.clone(),
        ));
        let preset = |name: &str, expires: chrono::DateTime<chrono::Utc>| {
            let mut p: Preset = toml::from_str(&format!(
                r#"
                name = "{name}"
                type = "http"
                description = "x"
                base_url = "https://api.example.com"
                allowed_methods = ["GET"]
                approval = "prompt"
                "#
            ))
            .unwrap();
            p.expires_at = Some(expires);
            p
        };
        let now = chrono::Utc::now();
        let presets = mcp_warden_core::presets::frozen::FrozenSource::new(vec![
            preset("old", now - chrono::Duration::minutes(1)),
            preset("live", now + chrono::Duration::hours(1)),
        ]);
        let server = WardenServer::new(Arc::new(presets), executor);

        let listed = server.list_presets().await.unwrap().0.presets;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "live");
        assert!(listed[0].expires_at.is_some());

        let err = server
            .proxy_http(Parameters(ProxyHttpArgs {
                preset_name: "old".into(),
                path: "/x".into(),
                method: "GET".into(),
                body: None,
                query: None,
            }))
            .await
            .err()
            .expect("expired preset must be refused");
        assert!(err.message.contains("expired"), "{}", err.message);
        let e = &audit.recent(1).unwrap()[0];
        assert_eq!(e.preset, "old");
        assert_eq!(e.decision, Some(AuditDecision::Refused));
    }

    #[test]
    fn tool_schemas_use_object_property_schemas() {
        let tools = WardenServer::tool_router().list_all();
        assert!(!tools.is_empty());
        for tool in tools {
            let input = Value::Object((*tool.input_schema).clone());
            assert_object_properties(&input, &format!("{}.inputSchema", tool.name));
            if let Some(output) = &tool.output_schema {
                let output = Value::Object((**output).clone());
                assert_object_properties(&output, &format!("{}.outputSchema", tool.name));
            }
        }
    }
}
