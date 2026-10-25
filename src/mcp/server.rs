use crate::executor::ActionExecutor;
use crate::executor::http::HttpRequest;
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
        let presets = self
            .presets
            .list()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let summaries = presets
            .into_iter()
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
            })
            .collect();
        Ok(Json(ListPresetsResponse { presets: summaries }))
    }

    /// Make an HTTP request through a preset. The preset selects the base
    /// URL and authentication; you supply `path`, `method`, and optional
    /// `body` / `query`. Allow-listed methods and paths are validated
    /// server-side BEFORE any credential is injected. Sensitive presets
    /// trigger a desktop / TUI approval prompt; you cannot bypass approval.
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
            .presets
            .find(&args.preset_name)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .ok_or_else(|| {
                McpError::invalid_params(format!("preset '{}' not found", args.preset_name), None)
            })?;
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
        };
        let summary = format!("Reveal secret '{}' to agent", args.name);
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
            .presets
            .find(&args.preset_name)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .ok_or_else(|| {
                McpError::invalid_params(format!("preset '{}' not found", args.preset_name), None)
            })?;
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
                return Err(McpError::invalid_params(
                    format!("direction must be 'get' or 'put', got '{other}'"),
                    None,
                ));
            }
        };
        let preset = self
            .presets
            .find(&args.preset_name)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .ok_or_else(|| {
                McpError::invalid_params(format!("preset '{}' not found", args.preset_name), None)
            })?;
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
            .presets
            .find(&args.preset_name)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .ok_or_else(|| {
                McpError::invalid_params(format!("preset '{}' not found", args.preset_name), None)
            })?;
        let resp = crate::executor::db::run(&self.executor, &preset, args.query_name, args.params)
            .await
            .map_err(map_warden_err)?;
        Ok(Json(resp))
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
