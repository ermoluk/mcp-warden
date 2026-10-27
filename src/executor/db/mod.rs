use crate::executor::ActionExecutor;
use mcp_warden_core::audit::AuditOutcome;
use mcp_warden_core::config::{NamedQuery, Preset};
use mcp_warden_core::error::{Result, WardenError};
use serde::Serialize;
use serde_json::Value;

/// True when the connection cannot leave this machine: a Unix-socket
/// directory, `localhost`, or a loopback IP.
pub(crate) fn is_local_host(host: &str) -> bool {
    host.starts_with('/')
        || host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

pub mod mysql;
pub mod postgres;
pub mod redis;

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
pub struct DbQueryResponse {
    pub rows: Vec<Value>,
    pub rows_affected: u64,
}

/// Look up the named query, validate parameters, then dispatch to the correct
/// per-database executor. Authorisation + audit happen here.
pub async fn run(
    actx: &ActionExecutor,
    preset: &Preset,
    query_name: String,
    params: Vec<Value>,
) -> Result<DbQueryResponse> {
    let summary = super::summary::db(
        preset_type_label(&preset.preset_type),
        &query_name,
        params.len(),
    );
    let request = super::policy::Request::Db {
        query: &query_name,
        params: params.len(),
    };
    let nq = super::policy::check_request(preset, &request)
        .and_then(|()| find_query(preset, &query_name, params.len()))
        .inspect_err(|e| actx.record_refused(&preset.name, "db_query", &summary, e))?;
    let event_id = actx.authorise(preset, "db_query", &summary, false).await?;

    let result = match preset.preset_type {
        mcp_warden_core::config::PresetType::Postgres => {
            postgres::run(actx, preset, &nq, &params).await
        }
        mcp_warden_core::config::PresetType::Mysql => mysql::run(actx, preset, &nq, &params).await,
        mcp_warden_core::config::PresetType::Redis => redis::run(actx, preset, &nq, &params).await,
        _ => Err(WardenError::Validation("not a db preset".into())),
    };

    match &result {
        Ok(_) => {
            let _ = actx
                .audit
                .record_outcome(event_id, AuditOutcome::Ok { status: 200 });
        }
        Err(e) => {
            let _ = actx.audit.record_outcome(
                event_id,
                AuditOutcome::Err {
                    message: e.to_string(),
                },
            );
        }
    };
    result
}

/// The named query the agent asked for, if the preset declares it and the
/// parameter count matches.
pub(crate) fn find_query(preset: &Preset, query_name: &str, params: usize) -> Result<NamedQuery> {
    let nq = preset
        .queries
        .iter()
        .find(|q| q.name == query_name)
        .cloned()
        .ok_or_else(|| {
            WardenError::Validation(format!(
                "preset '{}': named query '{query_name}' not in allow-list",
                preset.name
            ))
        })?;
    if params != nq.param_types.len() {
        return Err(WardenError::Validation(format!(
            "named query '{}' expects {} params, got {}",
            nq.name,
            nq.param_types.len(),
            params
        )));
    }
    Ok(nq)
}

fn preset_type_label(t: &mcp_warden_core::config::PresetType) -> &'static str {
    match t {
        mcp_warden_core::config::PresetType::Postgres => "postgres",
        mcp_warden_core::config::PresetType::Mysql => "mysql",
        mcp_warden_core::config::PresetType::Redis => "redis",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_loopback_and_unix_sockets_count_as_local() {
        for local in [
            "localhost",
            "LOCALHOST",
            "127.0.0.1",
            "127.5.5.5",
            "::1",
            "/var/run/postgresql",
        ] {
            assert!(is_local_host(local), "{local} should be local");
        }
        for remote in [
            "db.example.com",
            "10.0.0.5",
            "192.168.1.10",
            "localhost.evil.com",
            "",
        ] {
            assert!(!is_local_host(remote), "{remote} should be remote");
        }
    }
    use crate::executor::ActionExecutor;
    use async_trait::async_trait;
    use mcp_warden_core::approval::ApprovalDecision;
    use mcp_warden_core::approval::ApprovalRequest;
    use mcp_warden_core::approval::ApprovalTransport;
    use mcp_warden_core::audit::sqlite_sink::LocalSqlite;
    use mcp_warden_core::config::{ApprovalPolicy, NamedQuery, Preset, PresetType};
    use mcp_warden_core::keychain::KeychainStore;
    use mcp_warden_core::keychain::memory::InMemoryKeychain;
    use mcp_warden_core::secret::Secret;
    use std::sync::Arc;

    struct AlwaysApprove;
    #[async_trait]
    impl ApprovalTransport for AlwaysApprove {
        async fn request(&self, _r: ApprovalRequest) -> Result<ApprovalDecision> {
            Ok(ApprovalDecision::Approved)
        }
    }

    fn pg_preset_with_query(name: &str, template: &str, types: Vec<String>) -> Preset {
        Preset {
            name: "pg".into(),
            preset_type: PresetType::Postgres,
            description: "x".into(),
            host: Some("h".into()),
            user: Some("u".into()),
            port: Some(5432),
            secret: Some("k".into()),
            allowed_commands: vec![],
            allow_sftp: false,
            sftp_allowed_paths: vec![],
            approval: ApprovalPolicy::Auto,
            approval_window_seconds: None,
            base_url: None,
            auth: None,
            allowed_paths: vec![],
            allowed_methods: vec![],
            timeout_seconds: None,
            known_hosts: None,
            database: Some("app".into()),
            queries: vec![NamedQuery {
                name: name.into(),
                template: template.into(),
                param_types: types,
                readonly: true,
            }],
            expires_at: None,
            max_response_bytes: None,
            response_fields: vec![],
        }
    }

    fn test_executor() -> (ActionExecutor, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let kc = Arc::new(InMemoryKeychain::new());
        kc.set("k", Secret::new("hunter2".into())).unwrap();
        let exec = ActionExecutor::new(
            kc,
            Arc::new(AlwaysApprove),
            None,
            Arc::new(LocalSqlite::open(&dir.path().join("audit.db")).unwrap()),
        );
        (exec, dir)
    }

    #[tokio::test]
    async fn rejects_named_query_not_in_allow_list() {
        let preset = pg_preset_with_query("find_user", "SELECT 1", vec![]);
        let (exec, _dir) = test_executor();
        let err = run(&exec, &preset, "drop_users".into(), vec![])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not in allow-list"));
    }

    #[tokio::test]
    async fn rejects_param_count_mismatch() {
        let preset = pg_preset_with_query("find_user", "SELECT $1", vec!["int8".into()]);
        let (exec, _dir) = test_executor();
        let err = run(&exec, &preset, "find_user".into(), vec![])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("expects 1 params, got 0"));
    }
}
