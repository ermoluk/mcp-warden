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
    /// Set when mcp-warden withheld the rows (over the size limit).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notice: Option<String>,
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
        params: &params,
    };
    let nq = super::policy::check_request(preset, &request)
        .and_then(|()| find_query(preset, &query_name, params.len()))
        .inspect_err(|e| actx.record_refused(&preset.name, "db_query", &summary, e))?;
    let event_id = actx.authorise(preset, "db_query", &summary, false).await?;

    // Connecting, authenticating and the query, all under one timeout: a
    // database that stops answering cannot hold the call open.
    let timeout = std::time::Duration::from_secs(
        preset
            .timeout_seconds
            .unwrap_or(super::limits::DEFAULT_DB_TIMEOUT_SECS),
    );
    let query = async {
        match preset.preset_type {
            mcp_warden_core::config::PresetType::Postgres => {
                postgres::run(actx, preset, &nq, &params).await
            }
            mcp_warden_core::config::PresetType::Mysql => {
                mysql::run(actx, preset, &nq, &params).await
            }
            mcp_warden_core::config::PresetType::Redis => {
                redis::run(actx, preset, &nq, &params).await
            }
            _ => Err(WardenError::Validation("not a db preset".into())),
        }
    };
    let result = tokio::time::timeout(timeout, query)
        .await
        .unwrap_or_else(|_| Err(WardenError::Executor("db timeout".into())))
        .map(withhold_oversized);

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

/// Rows too large for the agent's context are not returned — the same
/// ceiling as a `proxy_http` body — and the response says why.
fn withhold_oversized(mut resp: DbQueryResponse) -> DbQueryResponse {
    let max = super::limits::MAX_RESPONSE_BYTES;
    let rows = Value::Array(std::mem::take(&mut resp.rows));
    if super::limits::json_longer_than(&rows, max) {
        resp.notice = Some(format!(
            "the result is larger than mcp-warden's limit of {max} bytes and was not returned"
        ));
    } else if let Value::Array(rows) = rows {
        resp.rows = rows;
    }
    resp
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

    /// A result too large for the agent's context is withheld, as for
    /// `proxy_http`: the call says so instead of returning it.
    #[tokio::test]
    async fn an_oversized_result_is_withheld() {
        let huge = crate::executor::limits::MAX_RESPONSE_BYTES + 1;
        let redis = crate::testutil::FakeRedis::start(move |args| {
            match args[0].to_ascii_uppercase().as_str() {
                "GET" => format!("${huge}\r\n{}\r\n", "a".repeat(huge)).into_bytes(),
                _ => b"+OK\r\n".to_vec(),
            }
        })
        .await;
        let (exec, _dir) = test_executor();
        let mut preset = pg_preset_with_query("GET", "GET", vec!["text".into()]);
        preset.preset_type = PresetType::Redis;
        preset.host = Some("127.0.0.1".into());
        preset.port = Some(redis.port);
        let resp = run(&exec, &preset, "GET".into(), vec![Value::from("k")])
            .await
            .unwrap();
        assert!(resp.rows.is_empty(), "{} rows returned", resp.rows.len());
        assert!(resp.notice.unwrap().contains("limit"));
    }

    /// A database that accepts the connection and never answers: the call
    /// ends after the preset's timeout, for every driver.
    #[tokio::test]
    async fn a_database_that_never_answers_times_out() {
        use mcp_warden_core::config::PresetType;
        let silent = crate::testutil::SilentListener::start();
        for kind in [PresetType::Postgres, PresetType::Mysql, PresetType::Redis] {
            let (exec, _dir) = test_executor();
            let mut preset = pg_preset_with_query("ping", "select 1", vec![]);
            preset.preset_type = kind;
            preset.approval = ApprovalPolicy::Auto;
            preset.host = Some("127.0.0.1".into());
            preset.port = Some(silent.port);
            preset.timeout_seconds = Some(1);
            let call = run(&exec, &preset, "ping".into(), vec![]);
            let res = tokio::time::timeout(std::time::Duration::from_secs(10), call)
                .await
                .unwrap_or_else(|_| panic!("{kind:?}: db_query hung past its own timeout"));
            let err = res.expect_err("must fail").to_string();
            assert!(err.contains("timeout"), "{kind:?}: {err}");
        }
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
