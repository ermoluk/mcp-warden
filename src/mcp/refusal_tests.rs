//! Invariant 3, checked mechanically: a call refused by validation reads no
//! credential, shows no prompt, sends nothing upstream and is audited as
//! `refused`. Every hostile input in `tests/corpus/` goes through the MCP
//! tools themselves, with a keychain and an approval transport that count
//! how often they are used, a wiremock server that expects no request and a
//! TCP listener that counts connections for the SSH and database presets.

use super::server::*;
use crate::executor::ActionExecutor;
use crate::testutil::{CountingApproval, CountingKeychain, CountingListener, corpus};
use mcp_warden_core::approval::ApprovalDecision;
use mcp_warden_core::audit::sqlite_sink::LocalSqlite;
use mcp_warden_core::audit::{AuditDecision, AuditSink};
use mcp_warden_core::config::Preset;
use mcp_warden_core::presets::frozen::FrozenSource;
use rmcp::handler::server::wrapper::Parameters;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;

pub(crate) struct Harness {
    pub server: WardenServer,
    pub keychain: Arc<CountingKeychain>,
    pub approval: Arc<CountingApproval>,
    pub audit: Arc<LocalSqlite>,
    pub http: wiremock::MockServer,
    pub tcp: CountingListener,
    pub _dir: tempfile::TempDir,
}

pub(crate) const SECRETS: &[(&str, &str)] = &[
    ("web_tok", "tok-WEB-0123456789abcdef"),
    ("box_key", "not-a-real-key-BOX-0123456789"),
    ("pg_pw", "pw-PG-0123456789abcdef"),
];

impl Harness {
    /// Presets that allow every path and every command, so only the checks
    /// that hold whatever the allow-list says can refuse.
    pub async fn wide_open() -> Self {
        let http = wiremock::MockServer::start().await;
        let tcp = CountingListener::start();
        let presets: Vec<Preset> = toml::from_str::<mcp_warden_core::config::Config>(&format!(
            r#"
            [[preset]]
            name = "web"
            type = "http"
            description = "web"
            base_url = "{http}"
            auth = {{ type = "bearer", secret = "web_tok" }}
            allowed_methods = ["GET", "POST"]
            allowed_paths = [".*"]
            approval = "prompt"

            [[preset]]
            name = "box"
            type = "ssh"
            description = "box"
            host = "127.0.0.1"
            port = {port}
            user = "u"
            secret = "box_key"
            allowed_commands = [".*"]
            allow_sftp = true
            sftp_allowed_paths = ["/srv/app/"]
            approval = "prompt"

            [[preset]]
            name = "pg"
            type = "postgres"
            description = "pg"
            host = "127.0.0.1"
            port = {port}
            user = "u"
            secret = "pg_pw"
            database = "db"
            approval = "prompt"

            [[preset.queries]]
            name = "user_by_id"
            template = "select * from users where id = $1"
            param_types = ["int8"]
            "#,
            http = http.uri(),
            port = tcp.port,
        ))
        .unwrap()
        .preset;
        Self::with_presets(presets, http, tcp)
    }

    pub fn with_presets(
        presets: Vec<Preset>,
        http: wiremock::MockServer,
        tcp: CountingListener,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let keychain = CountingKeychain::with(SECRETS);
        let approval = CountingApproval::new(ApprovalDecision::Approved);
        let audit = Arc::new(LocalSqlite::open(&dir.path().join("audit.db")).unwrap());
        let executor = Arc::new(ActionExecutor::new(
            keychain.clone(),
            approval.clone(),
            None,
            audit.clone(),
        ));
        let server = WardenServer::new(Arc::new(FrozenSource::new(presets)), executor);
        Self {
            server,
            keychain,
            approval,
            audit,
            http,
            tcp,
            _dir: dir,
        }
    }

    pub async fn http(&self, method: &str, path: &str, query: Option<Value>, body: Option<Value>) {
        let query: Option<BTreeMap<String, String>> =
            query.map(|q| serde_json::from_value(q).unwrap());
        let res = self
            .server
            .proxy_http(Parameters(ProxyHttpArgs {
                preset_name: "web".into(),
                path: path.into(),
                method: method.into(),
                body,
                query,
            }))
            .await;
        assert!(res.is_err(), "proxy_http {method} {path:?} was allowed");
    }

    pub async fn ssh(&self, command: &str) {
        let res = self
            .server
            .ssh_exec(Parameters(SshExecArgs {
                preset_name: "box".into(),
                command: command.into(),
            }))
            .await;
        assert!(res.is_err(), "ssh_exec {command:?} was allowed");
    }

    pub async fn sftp(&self, direction: &str, remote: &str, local: &str) {
        let res = self
            .server
            .sftp_transfer(Parameters(SftpTransferArgs {
                preset_name: "box".into(),
                direction: direction.into(),
                remote: remote.into(),
                local: local.into(),
            }))
            .await;
        assert!(
            res.is_err(),
            "sftp {direction} {remote:?} {local:?} was allowed"
        );
    }

    pub async fn reveal(&self, name: &str) {
        let res = self
            .server
            .get_secret_for_env(Parameters(GetSecretForEnvArgs { name: name.into() }))
            .await;
        assert!(res.is_err(), "get_secret_for_env {name:?} was allowed");
    }

    pub async fn db(&self, query_name: &str, params: Vec<Value>) {
        let res = self
            .server
            .db_query(Parameters(DbQueryArgs {
                preset_name: "pg".into(),
                query_name: query_name.into(),
                params,
            }))
            .await;
        assert!(res.is_err(), "db_query {query_name:?} was allowed");
    }

    /// Nothing was read, shown or sent, and each of the `n` calls left one
    /// `refused` event.
    pub async fn assert_all_refused_untouched(&self, n: usize) {
        assert_eq!(self.keychain.gets(), 0, "keychain reads");
        assert_eq!(self.approval.calls(), 0, "approval prompts");
        let requests = self.http.received_requests().await.unwrap_or_default();
        assert!(requests.is_empty(), "upstream HTTP requests: {requests:?}");
        assert_eq!(self.tcp.accepted(), 0, "upstream TCP connections");
        let events = self.audit.recent(n + 10).unwrap();
        assert_eq!(events.len(), n, "one audit event per call");
        for e in &events {
            assert_eq!(e.decision, Some(AuditDecision::Refused), "{e:?}");
        }
    }
}

#[tokio::test]
async fn corpus_paths_are_refused_before_anything_is_touched() {
    let h = Harness::wide_open().await;
    let entries = corpus(include_str!("../../tests/corpus/paths.txt"));
    for (_, path, _) in &entries {
        h.http("GET", path, None, None).await;
    }
    h.assert_all_refused_untouched(entries.len()).await;
}

#[tokio::test]
async fn corpus_query_keys_are_refused_before_anything_is_touched() {
    let h = Harness::wide_open().await;
    let entries = corpus(include_str!("../../tests/corpus/queries.txt"));
    for (_, key, _) in &entries {
        h.http("POST", "/x", Some(json!({ key: "DELETE" })), None)
            .await;
    }
    h.http("POST", "/x", None, Some(json!({ "_method": "DELETE" })))
        .await;
    h.assert_all_refused_untouched(entries.len() + 1).await;
}

#[tokio::test]
async fn corpus_commands_are_refused_before_anything_is_touched() {
    let h = Harness::wide_open().await;
    let entries = corpus(include_str!("../../tests/corpus/commands.txt"));
    for (_, command, _) in &entries {
        h.ssh(command).await;
    }
    h.assert_all_refused_untouched(entries.len()).await;
}

#[tokio::test]
async fn other_refusals_touch_nothing_either() {
    let h = Harness::wide_open().await;
    let local = crate::executor::sftp::tests::allowed_local("x.log");
    let many: serde_json::Map<String, Value> =
        (0..65).map(|i| (format!("k{i}"), json!("v"))).collect();
    let mut n = 0;

    // proxy_http: method, limits, preset kind.
    for (method, path) in [("DELETE", "/x"), ("PATCH", "/x"), ("get\n", "/x")] {
        h.http(method, path, None, None).await;
        n += 1;
    }
    h.http("GET", &format!("/{}", "a".repeat(3000)), None, None)
        .await;
    h.http("GET", "/x", Some(Value::Object(many)), None).await;
    h.http("POST", "/x", None, Some(json!("a".repeat(2 << 20))))
        .await;
    n += 3;

    // ssh_exec over the limit.
    h.ssh(&"a".repeat(2000)).await;
    n += 1;

    // sftp_transfer: remote outside the prefix or climbing out of it, local
    // outside $HOME and /tmp, relative or with `..`, bad direction.
    for (direction, remote, local) in [
        ("get", "/etc/shadow", local.as_str()),
        ("get", "/srv/app/../../etc/shadow", local.as_str()),
        ("get", "srv/app/x", local.as_str()),
        ("put", "/srv/app/x", "/etc/passwd"),
        ("put", "/srv/app/x", "x.log"),
        ("put", "/srv/app/x", "/tmp/../etc/passwd"),
        ("steal", "/srv/app/x", local.as_str()),
    ] {
        h.sftp(direction, remote, local).await;
        n += 1;
    }

    // db_query: unknown query, wrong count, over the limit.
    h.db("drop_users", vec![]).await;
    h.db("user_by_id", vec![]).await;
    h.db("user_by_id", vec![json!(1), json!(2)]).await;
    h.db("user_by_id", vec![json!("x".repeat(20_000))]).await;
    n += 4;

    h.assert_all_refused_untouched(n).await;
}

/// `get_secret_for_env` reveals only the secret of a preset or a wrapped
/// server, and decides that before anyone is asked: an unknown, oversized
/// or crafted name never reaches a prompt, and the Telegram bot token —
/// the approval channel itself — is never revealed.
#[tokio::test]
async fn revealing_anything_but_a_preset_secret_is_refused_unasked() {
    let mut h = Harness::wide_open().await;
    let presets = h.server.presets.list().unwrap();
    h.server = WardenServer::new(
        Arc::new(FrozenSource::new(presets)),
        h.server.executor.clone(),
    )
    .with_revealable(["web_tok", "server/gh/GITHUB_TOKEN"].map(String::from));
    let names = [
        "tg_bot_token".to_string(),
        "server/gh/OTHER".into(),
        "pg_pw".into(),
        "web_tok\u{202E}".into(),
        "x".repeat(300),
        String::new(),
    ];
    for name in &names {
        h.reveal(name).await;
    }
    h.assert_all_refused_untouched(names.len()).await;

    let ok = h
        .server
        .get_secret_for_env(Parameters(GetSecretForEnvArgs {
            name: "web_tok".into(),
        }))
        .await
        .unwrap();
    assert_eq!(ok.0.value, SECRETS[0].1);
    assert_eq!(h.approval.calls(), 1);
}

/// The prompt names where the request goes. An agent that edits
/// config.toml can point a `prompt` preset at its own host; with the host
/// in the prompt the human sees that before approving.
#[tokio::test]
async fn the_prompt_names_the_destination_host() {
    let h = Harness::wide_open().await;
    let _ = h
        .server
        .proxy_http(Parameters(ProxyHttpArgs {
            preset_name: "web".into(),
            path: "/user/repos".into(),
            method: "GET".into(),
            body: None,
            query: None,
        }))
        .await;
    let _ = h
        .server
        .db_query(Parameters(DbQueryArgs {
            preset_name: "pg".into(),
            query_name: "user_by_id".into(),
            params: vec![json!(1)],
        }))
        .await;
    let shown = h.approval.shown.lock().unwrap();
    assert_eq!(shown[0].summary, format!("GET {}/user/repos", h.http.uri()));
    assert_eq!(
        shown[1].summary,
        "db postgres 127.0.0.1 → user_by_id (1 param)"
    );
}
