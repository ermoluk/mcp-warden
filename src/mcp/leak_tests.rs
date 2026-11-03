//! Invariants 1 and 2, checked against failing upstreams: whatever goes
//! wrong — connection refused, a TLS failure, a 401 that quotes the token, a
//! database that echoes the password in its error or returns it as data —
//! no form of the secret reaches the agent, stderr or `audit.db`.

use super::server::*;
use crate::executor::ActionExecutor;
use crate::testutil::{
    CountingApproval, CountingKeychain, CountingListener, FakePostgres, FakeRedis,
    assert_no_secret, audit_text, capture_logs,
};
use mcp_warden_core::approval::ApprovalDecision;
use mcp_warden_core::audit::sqlite_sink::LocalSqlite;
use mcp_warden_core::config::Config;
use mcp_warden_core::presets::frozen::FrozenSource;
use rmcp::handler::server::wrapper::Parameters;
use serde_json::{Value, json};
use std::sync::Arc;

const SECRETS: &[(&str, &str)] = &[
    ("web_tok", "tok-WEB-a1b2c3d4e5f6"),
    ("pg_pw", "pw-PG-a1b2c3d4e5f6"),
    ("rd_pw", "pw-RD-a1b2c3d4e5f6"),
    ("box_key", "not-a-key-BOX-a1b2c3d4e5f6"),
];

/// A port with nothing listening on it.
fn closed_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn failing_upstreams_never_leak_the_secret() {
    let (logs, _guard) = capture_logs();
    let web = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::any())
        .respond_with(|req: &wiremock::Request| {
            let auth = req
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            wiremock::ResponseTemplate::new(401)
                .set_body_json(json!({ "error": format!("invalid credentials: {auth}") }))
        })
        .mount(&web)
        .await;
    let plain_tcp = CountingListener::start();
    let pg = FakePostgres::start().await;
    let rd_pw = SECRETS[2].1.to_string();
    let rd_bad = FakeRedis::start(|args| match args[0].to_ascii_uppercase().as_str() {
        "AUTH" => format!("-ERR invalid password '{}'\r\n", args.last().unwrap()).into_bytes(),
        _ => b"+OK\r\n".to_vec(),
    })
    .await;
    let rd_config = FakeRedis::start(move |args| match args[0].to_ascii_uppercase().as_str() {
        "CONFIG" => format!(
            "*2\r\n$11\r\nrequirepass\r\n${}\r\n{rd_pw}\r\n",
            rd_pw.len()
        )
        .into_bytes(),
        _ => b"+OK\r\n".to_vec(),
    })
    .await;
    let closed = closed_port();

    let presets = toml::from_str::<Config>(&format!(
        r#"
        [[preset]]
        name = "web_401"
        type = "http"
        description = "x"
        base_url = "{web}"
        auth = {{ type = "bearer", secret = "web_tok" }}
        allowed_methods = ["GET"]
        approval = "prompt"

        [[preset]]
        name = "web_refused"
        type = "http"
        description = "x"
        base_url = "http://127.0.0.1:{closed}"
        auth = {{ type = "header", name = "X-Key", secret = "web_tok" }}
        allowed_methods = ["GET"]
        approval = "prompt"

        [[preset]]
        name = "web_tls"
        type = "http"
        description = "x"
        base_url = "https://127.0.0.1:{plain}"
        auth = {{ type = "basic", username = "u", secret = "web_tok" }}
        allowed_methods = ["GET"]
        approval = "prompt"

        [[preset]]
        name = "pg"
        type = "postgres"
        description = "x"
        host = "127.0.0.1"
        port = {pg}
        user = "u"
        secret = "pg_pw"
        database = "db"
        approval = "prompt"
        [[preset.queries]]
        name = "one"
        template = "select 1"

        [[preset]]
        name = "rd_bad"
        type = "redis"
        description = "x"
        host = "127.0.0.1"
        port = {rd_bad}
        secret = "rd_pw"
        user = "default"
        approval = "prompt"
        [[preset.queries]]
        name = "get"
        template = "GET"
        param_types = ["text"]

        [[preset]]
        name = "rd_config"
        type = "redis"
        description = "x"
        host = "127.0.0.1"
        port = {rd_config}
        secret = "rd_pw"
        user = "default"
        approval = "prompt"
        [[preset.queries]]
        name = "requirepass"
        template = "CONFIG"
        param_types = ["text", "text"]

        [[preset]]
        name = "box"
        type = "ssh"
        description = "x"
        host = "127.0.0.1"
        port = {closed}
        user = "u"
        secret = "box_key"
        allowed_commands = ["uptime"]
        approval = "prompt"
        "#,
        web = web.uri(),
        plain = plain_tcp.port,
        pg = pg.port,
        rd_bad = rd_bad.port,
        rd_config = rd_config.port,
    ))
    .unwrap()
    .preset;

    let dir = tempfile::tempdir().unwrap();
    let audit_db = dir.path().join("audit.db");
    let executor = Arc::new(ActionExecutor::new(
        CountingKeychain::with(SECRETS),
        CountingApproval::new(ApprovalDecision::Approved),
        None,
        Arc::new(LocalSqlite::open(&audit_db).unwrap()),
    ));
    let server = WardenServer::new(Arc::new(FrozenSource::new(presets)), executor);

    let mut seen_by_agent = Vec::new();
    let mut record = |what: &str, out: Result<Value, rmcp::ErrorData>| {
        seen_by_agent.push(match out {
            Ok(v) => format!("{what}: ok {v}"),
            Err(e) => format!("{what}: err {} {:?}", e.message, e.data),
        });
    };
    for preset in ["web_401", "web_refused", "web_tls"] {
        let out = server
            .proxy_http(Parameters(ProxyHttpArgs {
                preset_name: preset.into(),
                path: "/me".into(),
                method: "GET".into(),
                body: None,
                query: None,
            }))
            .await
            .map(|r| serde_json::to_value(&r.0).unwrap());
        record(preset, out);
    }
    for (preset, query, params) in [
        ("pg", "one", vec![]),
        ("rd_bad", "get", vec![json!("k")]),
        (
            "rd_config",
            "requirepass",
            vec![json!("GET"), json!("requirepass")],
        ),
    ] {
        let out = server
            .db_query(Parameters(DbQueryArgs {
                preset_name: preset.into(),
                query_name: query.into(),
                params,
            }))
            .await
            .map(|r| serde_json::to_value(&r.0).unwrap());
        record(preset, out);
    }
    let out = server
        .ssh_exec(Parameters(SshExecArgs {
            preset_name: "box".into(),
            command: "uptime".into(),
        }))
        .await
        .map(|r| serde_json::to_value(&r.0).unwrap());
    record("box", out);

    let agent = seen_by_agent.join("\n");
    // Each call really failed or was scrubbed, rather than never running.
    assert!(
        agent.contains("web_401: ok") && agent.contains("[redacted by mcp-warden]"),
        "{agent}"
    );
    assert!(
        agent.contains("pg: err") && agent.contains("rd_bad: err"),
        "{agent}"
    );
    assert!(agent.contains("rd_config: ok"), "{agent}");
    let stderr = logs.text();
    let audit = audit_text(&audit_db);
    for (_, secret) in SECRETS {
        assert_no_secret("the agent's view", &agent, secret);
        assert_no_secret("stderr", &stderr, secret);
        assert_no_secret("audit.db", &audit, secret);
    }
}

/// The same for the 0.6.0 auth kinds: a query-parameter key echoed in a
/// URL or lost in a connection error, OAuth2 secrets quoted by a hostile
/// token endpoint or a minted token quoted by the API, SigV4 keys.
#[tokio::test]
async fn failing_upstreams_never_leak_query_oauth2_or_sigv4_secrets() {
    const NEW_SECRETS: &[(&str, &str)] = &[
        ("q_key", "key-QUERY-a1b2c3d4e5f6"),
        ("o_cs", "cs-OAUTH-a1b2c3d4e5f6"),
        ("o_rt", "rt-OAUTH-a1b2c3d4e5f6"),
        ("o_rt2", "rt-OAUTH2-a1b2c3d4e5f6"),
        ("a_id", "AKIDLEAKTESTa1b2c3d4"),
        ("a_sk", "sk-AWS-a1b2c3d4e5f6"),
        ("a_st", "st-AWS-a1b2c3d4e5f6"),
    ];
    const ACCESS: &str = "at-MINTED-a1b2c3d4e5f6";
    let (logs, _guard) = capture_logs();
    // Every request, URL and authorization header quoted back in a 401.
    let web = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::any())
        .respond_with(|req: &wiremock::Request| {
            let auth = req
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            wiremock::ResponseTemplate::new(401).set_body_json(json!({
                "error": format!("denied {} {auth}", req.url),
            }))
        })
        .mount(&web)
        .await;
    // A token endpoint that quotes what it was sent, and one that works.
    let hostile = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::any())
        .respond_with(|req: &wiremock::Request| {
            wiremock::ResponseTemplate::new(400).set_body_json(json!({
                "error": "invalid_grant",
                "error_description": String::from_utf8_lossy(&req.body),
            }))
        })
        .mount(&hostile)
        .await;
    let issuer = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::any())
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(json!({ "access_token": ACCESS, "token_type": "bearer" })),
        )
        .mount(&issuer)
        .await;
    let closed = closed_port();
    let presets = toml::from_str::<Config>(&format!(
        r#"
        [[preset]]
        name = "q_401"
        type = "http"
        description = "x"
        base_url = "{web}"
        auth = {{ type = "query", name = "key", secret = "q_key" }}
        allowed_methods = ["GET"]
        approval = "prompt"

        [[preset]]
        name = "q_refused"
        type = "http"
        description = "x"
        base_url = "http://127.0.0.1:{closed}"
        auth = {{ type = "query", name = "key", secret = "q_key" }}
        allowed_methods = ["GET"]
        approval = "prompt"

        [[preset]]
        name = "o_hostile"
        type = "http"
        description = "x"
        base_url = "{web}"
        allowed_methods = ["GET"]
        approval = "prompt"
        [preset.auth]
        type = "oauth2"
        grant = "refresh_token"
        token_url = "{hostile}/token"
        client_id = "id"
        client_secret = "o_cs"
        refresh_token = "o_rt"
        client_auth = "body"

        [[preset]]
        name = "o_401"
        type = "http"
        description = "x"
        base_url = "{web}"
        allowed_methods = ["GET"]
        approval = "prompt"
        [preset.auth]
        type = "oauth2"
        grant = "refresh_token"
        token_url = "{issuer}/token"
        client_id = "id"
        client_secret = "o_cs"
        refresh_token = "o_rt2"

        [[preset]]
        name = "a_401"
        type = "http"
        description = "x"
        base_url = "{web}"
        allowed_methods = ["GET"]
        approval = "prompt"
        [preset.auth]
        type = "aws_sigv4"
        region = "eu-central-1"
        service = "execute-api"
        access_key_id = "a_id"
        secret_access_key = "a_sk"
        session_token = "a_st"
        "#,
        web = web.uri(),
        hostile = hostile.uri(),
        issuer = issuer.uri(),
    ))
    .unwrap()
    .preset;

    let dir = tempfile::tempdir().unwrap();
    let audit_db = dir.path().join("audit.db");
    let executor = Arc::new(ActionExecutor::new(
        CountingKeychain::with(NEW_SECRETS),
        CountingApproval::new(ApprovalDecision::Approved),
        None,
        Arc::new(LocalSqlite::open(&audit_db).unwrap()),
    ));
    let server = WardenServer::new(Arc::new(FrozenSource::new(presets)), executor);
    let mut agent = String::new();
    for preset in ["q_401", "q_refused", "o_hostile", "o_401", "a_401"] {
        let out = server
            .proxy_http(Parameters(ProxyHttpArgs {
                preset_name: preset.into(),
                path: "/me".into(),
                method: "GET".into(),
                body: None,
                query: Some([("page".to_string(), "1".to_string())].into()),
            }))
            .await;
        agent.push_str(&match out {
            Ok(r) => format!("{preset}: ok {}\n", serde_json::to_value(&r.0).unwrap()),
            Err(e) => format!("{preset}: err {} {:?}\n", e.message, e.data),
        });
    }
    // Each call really ran: the 401s came back scrubbed, the others failed.
    for want in [
        "q_401: ok",
        "q_refused: err",
        "o_hostile: err",
        "o_401: ok",
        "a_401: ok",
    ] {
        assert!(agent.contains(want), "{want}\n{agent}");
    }
    assert!(agent.contains("[redacted by mcp-warden]"), "{agent}");
    let stderr = logs.text();
    let audit = audit_text(&audit_db);
    for secret in NEW_SECRETS.iter().map(|(_, s)| *s).chain([ACCESS]) {
        assert_no_secret("the agent's view", &agent, secret);
        assert_no_secret("stderr", &stderr, secret);
        assert_no_secret("audit.db", &audit, secret);
    }
}
