//! `policy::check_request` with every kind of call, against presets that
//! allow everything — only the checks that hold whatever the allow-list
//! says can refuse. A panic is a finding; so is an allowed HTTP path that
//! the URL builder would rewrite.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mcp_warden::executor::http::build_url;
use mcp_warden::executor::policy::{Request, check_request};
use mcp_warden_core::config::Config;
use std::collections::BTreeMap;
use std::sync::LazyLock;

static PRESETS: LazyLock<Config> = LazyLock::new(|| {
    toml::from_str(
        r#"
        [[preset]]
        name = "web"
        type = "http"
        description = "x"
        base_url = "https://api.example.com/v1"
        auth = { type = "bearer", secret = "k" }
        allowed_methods = ["GET", "POST"]
        allowed_paths = [".*"]
        approval = "auto"

        [[preset]]
        name = "box"
        type = "ssh"
        description = "x"
        host = "h"
        user = "u"
        secret = "k"
        allowed_commands = [".*"]
        allow_sftp = true
        sftp_allowed_paths = ["/srv/"]
        approval = "auto"

        [[preset.commands]]
        name = "run"
        description = "x"
        template = "echo {v} {n}"
        params.v = { type = "string", pattern = ".*" }
        params.n = { type = "int", min = 0, max = 100 }

        [[preset]]
        name = "webq"
        type = "http"
        description = "x"
        base_url = "https://api.example.com/v1"
        auth = { type = "query", name = "key", secret = "k" }
        allowed_methods = ["GET"]
        allowed_paths = [".*"]
        approval = "auto"

        [[preset]]
        name = "pg"
        type = "postgres"
        description = "x"
        host = "h"
        user = "u"
        secret = "k"
        database = "d"
        approval = "auto"
        [[preset.queries]]
        name = "q"
        template = "select $1"
        param_types = ["text"]
        "#,
    )
    .unwrap()
});

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    let mut parts = text.splitn(3, '\u{0}');
    let a = parts.next().unwrap_or("");
    let b = parts.next().unwrap_or("");
    let c = parts.next().unwrap_or("");
    let cfg = &*PRESETS;
    match selector % 6 {
        0 => {
            let query: BTreeMap<String, String> = [(b.to_string(), c.to_string())].into();
            let body = serde_json::json!({ c: b });
            let req = Request::Http {
                method: "GET",
                path: a,
                query: Some(&query),
                body: Some(&body),
            };
            if check_request(&cfg.preset[0], &req).is_ok() {
                // What passed the allow-list is what would be sent.
                let url = build_url("https://api.example.com/v1", a).expect("allowed path builds");
                assert_eq!(url.path(), format!("/v1{a}"));
            }
        }
        1 => {
            let _ = check_request(&cfg.preset[1], &Request::Ssh { command: a });
        }
        2 => {
            let _ = check_request(
                &cfg.preset[1],
                &Request::Sftp {
                    remote: a,
                    local: b,
                },
            );
        }
        3 => {
            let params: BTreeMap<String, serde_json::Value> =
                [("v".to_string(), b.into()), ("n".to_string(), c.into())].into();
            let _ = check_request(
                &cfg.preset[1],
                &Request::SshRun {
                    command: a,
                    params: &params,
                },
            );
        }
        4 => {
            // The credential's own parameter name never gets through.
            let query: BTreeMap<String, String> = [(a.to_string(), b.to_string())].into();
            let req = Request::Http {
                method: "GET",
                path: "/x",
                query: Some(&query),
                body: None,
            };
            if check_request(&cfg.preset[2], &req).is_ok() {
                assert!(!a.trim().eq_ignore_ascii_case("key"), "{a:?}");
            }
        }
        _ => {
            let params = [serde_json::Value::from(b)];
            let _ = check_request(
                &cfg.preset[3],
                &Request::Db {
                    query: a,
                    params: &params,
                },
            );
        }
    }
});
