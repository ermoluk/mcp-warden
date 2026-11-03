//! Would this call be allowed? The one place that decides, shared by the
//! tools and by `mcp-warden preset test`, so the simulator and the server
//! cannot disagree. Every check here is pure: no secret is read and nothing
//! is sent.

use chrono::{DateTime, SecondsFormat, Utc};
use mcp_warden_core::config::{ApprovalPolicy, Preset, PresetType};
use mcp_warden_core::error::{Result, WardenError};
use serde_json::Value;
use std::collections::BTreeMap;

/// A call as the agent would make it.
#[derive(Debug, Clone, Copy)]
pub enum Request<'a> {
    Http {
        method: &'a str,
        path: &'a str,
        query: Option<&'a BTreeMap<String, String>>,
        body: Option<&'a Value>,
    },
    Ssh {
        command: &'a str,
    },
    /// `ssh_run`: a named command and its parameter values.
    SshRun {
        command: &'a str,
        params: &'a BTreeMap<String, Value>,
    },
    Sftp {
        remote: &'a str,
        local: &'a str,
    },
    Db {
        query: &'a str,
        params: &'a [Value],
    },
}

impl<'a> Request<'a> {
    /// A `proxy_http` call without query parameters or body.
    pub fn http(method: &'a str, path: &'a str) -> Self {
        Request::Http {
            method,
            path,
            query: None,
            body: None,
        }
    }

    /// The MCP tool that makes this call.
    pub fn tool(&self) -> &'static str {
        match self {
            Request::Http { .. } => "proxy_http",
            Request::Ssh { .. } => "ssh_exec",
            Request::SshRun { .. } => "ssh_run",
            Request::Sftp { .. } => "sftp_transfer",
            Request::Db { .. } => "db_query",
        }
    }

    /// The preset kind this call needs, as users write it in `type = …`.
    fn needs(&self) -> &'static str {
        match self {
            Request::Http { .. } => "http",
            Request::Ssh { .. } | Request::SshRun { .. } | Request::Sftp { .. } => "ssh",
            Request::Db { .. } => "database (postgres / mysql / redis)",
        }
    }

    fn fits(&self, kind: PresetType) -> bool {
        match self {
            Request::Http { .. } => kind == PresetType::Http,
            Request::Ssh { .. } | Request::SshRun { .. } | Request::Sftp { .. } => {
                kind == PresetType::Ssh
            }
            Request::Db { .. } => matches!(
                kind,
                PresetType::Postgres | PresetType::Mysql | PresetType::Redis
            ),
        }
    }
}

/// Check a request against the input limits, the preset's kind and its
/// allow-lists, in that order. Runs before any credential is touched
/// (invariant 3).
pub fn check_request(preset: &Preset, req: &Request) -> Result<()> {
    super::limits::check(req)?;
    if !req.fits(preset.preset_type) {
        return Err(WardenError::Validation(format!(
            "preset '{}' is not an {} preset; {} needs one",
            preset.name,
            req.needs(),
            req.tool()
        )));
    }
    match *req {
        Request::Http {
            method,
            path,
            query,
            body,
        } => {
            super::http::validated_url(preset, &method.to_uppercase(), path)?;
            super::http::check_query_and_body_keys(query, body)?;
            super::http::check_auth_query_name(preset, query)
        }
        Request::Ssh { command } => super::ssh::validate_command(preset, command),
        Request::SshRun { command, params } => {
            mcp_warden_core::commands::render(preset, command, params).map(drop)
        }
        Request::Sftp { remote, local } => super::sftp::validate_transfer(preset, remote, local),
        Request::Db { query, params } => {
            super::db::find_query(preset, query, params.len()).map(drop)
        }
    }
}

/// Refuse a preset whose access window (`mcp-warden preset grant`) has ended.
pub fn check_expiry(preset: &Preset, now: DateTime<Utc>) -> Result<()> {
    match preset.expires_at {
        Some(at) if at <= now => Err(WardenError::Validation(format!(
            "access to preset '{name}' expired at {at}; run `mcp-warden preset grant {name} --for 1h`, \
             then restart the MCP server",
            name = preset.name,
            at = at.to_rfc3339_opts(SecondsFormat::Secs, true),
        ))),
        _ => Ok(()),
    }
}

/// What `mcp-warden preset test` reports for a simulated call.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The call would go ahead: straight away for `auto`, after a prompt for
    /// `prompt` (which may offer an approval window of up to N seconds).
    Allowed {
        policy: ApprovalPolicy,
        window_seconds: Option<u64>,
    },
    Refused(String),
}

/// Simulate a call at `now` in the order the server checks it: the preset's
/// access window, the request, then the approval policy.
pub fn simulate(preset: &Preset, req: &Request, now: DateTime<Utc>) -> Verdict {
    if let Err(e) = check_expiry(preset, now).and_then(|()| check_request(preset, req)) {
        return Verdict::Refused(e.to_string());
    }
    let policy = match *req {
        Request::SshRun { command, params } => {
            match mcp_warden_core::commands::render(preset, command, params) {
                Ok(r) => r.approval,
                Err(e) => return Verdict::Refused(e.to_string()),
            }
        }
        _ => preset.approval,
    };
    match policy {
        ApprovalPolicy::Deny if preset.approval != ApprovalPolicy::Deny => {
            Verdict::Refused("command policy is deny".into())
        }
        ApprovalPolicy::Deny => Verdict::Refused("preset policy is deny".into()),
        ApprovalPolicy::Auto => Verdict::Allowed {
            policy: ApprovalPolicy::Auto,
            window_seconds: None,
        },
        ApprovalPolicy::Prompt => Verdict::Allowed {
            policy: ApprovalPolicy::Prompt,
            window_seconds: preset.approval_window_seconds.filter(|n| *n > 0),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_warden_core::config::{Auth, NamedQuery};

    fn http(policy: ApprovalPolicy) -> Preset {
        toml::from_str::<Preset>(&format!(
            r#"
            name = "gh"
            type = "http"
            description = "GitHub"
            base_url = "https://api.github.com"
            allowed_methods = ["GET"]
            allowed_paths = ["/repos/o/[^/]+"]
            approval = "{}"
            "#,
            match policy {
                ApprovalPolicy::Auto => "auto",
                ApprovalPolicy::Prompt => "prompt",
                ApprovalPolicy::Deny => "deny",
            }
        ))
        .map(|mut p| {
            p.auth = Some(Auth::Bearer {
                secret: "gh_pat".into(),
            });
            p
        })
        .unwrap()
    }

    fn ssh() -> Preset {
        toml::from_str(
            r#"
            name = "deploy"
            type = "ssh"
            description = "deploy box"
            host = "example.com"
            user = "deploy"
            secret = "deploy_key"
            allowed_commands = ["docker compose (pull|up -d)"]
            allow_sftp = true
            sftp_allowed_paths = ["/srv/app/"]
            approval = "prompt"
            "#,
        )
        .unwrap()
    }

    fn db() -> Preset {
        let mut p: Preset = toml::from_str(
            r#"
            name = "pg"
            type = "postgres"
            description = "db"
            host = "localhost"
            secret = "pg_pw"
            approval = "auto"
            "#,
        )
        .unwrap();
        p.queries = vec![NamedQuery {
            name: "user_by_id".into(),
            template: "select * from users where id = $1".into(),
            param_types: vec!["int8".into()],
            readonly: true,
        }];
        p
    }

    #[test]
    fn http_allowed_path_and_method() {
        let req = Request::http("get", "/repos/o/r");
        assert!(check_request(&http(ApprovalPolicy::Auto), &req).is_ok());
    }

    #[test]
    fn http_refuses_method_path_and_encoded_slash() {
        let p = http(ApprovalPolicy::Auto);
        for (method, path) in [
            ("DELETE", "/repos/o/r"),
            ("GET", "/repos/o/r/collaborators"),
            ("GET", "/repos/o/x%2Fcollaborators"),
            ("GET", "/repos/o/x%252Fcollaborators"),
            ("GET", "/repos/o/../admin"),
        ] {
            let req = Request::http(method, path);
            assert!(check_request(&p, &req).is_err(), "{method} {path}");
        }
    }

    #[test]
    fn ssh_command_is_anchored() {
        let p = ssh();
        assert!(
            check_request(
                &p,
                &Request::Ssh {
                    command: "docker compose pull"
                }
            )
            .is_ok()
        );
        let evil = Request::Ssh {
            command: "docker compose pull; rm -rf /",
        };
        assert!(check_request(&p, &evil).is_err());
    }

    #[test]
    fn sftp_checks_remote_prefix() {
        let p = ssh();
        let local = crate::executor::sftp::tests::allowed_local("x.log");
        let ok = Request::Sftp {
            remote: "/srv/app/x.log",
            local: &local,
        };
        check_request(&p, &ok).unwrap();
        let bad = Request::Sftp {
            remote: "/etc/shadow",
            local: &local,
        };
        assert!(check_request(&p, &bad).is_err());
    }

    #[test]
    fn db_checks_query_name_and_param_count() {
        let p = db();
        let one = [Value::from(7)];
        let ok = Request::Db {
            query: "user_by_id",
            params: &one,
        };
        assert!(check_request(&p, &ok).is_ok());
        let two = [Value::from(7), Value::from(8)];
        for (query, params) in [("drop_all", &[][..]), ("user_by_id", &two[..])] {
            assert!(check_request(&p, &Request::Db { query, params }).is_err());
        }
    }

    #[test]
    fn wrong_preset_kind_is_refused() {
        let err = check_request(&ssh(), &Request::http("GET", "/")).unwrap_err();
        assert!(err.to_string().contains("not an http preset"), "{err}");
        assert!(
            check_request(
                &http(ApprovalPolicy::Auto),
                &Request::Db {
                    query: "q",
                    params: &[]
                }
            )
            .is_err()
        );
    }

    #[test]
    fn simulate_reports_policy_after_the_request_passes() {
        let req = Request::http("GET", "/repos/o/r");
        assert_eq!(
            simulate(&http(ApprovalPolicy::Auto), &req, Utc::now()),
            Verdict::Allowed {
                policy: ApprovalPolicy::Auto,
                window_seconds: None
            }
        );
        let mut prompt = http(ApprovalPolicy::Prompt);
        prompt.approval_window_seconds = Some(600);
        assert_eq!(
            simulate(&prompt, &req, Utc::now()),
            Verdict::Allowed {
                policy: ApprovalPolicy::Prompt,
                window_seconds: Some(600)
            }
        );
        assert_eq!(
            simulate(&http(ApprovalPolicy::Deny), &req, Utc::now()),
            Verdict::Refused("preset policy is deny".into())
        );
    }

    #[test]
    fn expired_preset_is_refused_before_the_request_is_checked() {
        let now = Utc::now();
        let mut p = http(ApprovalPolicy::Auto);
        p.expires_at = Some(now - chrono::Duration::seconds(1));
        let err = check_expiry(&p, now).unwrap_err().to_string();
        assert!(err.contains("access to preset 'gh' expired"), "{err}");
        assert!(err.contains("preset grant gh"), "{err}");
        let req = Request::http("DELETE", "/nope");
        match simulate(&p, &req, now) {
            Verdict::Refused(why) => assert!(why.contains("expired"), "{why}"),
            other => panic!("{other:?}"),
        }

        p.expires_at = Some(now + chrono::Duration::minutes(5));
        assert!(check_expiry(&p, now).is_ok());
        // Ends exactly at the instant it names.
        p.expires_at = Some(now);
        assert!(check_expiry(&p, now).is_err());
    }

    #[test]
    fn simulate_reports_validation_before_policy() {
        let req = Request::http("DELETE", "/repos/o/r");
        match simulate(&http(ApprovalPolicy::Deny), &req, Utc::now()) {
            Verdict::Refused(why) => assert!(why.contains("DELETE"), "{why}"),
            other => panic!("{other:?}"),
        }
    }

    fn named() -> Preset {
        let cfg: mcp_warden_core::config::Config =
            toml::from_str(include_str!("../../tests/fixtures/named_commands.toml")).unwrap();
        cfg.preset[0].clone()
    }

    fn params(v: Value) -> BTreeMap<String, Value> {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn ssh_run_renders_through_the_same_check() {
        let p = named();
        let ok = params(serde_json::json!({"lines": 50}));
        let req = Request::SshRun {
            command: "tail_log",
            params: &ok,
        };
        assert_eq!(req.tool(), "ssh_run");
        check_request(&p, &req).unwrap();
        let bad = params(serde_json::json!({"lines": "50 ; id"}));
        let req = Request::SshRun {
            command: "tail_log",
            params: &bad,
        };
        assert!(check_request(&p, &req).is_err());
        // Only SSH presets run commands.
        let req = Request::SshRun {
            command: "tail_log",
            params: &ok,
        };
        let err = check_request(&http(ApprovalPolicy::Prompt), &req)
            .unwrap_err()
            .to_string();
        assert!(err.contains("ssh_run needs one"), "{err}");
    }

    #[test]
    fn ssh_run_limits_come_first() {
        let p = named();
        let many = params(serde_json::Value::Object(
            (0..17)
                .map(|i| (format!("p{i}"), serde_json::json!(1)))
                .collect(),
        ));
        let req = Request::SshRun {
            command: "tail_log",
            params: &many,
        };
        let err = check_request(&p, &req).unwrap_err().to_string();
        assert!(err.contains("the limit is 16 parameters"), "{err}");
        let long = params(serde_json::json!({"lines": "1".repeat(300)}));
        let req = Request::SshRun {
            command: "tail_log",
            params: &long,
        };
        let err = check_request(&p, &req).unwrap_err().to_string();
        assert!(err.contains("over the limit of 256 bytes"), "{err}");
    }

    #[test]
    fn simulate_uses_the_command_policy() {
        let mut p = named();
        p.commands[0].approval = Some(ApprovalPolicy::Auto);
        p.commands[1].approval = Some(ApprovalPolicy::Deny);
        let lines = params(serde_json::json!({"lines": 5}));
        let unit = params(serde_json::json!({"unit": "app.service"}));
        let tail = Request::SshRun {
            command: "tail_log",
            params: &lines,
        };
        let restart = Request::SshRun {
            command: "restart",
            params: &unit,
        };
        assert_eq!(
            simulate(&p, &tail, Utc::now()),
            Verdict::Allowed {
                policy: ApprovalPolicy::Auto,
                window_seconds: None
            }
        );
        assert_eq!(
            simulate(&p, &restart, Utc::now()),
            Verdict::Refused("command policy is deny".into())
        );
        p.commands[1].approval = None;
        assert_eq!(
            simulate(&p, &restart, Utc::now()),
            Verdict::Allowed {
                policy: ApprovalPolicy::Prompt,
                window_seconds: Some(600)
            }
        );
        p.approval = ApprovalPolicy::Deny;
        assert_eq!(
            simulate(&p, &tail, Utc::now()),
            Verdict::Refused("preset policy is deny".into())
        );
    }

    // -------- hostile-input corpus --------

    /// Every entry of `text` must be refused for `preset`; returns how many
    /// were checked.
    fn assert_all_refused(
        file: &str,
        text: &str,
        preset: &Preset,
        req: impl Fn(&str) -> Request,
    ) -> usize {
        let entries = crate::testutil::corpus(text);
        let allowed: Vec<String> = entries
            .iter()
            .filter(|(_, input, _)| check_request(preset, &req(input)).is_ok())
            .map(|(line, input, note)| format!("  {file}:{line}: {input:?} — {note}"))
            .collect();
        assert!(
            allowed.is_empty(),
            "allowed by a preset that permits everything:\n{}",
            allowed.join("\n")
        );
        entries.len()
    }

    #[test]
    fn hostile_corpus_paths_are_refused_whatever_the_allow_list() {
        let mut wide = http(ApprovalPolicy::Auto);
        wide.allowed_paths = vec![".*".into()];
        // The allow-list really is wide open: an ordinary path passes.
        check_request(&wide, &Request::http("GET", "/repos/o/r/issues")).unwrap();
        let n = assert_all_refused(
            "tests/corpus/paths.txt",
            include_str!("../../tests/corpus/paths.txt"),
            &wide,
            |path| Request::http("GET", path),
        );
        assert!(n >= 50, "only {n} entries in tests/corpus/paths.txt");
    }

    /// A preset whose parameters accept anything their type allows, for the
    /// named-command corpus.
    fn wide_named() -> Preset {
        toml::from_str(
            r#"
            name = "wide"
            type = "ssh"
            description = "x"
            host = "example.com"
            user = "deploy"
            secret = "deploy_key"
            approval = "prompt"
            [[commands]]
            name = "word"
            description = "x"
            template = "echo {v}"
            params.v = { type = "string", pattern = ".*" }
            [[commands]]
            name = "path"
            description = "x"
            template = "cat {v}"
            params.v = { type = "path", pattern = ".*" }
            [[commands]]
            name = "num"
            description = "x"
            template = "head -n {v} f"
            params.v = { type = "int", min = 0, max = 9223372036854775807 }
            [[commands]]
            name = "opt"
            description = "x"
            template = "ls --color={v}"
            params.v = { type = "enum", values = ["auto", "never"] }
            "#,
        )
        .unwrap()
    }

    #[test]
    fn hostile_corpus_named_commands_are_refused_whatever_the_patterns() {
        let wide = wide_named();
        mcp_warden_core::commands::validate_preset(&wide).unwrap();
        for (command, ok) in [
            ("word", r#"{"v":"a.b-c"}"#),
            ("path", r#"{"v":"/srv/app/x"}"#),
            ("num", r#"{"v":"9223372036854775807"}"#),
            ("opt", r#"{"v":"never"}"#),
        ] {
            let params: BTreeMap<String, Value> = serde_json::from_str(ok).unwrap();
            check_request(
                &wide,
                &Request::SshRun {
                    command,
                    params: &params,
                },
            )
            .unwrap();
        }
        let file = "tests/corpus/named-commands.txt";
        let entries =
            crate::testutil::corpus(include_str!("../../tests/corpus/named-commands.txt"));
        let allowed: Vec<String> = entries
            .iter()
            .filter(|(line, input, _)| {
                let (command, json) = input
                    .split_once(' ')
                    .unwrap_or_else(|| panic!("{file}:{line}: no params"));
                let params: BTreeMap<String, Value> =
                    serde_json::from_str(json).unwrap_or_else(|e| panic!("{file}:{line}: {e}"));
                check_request(
                    &wide,
                    &Request::SshRun {
                        command,
                        params: &params,
                    },
                )
                .is_ok()
            })
            .map(|(line, input, note)| format!("  {file}:{line}: {input:?} — {note}"))
            .collect();
        assert!(allowed.is_empty(), "allowed:\n{}", allowed.join("\n"));
        assert!(
            entries.len() >= 60,
            "only {} entries in {file}",
            entries.len()
        );
    }

    #[test]
    fn hostile_corpus_commands_are_refused_whatever_the_allow_list() {
        let mut wide = ssh();
        wide.allowed_commands = vec![".*".into()];
        check_request(
            &wide,
            &Request::Ssh {
                command: "git pull",
            },
        )
        .unwrap();
        let n = assert_all_refused(
            "tests/corpus/commands.txt",
            include_str!("../../tests/corpus/commands.txt"),
            &wide,
            |command| Request::Ssh { command },
        );
        assert!(n >= 40, "only {n} entries in tests/corpus/commands.txt");
    }

    #[test]
    fn hostile_corpus_query_keys_are_refused_whatever_the_allow_list() {
        let mut wide = http(ApprovalPolicy::Auto);
        wide.allowed_methods = vec!["GET".into(), "POST".into()];
        wide.allowed_paths = vec![".*".into()];
        let ordinary: BTreeMap<String, String> = [
            ("page".to_string(), "2".to_string()),
            ("q".into(), "a b\nc".into()),
        ]
        .into();
        check_request(
            &wide,
            &Request::Http {
                method: "POST",
                path: "/x",
                query: Some(&ordinary),
                body: None,
            },
        )
        .unwrap();
        let n = assert_all_refused(
            "tests/corpus/queries.txt",
            include_str!("../../tests/corpus/queries.txt"),
            &wide,
            |key| {
                let query = Box::leak(Box::new(BTreeMap::from([(
                    key.to_string(),
                    "DELETE".to_string(),
                )])));
                Request::Http {
                    method: "POST",
                    path: "/x",
                    query: Some(query),
                    body: None,
                }
            },
        );
        assert!(n >= 20, "only {n} entries in tests/corpus/queries.txt");
    }

    /// Laravel reads `_method` from a JSON body too.
    #[test]
    fn method_override_in_the_json_body_is_refused() {
        let mut wide = http(ApprovalPolicy::Auto);
        wide.allowed_methods = vec!["POST".into()];
        wide.allowed_paths = vec![".*".into()];
        let post = |body: &Value| {
            check_request(
                &wide,
                &Request::Http {
                    method: "POST",
                    path: "/x",
                    query: None,
                    body: Some(body),
                },
            )
        };
        for body in [
            serde_json::json!({ "_method": "DELETE" }),
            serde_json::json!({ "title": "x", "X-HTTP-Method-Override": "DELETE" }),
            serde_json::json!({ ".method": "DELETE" }),
        ] {
            let err = post(&body).unwrap_err().to_string();
            assert!(err.contains("override the HTTP method"), "{body}: {err}");
        }
        // Only top-level keys count; nested data is the upstream's business.
        post(&serde_json::json!({ "data": { "_method": "x" }, "method": "card" })).unwrap();
        post(&serde_json::json!(["_method"])).unwrap();
    }

    #[test]
    fn corpus_escapes() {
        use crate::testutil::{corpus, unescape};
        assert_eq!(
            unescape(r"a\\b\n\t\x00\x20\u{FF0F}\{z*3}", 1),
            "a\\b\n\t\0 ／zzz"
        );
        let entries = corpus("# comment\n\n  # empty input (since v0.1.0)\nx#y  # z (since v1)\n");
        assert_eq!(entries[0].1, "");
        assert_eq!(entries[1].1, "x#y");
    }
}
