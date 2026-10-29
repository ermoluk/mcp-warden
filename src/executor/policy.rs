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
            Request::Sftp { .. } => "sftp_transfer",
            Request::Db { .. } => "db_query",
        }
    }

    /// The preset kind this call needs, as users write it in `type = …`.
    fn needs(&self) -> &'static str {
        match self {
            Request::Http { .. } => "http",
            Request::Ssh { .. } | Request::Sftp { .. } => "ssh",
            Request::Db { .. } => "database (postgres / mysql / redis)",
        }
    }

    fn fits(&self, kind: PresetType) -> bool {
        match self {
            Request::Http { .. } => kind == PresetType::Http,
            Request::Ssh { .. } | Request::Sftp { .. } => kind == PresetType::Ssh,
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
        Request::Http { method, path, .. } => {
            super::http::validated_url(preset, &method.to_uppercase(), path).map(drop)
        }
        Request::Ssh { command } => super::ssh::validate_command(preset, command),
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
    match preset.approval {
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

    // -------- hostile-input corpus --------

    /// `tests/corpus/*.txt` entries as `(line, input, note)`. The format is
    /// described at the top of each file.
    fn corpus(text: &str) -> Vec<(usize, String, String)> {
        text.lines()
            .enumerate()
            .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
            .map(|(i, line)| {
                let (raw, note) = line
                    .split_once("  # ")
                    .unwrap_or_else(|| panic!("line {}: no `  # <note>`: {line:?}", i + 1));
                assert!(
                    note.contains("(since v"),
                    "line {}: the note must say `(since vX.Y.Z)`: {line:?}",
                    i + 1
                );
                (i + 1, unescape(raw, i + 1), note.to_string())
            })
            .collect()
    }

    fn unescape(raw: &str, line: usize) -> String {
        let mut out = String::new();
        let mut chars = raw.chars();
        let bad = |what: &str| -> ! { panic!("line {line}: {what} in {raw:?}") };
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('\\') => out.push('\\'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('x') => {
                    let hex: String = chars.by_ref().take(2).collect();
                    let byte = u8::from_str_radix(&hex, 16).unwrap_or_else(|_| bad("bad \\xNN"));
                    out.push(char::from(byte));
                }
                Some('u') => {
                    if chars.next() != Some('{') {
                        bad("\\u without {");
                    }
                    let hex: String = chars.by_ref().take_while(|c| *c != '}').collect();
                    let code = u32::from_str_radix(&hex, 16).unwrap_or_else(|_| bad("bad \\u{}"));
                    out.push(char::from_u32(code).unwrap_or_else(|| bad("bad \\u{}")));
                }
                Some('{') => {
                    let spec: String = chars.by_ref().take_while(|c| *c != '}').collect();
                    let (c, n) = spec.split_once('*').unwrap_or_else(|| bad("bad \\{c*N}"));
                    let n: usize = n.parse().unwrap_or_else(|_| bad("bad \\{c*N}"));
                    out.push_str(&c.repeat(n));
                }
                _ => bad("unknown escape"),
            }
        }
        out
    }

    /// Every entry of `text` must be refused for `preset`; returns how many
    /// were checked.
    fn assert_all_refused(
        file: &str,
        text: &str,
        preset: &Preset,
        req: impl Fn(&str) -> Request,
    ) -> usize {
        let entries = corpus(text);
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
    fn corpus_escapes() {
        assert_eq!(
            unescape(r"a\\b\n\t\x00\x20\u{FF0F}\{z*3}", 1),
            "a\\b\n\t\0 ／zzz"
        );
        let entries = corpus("# comment\n\n  # empty input (since v0.1.0)\nx#y  # z (since v1)\n");
        assert_eq!(entries[0].1, "");
        assert_eq!(entries[1].1, "x#y");
    }
}
