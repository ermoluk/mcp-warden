//! Would this call be allowed? The one place that decides, shared by the
//! tools and by `mcp-warden preset test`, so the simulator and the server
//! cannot disagree. Every check here is pure: no secret is read and nothing
//! is sent.

use mcp_warden_core::config::{ApprovalPolicy, Preset, PresetType};
use mcp_warden_core::error::{Result, WardenError};

/// A call as the agent would make it.
#[derive(Debug, Clone, Copy)]
pub enum Request<'a> {
    Http { method: &'a str, path: &'a str },
    Ssh { command: &'a str },
    Sftp { remote: &'a str, local: &'a str },
    Db { query: &'a str, params: usize },
}

impl Request<'_> {
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

/// Check a request against the preset's kind and allow-lists. Runs before
/// any credential is touched (invariant 3).
pub fn check_request(preset: &Preset, req: &Request) -> Result<()> {
    if !req.fits(preset.preset_type) {
        return Err(WardenError::Validation(format!(
            "preset '{}' is not an {} preset; {} needs one",
            preset.name,
            req.needs(),
            req.tool()
        )));
    }
    match *req {
        Request::Http { method, path } => {
            super::http::validated_url(preset, &method.to_uppercase(), path).map(drop)
        }
        Request::Ssh { command } => super::ssh::validate_command(preset, command),
        Request::Sftp { remote, local } => super::sftp::validate_transfer(preset, remote, local),
        Request::Db { query, params } => super::db::find_query(preset, query, params).map(drop),
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

/// Simulate a call in the order the server checks it: the request first,
/// then the approval policy.
pub fn simulate(preset: &Preset, req: &Request) -> Verdict {
    if let Err(e) = check_request(preset, req) {
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
        let req = Request::Http {
            method: "get",
            path: "/repos/o/r",
        };
        assert!(check_request(&http(ApprovalPolicy::Auto), &req).is_ok());
    }

    #[test]
    fn http_refuses_method_path_and_encoded_slash() {
        let p = http(ApprovalPolicy::Auto);
        for (method, path) in [
            ("DELETE", "/repos/o/r"),
            ("GET", "/repos/o/r/collaborators"),
            ("GET", "/repos/o/x%2Fcollaborators"),
            ("GET", "/repos/o/../admin"),
        ] {
            let req = Request::Http { method, path };
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
        let ok = Request::Sftp {
            remote: "/srv/app/x.log",
            local: "/tmp/x.log",
        };
        assert!(check_request(&p, &ok).is_ok());
        let bad = Request::Sftp {
            remote: "/etc/shadow",
            local: "/tmp/x",
        };
        assert!(check_request(&p, &bad).is_err());
    }

    #[test]
    fn db_checks_query_name_and_param_count() {
        let p = db();
        let ok = Request::Db {
            query: "user_by_id",
            params: 1,
        };
        assert!(check_request(&p, &ok).is_ok());
        for (query, params) in [("drop_all", 0), ("user_by_id", 2)] {
            assert!(check_request(&p, &Request::Db { query, params }).is_err());
        }
    }

    #[test]
    fn wrong_preset_kind_is_refused() {
        let err = check_request(
            &ssh(),
            &Request::Http {
                method: "GET",
                path: "/",
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("not an http preset"), "{err}");
        assert!(
            check_request(
                &http(ApprovalPolicy::Auto),
                &Request::Db {
                    query: "q",
                    params: 0
                }
            )
            .is_err()
        );
    }

    #[test]
    fn simulate_reports_policy_after_the_request_passes() {
        let req = Request::Http {
            method: "GET",
            path: "/repos/o/r",
        };
        assert_eq!(
            simulate(&http(ApprovalPolicy::Auto), &req),
            Verdict::Allowed {
                policy: ApprovalPolicy::Auto,
                window_seconds: None
            }
        );
        let mut prompt = http(ApprovalPolicy::Prompt);
        prompt.approval_window_seconds = Some(600);
        assert_eq!(
            simulate(&prompt, &req),
            Verdict::Allowed {
                policy: ApprovalPolicy::Prompt,
                window_seconds: Some(600)
            }
        );
        assert_eq!(
            simulate(&http(ApprovalPolicy::Deny), &req),
            Verdict::Refused("preset policy is deny".into())
        );
    }

    #[test]
    fn simulate_reports_validation_before_policy() {
        let req = Request::Http {
            method: "DELETE",
            path: "/repos/o/r",
        };
        match simulate(&http(ApprovalPolicy::Deny), &req) {
            Verdict::Refused(why) => assert!(why.contains("DELETE"), "{why}"),
            other => panic!("{other:?}"),
        }
    }
}
