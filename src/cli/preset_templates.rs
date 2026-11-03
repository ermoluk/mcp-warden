use mcp_warden_core::config::{
    ApprovalPolicy, Auth, ClientAuth, NamedCommand, OAuth2Grant, ParamSpec, Preset, PresetType,
};

/// What the user picked when scaffolding: the preset's name, the keychain
/// entry it reads, and for SSH templates the host and user.
pub struct Choices<'a> {
    pub name: &'a str,
    pub secret_name: &'a str,
    pub host: &'a str,
    pub user: &'a str,
}

/// One built-in scaffold template: a name, a one-line description, a default
/// keychain secret name, and a constructor that builds the [`Preset`] from
/// the user's [`Choices`].
pub struct Template {
    pub name: &'static str,
    pub description: &'static str,
    pub default_secret_name: &'static str,
    pub build: fn(&Choices) -> Preset,
    /// SSH templates need `--host` and `--user`.
    pub needs_host: bool,
    /// Comment lines `scaffold --dry-run` prints above a template that ships
    /// without `allowed_paths`: an example allow-list and token advice.
    /// Empty for templates that list their paths.
    pub open_paths_note: &'static [&'static str],
    /// Placeholders to replace after scaffolding (a client id, a bucket),
    /// printed with the result. Empty when there are none.
    pub setup_note: &'static [&'static str],
}

pub const TEMPLATES: &[Template] = &[
    Template {
        name: "github-read",
        description: "GitHub API (read-only), prompt per call",
        default_secret_name: "gh_pat",
        build: |c| github_read(c.name, c.secret_name),
        needs_host: false,
        open_paths_note: &[
            "  allowed_paths = [\"/user/repos\", \"/repos/OWNER/[^/]+\"]",
            "A classic PAT lets this preset read every private repo the token can see.",
            "Prefer a fine-grained PAT limited to specific repositories, read-only.",
            "Approval stays `prompt` until you narrow allowed_paths; then set it to auto if you want.",
        ],
        setup_note: &[],
    },
    Template {
        name: "github-write",
        description: "GitHub API write (repos/orgs), prompt per call",
        default_secret_name: "gh_pat",
        build: |c| github_write(c.name, c.secret_name),
        needs_host: false,
        open_paths_note: &[],
        setup_note: &[],
    },
    Template {
        name: "notion-read",
        description: "Notion API read (databases/pages/search), auto-approve",
        default_secret_name: "notion_token",
        build: |c| notion_read(c.name, c.secret_name),
        needs_host: false,
        open_paths_note: &[],
        setup_note: &[],
    },
    Template {
        name: "stripe-read",
        description: "Stripe API read-only, prompt per call",
        default_secret_name: "stripe_key",
        build: |c| stripe_read(c.name, c.secret_name),
        needs_host: false,
        open_paths_note: &[
            "  allowed_paths = [\"/customers(/[^/]+)?\", \"/charges(/[^/]+)?\"]",
            "Prefer a restricted key (rk_...) with read-only permissions over a secret key.",
        ],
        setup_note: &[],
    },
    Template {
        name: "openai-chat",
        description: "OpenAI chat completions + embeddings, prompt per call",
        default_secret_name: "openai_api_key",
        build: |c| openai_chat(c.name, c.secret_name),
        needs_host: false,
        open_paths_note: &[],
        setup_note: &[],
    },
    Template {
        name: "anthropic-messages",
        description: "Anthropic Messages API, prompt per call",
        default_secret_name: "anthropic_api_key",
        build: |c| anthropic_messages(c.name, c.secret_name),
        needs_host: false,
        open_paths_note: &[],
        setup_note: &[],
    },
    Template {
        name: "gitea-read",
        description: "Gitea API read-only, prompt per call",
        default_secret_name: "gitea_token",
        build: |c| gitea_read(c.name, c.secret_name),
        needs_host: false,
        open_paths_note: &[
            "  allowed_paths = [\"/api/v1/user/repos\", \"/api/v1/repos/OWNER/[^/]+\"]",
            "Prefer a token with read-only scopes (e.g. read:repository) over an all-access one.",
            "Approval stays `prompt` until you narrow allowed_paths; then set it to auto if you want.",
        ],
        setup_note: &[],
    },
    Template {
        name: "cloudflare-dns",
        description: "Cloudflare DNS zones (read/write), prompt per call",
        default_secret_name: "cloudflare_api_token",
        build: |c| cloudflare_dns(c.name, c.secret_name),
        needs_host: false,
        open_paths_note: &[],
        setup_note: &[],
    },
    Template {
        name: "gitlab-read",
        description: "GitLab API read (projects by numeric id, issues, MRs), prompt per call",
        default_secret_name: "gitlab_token",
        build: |c| gitlab_read(c.name, c.secret_name),
        needs_host: false,
        open_paths_note: &[],
        setup_note: &[],
    },
    Template {
        name: "linear",
        description: "Linear GraphQL API (queries AND mutations), prompt per call",
        default_secret_name: "linear_api_key",
        build: |c| linear(c.name, c.secret_name),
        needs_host: false,
        open_paths_note: &[],
        setup_note: &[],
    },
    Template {
        name: "jira-read",
        description: "Jira Cloud REST read (issues, search, projects), prompt per call",
        default_secret_name: "jira_api_token",
        build: |c| jira_read(c.name, c.secret_name),
        needs_host: false,
        open_paths_note: &[],
        setup_note: &[],
    },
    Template {
        name: "slack-read",
        description: "Slack Web API read (channels, history, users), prompt per call",
        default_secret_name: "slack_bot_token",
        build: |c| slack_read(c.name, c.secret_name),
        needs_host: false,
        open_paths_note: &[],
        setup_note: &[],
    },
    Template {
        name: "vercel-read",
        description: "Vercel API read (projects, deployments), prompt per call",
        default_secret_name: "vercel_token",
        build: |c| vercel_read(c.name, c.secret_name),
        needs_host: false,
        open_paths_note: &[],
        setup_note: &[],
    },
    Template {
        name: "google-maps",
        description: "Google Maps Platform web services (geocoding, places, distances), key in the query",
        default_secret_name: "gmaps_key",
        build: |c| google_maps(c.name, c.secret_name),
        needs_host: false,
        open_paths_note: &[],
        setup_note: &[
            "Restrict the key in Google Cloud Console to these APIs (and, if you can, to your IP).",
        ],
    },
    Template {
        name: "google-drive-read",
        description: "Google Drive (read-only) with OAuth2: a fresh access token per call",
        default_secret_name: "gdrive",
        build: |c| google_drive_read(c.name, c.secret_name),
        needs_host: false,
        open_paths_note: &[],
        setup_note: &[
            "Replace client_id with your OAuth client's id (Google Cloud Console → Credentials).",
            "Get a refresh token for the drive.readonly scope (e.g. with the OAuth Playground),",
            "then store the client secret and the refresh token with the commands above.",
        ],
    },
    Template {
        name: "aws-s3-read",
        description: "Amazon S3 (read-only: list and get objects), signed with AWS SigV4",
        default_secret_name: "aws_s3",
        build: |c| aws_s3_read(c.name, c.secret_name),
        needs_host: false,
        open_paths_note: &[],
        setup_note: &[
            "Replace your-bucket and eu-central-1 in base_url and region with your bucket's.",
            "Use an IAM user or role limited to s3:GetObject and s3:ListBucket on that bucket.",
        ],
    },
    Template {
        name: "ssh-deploy",
        description: "SSH deploy host: named commands for status, logs, restart and pull",
        default_secret_name: "deploy_key",
        build: ssh_deploy,
        needs_host: true,
        open_paths_note: &[],
        setup_note: &[],
    },
];

pub fn find(name: &str) -> Option<&'static Template> {
    TEMPLATES.iter().find(|t| t.name == name)
}

fn http_preset(
    name: &str,
    description: &str,
    base_url: &str,
    auth: Auth,
    allowed_methods: &[&str],
    allowed_paths: &[&str],
    approval: ApprovalPolicy,
) -> Preset {
    Preset {
        name: name.to_string(),
        preset_type: PresetType::Http,
        description: description.to_string(),
        base_url: Some(base_url.to_string()),
        auth: Some(auth),
        allowed_paths: allowed_paths.iter().map(|s| s.to_string()).collect(),
        allowed_methods: allowed_methods.iter().map(|s| s.to_string()).collect(),
        approval,
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
        max_response_bytes: None,
        response_fields: vec![],
        allowed_local_paths: vec![],
        max_output_bytes: None,
        expose_as_tools: false,
        commands: vec![],
    }
}

/// An SSH host the agent drives only through named commands: no
/// `allowed_commands`, so `ssh_exec` refuses everything, and four commands
/// with fixed templates. The unit names and the checkout path are
/// placeholders to edit.
fn ssh_deploy(c: &Choices) -> Preset {
    let units = || ParamSpec::Enum {
        values: vec!["app.service".into()],
    };
    let command =
        |name: &str, description: &str, template: &str, params: Vec<(&str, ParamSpec)>| {
            NamedCommand {
                name: name.into(),
                description: description.into(),
                template: template.into(),
                params: params
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect(),
                approval: None,
                max_output_bytes: None,
            }
        };
    let commands = vec![
        command(
            "status",
            "Show whether a service is running",
            "systemctl status {unit} --no-pager",
            vec![("unit", units())],
        ),
        command(
            "logs",
            "Last N lines of a service's log",
            "journalctl -u {unit} -n {lines} --no-pager",
            vec![
                ("unit", units()),
                ("lines", ParamSpec::Int { min: 1, max: 500 }),
            ],
        ),
        command(
            "restart",
            "Restart a service",
            "sudo -n systemctl restart {unit}",
            vec![("unit", units())],
        ),
        command(
            "pull",
            "Fast-forward the checkout to its upstream branch",
            "git -C /srv/app pull --ff-only",
            vec![],
        ),
    ];
    Preset {
        name: c.name.to_string(),
        preset_type: PresetType::Ssh,
        description: "Deploy host (named commands only)".into(),
        base_url: None,
        auth: None,
        allowed_paths: vec![],
        allowed_methods: vec![],
        approval: ApprovalPolicy::Prompt,
        approval_window_seconds: None,
        host: Some(c.host.to_string()),
        user: Some(c.user.to_string()),
        port: None,
        secret: Some(c.secret_name.to_string()),
        allowed_commands: vec![],
        timeout_seconds: None,
        known_hosts: None,
        allow_sftp: false,
        sftp_allowed_paths: vec![],
        database: None,
        queries: vec![],
        expires_at: None,
        max_response_bytes: None,
        response_fields: vec![],
        allowed_local_paths: vec![],
        max_output_bytes: Some(65536),
        expose_as_tools: false,
        commands,
    }
}

fn google_maps(name: &str, secret_name: &str) -> Preset {
    http_preset(
        name,
        "Google Maps Platform web services",
        "https://maps.googleapis.com",
        Auth::Query {
            name: "key".into(),
            secret: secret_name.to_string(),
        },
        &["GET"],
        &[
            "/maps/api/geocode/json",
            "/maps/api/place/textsearch/json",
            "/maps/api/place/details/json",
            "/maps/api/distancematrix/json",
        ],
        ApprovalPolicy::Prompt,
    )
}

/// `secret_name` is a prefix: the client secret and the refresh token get
/// entries of their own.
fn google_drive_read(name: &str, secret_name: &str) -> Preset {
    http_preset(
        name,
        "Google Drive (read-only)",
        "https://www.googleapis.com",
        Auth::Oauth2 {
            grant: OAuth2Grant::RefreshToken,
            token_url: "https://oauth2.googleapis.com/token".into(),
            client_id: "YOUR_CLIENT_ID.apps.googleusercontent.com".into(),
            client_secret: Some(format!("{secret_name}_client_secret")),
            refresh_token: Some(format!("{secret_name}_refresh_token")),
            scopes: vec!["https://www.googleapis.com/auth/drive.readonly".into()],
            client_auth: ClientAuth::Basic,
        },
        &["GET"],
        &["/drive/v3/files", "/drive/v3/files/[A-Za-z0-9_-]+"],
        ApprovalPolicy::Prompt,
    )
}

/// `secret_name` is a prefix: the key id and the secret key get entries of
/// their own.
fn aws_s3_read(name: &str, secret_name: &str) -> Preset {
    http_preset(
        name,
        "Amazon S3 bucket (read-only)",
        "https://your-bucket.s3.eu-central-1.amazonaws.com",
        Auth::AwsSigv4 {
            region: "eu-central-1".into(),
            service: "s3".into(),
            access_key_id: format!("{secret_name}_access_key_id"),
            secret_access_key: format!("{secret_name}_secret_access_key"),
            session_token: None,
        },
        &["GET"],
        &["/", "/[A-Za-z0-9!_.*'()/-]+"],
        ApprovalPolicy::Prompt,
    )
}

fn bearer(secret_name: &str) -> Auth {
    Auth::Bearer {
        secret: secret_name.to_string(),
    }
}

fn github_read(name: &str, secret_name: &str) -> Preset {
    http_preset(
        name,
        "GitHub API (read-only)",
        "https://api.github.com",
        bearer(secret_name),
        &["GET"],
        &[],
        ApprovalPolicy::Prompt,
    )
}

fn github_write(name: &str, secret_name: &str) -> Preset {
    http_preset(
        name,
        "GitHub API (write to repos/orgs)",
        "https://api.github.com",
        bearer(secret_name),
        &["GET", "POST", "PATCH", "PUT", "DELETE"],
        &["/repos/", "/user/repos", "/orgs/"],
        ApprovalPolicy::Prompt,
    )
}

fn notion_read(name: &str, secret_name: &str) -> Preset {
    http_preset(
        name,
        "Notion API (read databases/pages/search)",
        "https://api.notion.com",
        bearer(secret_name),
        &["GET", "POST"],
        &["/v1/databases/", "/v1/pages/", "/v1/users/", "/v1/search"],
        ApprovalPolicy::Auto,
    )
}

fn stripe_read(name: &str, secret_name: &str) -> Preset {
    http_preset(
        name,
        "Stripe API (read-only)",
        "https://api.stripe.com/v1",
        bearer(secret_name),
        &["GET"],
        &[],
        ApprovalPolicy::Prompt,
    )
}

fn openai_chat(name: &str, secret_name: &str) -> Preset {
    http_preset(
        name,
        "OpenAI chat completions + embeddings",
        "https://api.openai.com",
        bearer(secret_name),
        &["POST"],
        &["/v1/chat/completions", "/v1/embeddings"],
        ApprovalPolicy::Prompt,
    )
}

fn anthropic_messages(name: &str, secret_name: &str) -> Preset {
    http_preset(
        name,
        "Anthropic Messages API",
        "https://api.anthropic.com",
        Auth::Header {
            name: "x-api-key".to_string(),
            secret: secret_name.to_string(),
            prefix: None,
        },
        &["POST"],
        &["/v1/messages"],
        ApprovalPolicy::Prompt,
    )
}

fn gitea_read(name: &str, secret_name: &str) -> Preset {
    let base_url = std::env::var("MCP_WARDEN_GITEA_BASE_URL")
        .unwrap_or_else(|_| "https://gitea.example.com".to_string());
    http_preset(
        name,
        "Gitea API (read-only)",
        &base_url,
        Auth::Header {
            name: "Authorization".to_string(),
            secret: secret_name.to_string(),
            prefix: Some("token ".to_string()),
        },
        &["GET"],
        &[],
        ApprovalPolicy::Prompt,
    )
}

fn cloudflare_dns(name: &str, secret_name: &str) -> Preset {
    http_preset(
        name,
        "Cloudflare DNS zones (read/write)",
        "https://api.cloudflare.com",
        bearer(secret_name),
        &["GET", "POST", "PATCH", "DELETE"],
        &["/client/v4/zones"],
        ApprovalPolicy::Prompt,
    )
}

/// Projects by numeric id only: a namespaced id (`group%2Fproject`) is two
/// segments once decoded, and a looser pattern would also reach endpoints
/// such as `/projects/:id/variables` that return CI secrets.
fn gitlab_read(name: &str, secret_name: &str) -> Preset {
    http_preset(
        name,
        "GitLab API (read-only)",
        "https://gitlab.com/api/v4",
        bearer(secret_name),
        &["GET"],
        &[
            "/user",
            "/projects",
            "/projects/[0-9]+",
            "/projects/[0-9]+/(issues|merge_requests)(/[0-9]+)?",
            "/projects/[0-9]+/repository/(tree|commits)",
        ],
        ApprovalPolicy::Prompt,
    )
}

/// One GraphQL endpoint carries both queries and mutations, so the path
/// allow-list cannot make it read-only: every call is a prompt.
fn linear(name: &str, secret_name: &str) -> Preset {
    http_preset(
        name,
        "Linear GraphQL API (queries and mutations)",
        "https://api.linear.app",
        // Personal API keys go in `Authorization` as-is, without `Bearer`.
        Auth::Header {
            name: "Authorization".to_string(),
            secret: secret_name.to_string(),
            prefix: None,
        },
        &["POST"],
        &["/graphql"],
        ApprovalPolicy::Prompt,
    )
}

/// Jira Cloud uses Basic auth with the account e-mail and an API token; the
/// site and e-mail come from `MCP_WARDEN_JIRA_BASE_URL` / `MCP_WARDEN_JIRA_EMAIL`
/// (like `gitea-read`), or edit them in the config afterwards.
fn jira_read(name: &str, secret_name: &str) -> Preset {
    let base_url = std::env::var("MCP_WARDEN_JIRA_BASE_URL")
        .unwrap_or_else(|_| "https://your-site.atlassian.net".to_string());
    let email =
        std::env::var("MCP_WARDEN_JIRA_EMAIL").unwrap_or_else(|_| "you@example.com".to_string());
    http_preset(
        name,
        "Jira Cloud REST API (read-only)",
        &base_url,
        Auth::Basic {
            username: email,
            secret: secret_name.to_string(),
        },
        &["GET"],
        &[
            "/rest/api/3/myself",
            "/rest/api/3/search/jql",
            "/rest/api/3/issue/[A-Z][A-Z0-9_]*-[0-9]+(/comment)?",
            "/rest/api/3/project(/[A-Z][A-Z0-9_]*)?",
        ],
        ApprovalPolicy::Prompt,
    )
}

/// Read methods of the Web API only; dots are escaped so `conversations.list`
/// can't match some other method name.
fn slack_read(name: &str, secret_name: &str) -> Preset {
    http_preset(
        name,
        "Slack Web API (read-only)",
        "https://slack.com",
        bearer(secret_name),
        &["GET"],
        &[
            r"/api/auth\.test",
            r"/api/conversations\.(list|info|history|replies)",
            r"/api/users\.(list|info)",
        ],
        ApprovalPolicy::Prompt,
    )
}

/// Projects and deployments, but not `/v9/projects/:id/env`, which returns
/// a project's environment variables (its secrets).
fn vercel_read(name: &str, secret_name: &str) -> Preset {
    http_preset(
        name,
        "Vercel API (read-only)",
        "https://api.vercel.com",
        bearer(secret_name),
        &["GET"],
        &[
            "/v2/user",
            "/v9/projects",
            "/v9/projects/[^/]+",
            "/v6/deployments",
            "/v13/deployments/[^/]+",
        ],
        ApprovalPolicy::Prompt,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::policy::{Request, check_request};

    fn build(t: &Template) -> Preset {
        (t.build)(&Choices {
            name: t.name,
            secret_name: t.default_secret_name,
            host: "deploy.example.com",
            user: "deploy",
        })
    }

    /// Would `GET`/`POST path` through template `name` be allowed?
    fn allows(name: &str, method: &str, path: &str) -> bool {
        let t = find(name).unwrap();
        let p = build(t);
        check_request(&p, &Request::http(method, path)).is_ok()
    }

    #[test]
    fn new_templates_allow_their_reads_and_nothing_secret() {
        for (template, method, path, want) in [
            ("gitlab-read", "GET", "/projects/42/issues/7", true),
            ("gitlab-read", "GET", "/projects/42/merge_requests", true),
            ("gitlab-read", "GET", "/projects/42/variables", false),
            (
                "gitlab-read",
                "GET",
                "/projects/group%2Fproject/variables",
                false,
            ),
            ("gitlab-read", "DELETE", "/projects/42", false),
            ("linear", "POST", "/graphql", true),
            ("linear", "GET", "/graphql", false),
            ("jira-read", "GET", "/rest/api/3/issue/PROJ-123", true),
            (
                "jira-read",
                "GET",
                "/rest/api/3/issue/PROJ-123/comment",
                true,
            ),
            ("jira-read", "GET", "/rest/api/3/search/jql", true),
            ("jira-read", "GET", "/rest/api/3/users/search", false),
            ("slack-read", "GET", "/api/conversations.history", true),
            ("slack-read", "GET", "/api/conversationsXhistory", false),
            ("slack-read", "GET", "/api/chat.postMessage", false),
            ("vercel-read", "GET", "/v9/projects/my-app", true),
            ("vercel-read", "GET", "/v9/projects/my-app/env", false),
            ("vercel-read", "GET", "/v13/deployments/dpl_123", true),
        ] {
            assert_eq!(
                allows(template, method, path),
                want,
                "{template} {method} {path}"
            );
        }
    }

    /// Each template is a valid config as scaffolded, once its secrets are
    /// in the keychain.
    #[test]
    fn every_template_validates_with_its_secrets() {
        use mcp_warden_core::keychain::KeychainStore;
        for t in TEMPLATES {
            let p = build(t);
            let kc = mcp_warden_core::keychain::memory::InMemoryKeychain::new();
            for name in p.secret_names() {
                kc.set(name, mcp_warden_core::secret::Secret::new("x".into()))
                    .unwrap();
            }
            let cfg = mcp_warden_core::config::Config {
                preset: vec![p],
                ..Default::default()
            };
            cfg.validate(&kc)
                .unwrap_or_else(|e| panic!("{}: {e}", t.name));
        }
    }

    #[test]
    fn the_new_auth_templates_reach_only_their_reads() {
        for (template, method, path, want) in [
            ("google-maps", "GET", "/maps/api/geocode/json", true),
            ("google-maps", "GET", "/maps/api/staticmap", false),
            ("google-drive-read", "GET", "/drive/v3/files/1AbC_d-9", true),
            ("google-drive-read", "DELETE", "/drive/v3/files/1AbC", false),
            ("google-drive-read", "GET", "/drive/v3/about", false),
            ("aws-s3-read", "GET", "/reports/2026/11.csv", true),
            ("aws-s3-read", "PUT", "/reports/x", false),
        ] {
            assert_eq!(
                allows(template, method, path),
                want,
                "{template} {method} {path}"
            );
        }
        let drive = build(find("google-drive-read").unwrap());
        assert_eq!(
            drive.secret_names(),
            ["gdrive_client_secret", "gdrive_refresh_token"]
        );
        let s3 = build(find("aws-s3-read").unwrap());
        assert_eq!(
            s3.secret_names(),
            ["aws_s3_access_key_id", "aws_s3_secret_access_key"]
        );
    }

    /// The SSH template is a valid config as scaffolded: its commands pass
    /// startup validation, and ssh_exec refuses everything.
    #[test]
    fn ssh_deploy_uses_named_commands_only() {
        use mcp_warden_core::keychain::KeychainStore;
        let p = build(find("ssh-deploy").unwrap());
        assert!(p.allowed_commands.is_empty());
        assert_eq!(p.approval, ApprovalPolicy::Prompt);
        let kc = mcp_warden_core::keychain::memory::InMemoryKeychain::new();
        kc.set(
            "deploy_key",
            mcp_warden_core::secret::Secret::new("k".into()),
        )
        .unwrap();
        let cfg = mcp_warden_core::config::Config {
            preset: vec![p.clone()],
            ..Default::default()
        };
        cfg.validate(&kc).unwrap();
        let lines: std::collections::BTreeMap<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({"unit": "app.service", "lines": 20}))
                .unwrap();
        assert_eq!(
            mcp_warden_core::commands::render(&p, "logs", &lines)
                .unwrap()
                .command,
            "journalctl -u app.service -n 20 --no-pager"
        );
        assert!(check_request(&p, &Request::Ssh { command: "id" }).is_err());
    }

    #[test]
    fn linear_sends_the_key_without_a_bearer_prefix() {
        let p = linear("linear", "linear_api_key");
        match p.auth.as_ref().unwrap() {
            Auth::Header { name, prefix, .. } => {
                assert_eq!(name, "Authorization");
                assert_eq!(prefix, &None);
            }
            other => panic!("expected header auth, got {other:?}"),
        }
    }

    #[test]
    fn jira_uses_basic_auth_with_the_account_email() {
        let p = jira_read("jira-read", "jira_api_token");
        assert!(matches!(p.auth, Some(Auth::Basic { .. })));
    }

    #[test]
    fn all_templates_build_and_have_unique_names() {
        let mut seen = std::collections::HashSet::new();
        for t in TEMPLATES {
            assert!(seen.insert(t.name), "duplicate template name {}", t.name);
            let p = build(t);
            assert_eq!(p.name, t.name);
            if t.needs_host {
                assert!(matches!(p.preset_type, PresetType::Ssh));
                assert!(p.host.is_some() && p.user.is_some() && p.secret.is_some());
                continue;
            }
            assert!(matches!(p.preset_type, PresetType::Http));
            assert!(p.base_url.is_some());
            assert!(p.auth.is_some());
            assert!(!p.allowed_methods.is_empty());
        }
    }

    #[test]
    fn github_read_uses_bearer_and_get_only() {
        let p = github_read("github-read", "gh_pat");
        assert_eq!(p.allowed_methods, vec!["GET"]);
        assert!(matches!(p.approval, ApprovalPolicy::Prompt));
        match p.auth.as_ref().unwrap() {
            Auth::Bearer { secret } => assert_eq!(secret, "gh_pat"),
            _ => panic!("expected Bearer"),
        }
    }

    #[test]
    fn templates_without_allowed_paths_explain_the_risk() {
        for t in TEMPLATES.iter().filter(|t| !t.needs_host) {
            let p = build(t);
            assert_eq!(
                p.allowed_paths.is_empty(),
                !t.open_paths_note.is_empty(),
                "template {}: open_paths_note must be set exactly when allowed_paths is empty",
                t.name
            );
        }
    }

    /// Invariant 4: a template that allows every path under `base_url` must
    /// not also skip the approval prompt. `auto` is for presets the user has
    /// narrowed with `allowed_paths`.
    #[test]
    fn templates_without_allowed_paths_are_never_auto() {
        for t in TEMPLATES {
            let p = build(t);
            if p.allowed_paths.is_empty() {
                assert!(
                    !matches!(p.approval, ApprovalPolicy::Auto),
                    "template {} has open allowed_paths and approval = auto",
                    t.name
                );
            }
        }
    }

    #[test]
    fn anthropic_uses_x_api_key_header() {
        let p = anthropic_messages("anthropic", "anthropic_api_key");
        match p.auth.as_ref().unwrap() {
            Auth::Header {
                name,
                secret,
                prefix,
            } => {
                assert_eq!(name, "x-api-key");
                assert_eq!(secret, "anthropic_api_key");
                assert!(prefix.is_none());
            }
            _ => panic!("expected Header"),
        }
    }

    #[test]
    fn cloudflare_dns_paths_restricted_to_zones() {
        let p = cloudflare_dns("cf", "cloudflare_api_token");
        assert_eq!(p.allowed_paths, vec!["/client/v4/zones".to_string()]);
    }
}
