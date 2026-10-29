use mcp_warden_core::config::{ApprovalPolicy, Auth, Preset, PresetType};

/// One built-in scaffold template: a name, a one-line description, a default
/// keychain secret name, and a constructor that builds the [`Preset`] given
/// the user-chosen preset name and secret name.
pub struct Template {
    pub name: &'static str,
    pub description: &'static str,
    pub default_secret_name: &'static str,
    pub build: fn(preset_name: &str, secret_name: &str) -> Preset,
    /// Comment lines `scaffold --dry-run` prints above a template that ships
    /// without `allowed_paths`: an example allow-list and token advice.
    /// Empty for templates that list their paths.
    pub open_paths_note: &'static [&'static str],
}

pub const TEMPLATES: &[Template] = &[
    Template {
        name: "github-read",
        description: "GitHub API (read-only), prompt per call",
        default_secret_name: "gh_pat",
        build: github_read,
        open_paths_note: &[
            "  allowed_paths = [\"/user/repos\", \"/repos/OWNER/[^/]+\"]",
            "A classic PAT lets this preset read every private repo the token can see.",
            "Prefer a fine-grained PAT limited to specific repositories, read-only.",
            "Approval stays `prompt` until you narrow allowed_paths; then set it to auto if you want.",
        ],
    },
    Template {
        name: "github-write",
        description: "GitHub API write (repos/orgs), prompt per call",
        default_secret_name: "gh_pat",
        build: github_write,
        open_paths_note: &[],
    },
    Template {
        name: "notion-read",
        description: "Notion API read (databases/pages/search), auto-approve",
        default_secret_name: "notion_token",
        build: notion_read,
        open_paths_note: &[],
    },
    Template {
        name: "stripe-read",
        description: "Stripe API read-only, prompt per call",
        default_secret_name: "stripe_key",
        build: stripe_read,
        open_paths_note: &[
            "  allowed_paths = [\"/customers(/[^/]+)?\", \"/charges(/[^/]+)?\"]",
            "Prefer a restricted key (rk_...) with read-only permissions over a secret key.",
        ],
    },
    Template {
        name: "openai-chat",
        description: "OpenAI chat completions + embeddings, prompt per call",
        default_secret_name: "openai_api_key",
        build: openai_chat,
        open_paths_note: &[],
    },
    Template {
        name: "anthropic-messages",
        description: "Anthropic Messages API, prompt per call",
        default_secret_name: "anthropic_api_key",
        build: anthropic_messages,
        open_paths_note: &[],
    },
    Template {
        name: "gitea-read",
        description: "Gitea API read-only, prompt per call",
        default_secret_name: "gitea_token",
        build: gitea_read,
        open_paths_note: &[
            "  allowed_paths = [\"/api/v1/user/repos\", \"/api/v1/repos/OWNER/[^/]+\"]",
            "Prefer a token with read-only scopes (e.g. read:repository) over an all-access one.",
            "Approval stays `prompt` until you narrow allowed_paths; then set it to auto if you want.",
        ],
    },
    Template {
        name: "cloudflare-dns",
        description: "Cloudflare DNS zones (read/write), prompt per call",
        default_secret_name: "cloudflare_api_token",
        build: cloudflare_dns,
        open_paths_note: &[],
    },
    Template {
        name: "gitlab-read",
        description: "GitLab API read (projects by numeric id, issues, MRs), prompt per call",
        default_secret_name: "gitlab_token",
        build: gitlab_read,
        open_paths_note: &[],
    },
    Template {
        name: "linear",
        description: "Linear GraphQL API (queries AND mutations), prompt per call",
        default_secret_name: "linear_api_key",
        build: linear,
        open_paths_note: &[],
    },
    Template {
        name: "jira-read",
        description: "Jira Cloud REST read (issues, search, projects), prompt per call",
        default_secret_name: "jira_api_token",
        build: jira_read,
        open_paths_note: &[],
    },
    Template {
        name: "slack-read",
        description: "Slack Web API read (channels, history, users), prompt per call",
        default_secret_name: "slack_bot_token",
        build: slack_read,
        open_paths_note: &[],
    },
    Template {
        name: "vercel-read",
        description: "Vercel API read (projects, deployments), prompt per call",
        default_secret_name: "vercel_token",
        build: vercel_read,
        open_paths_note: &[],
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
    }
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

    /// Would `GET`/`POST path` through template `name` be allowed?
    fn allows(name: &str, method: &str, path: &str) -> bool {
        let t = find(name).unwrap();
        let p = (t.build)(t.name, t.default_secret_name);
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
            let p = (t.build)(t.name, t.default_secret_name);
            assert_eq!(p.name, t.name);
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
        for t in TEMPLATES {
            let p = (t.build)(t.name, t.default_secret_name);
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
            let p = (t.build)(t.name, t.default_secret_name);
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
