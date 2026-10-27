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

#[cfg(test)]
mod tests {
    use super::*;

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
