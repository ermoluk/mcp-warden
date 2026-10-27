//! Does this value look like a secret? Known token formats are reported
//! with high confidence; a long value under a secret-sounding name with
//! medium confidence. Placeholders and references are never reported.
//!
//! Output never carries secret material: `redact` keeps at most a token
//! type's public prefix (`ghp_`, `sk-ant-`, …) and the length.

use regex::Regex;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub kind: &'static str,
    pub confidence: Confidence,
    /// `ghp_…, 40 chars` — never more than the public prefix and a length.
    pub redacted: String,
}

/// Token formats: (kind, public prefix shown when redacted, pattern).
/// Order matters where prefixes overlap (`sk-ant-` before `sk-`).
static KNOWN: LazyLock<Vec<(&'static str, &'static str, Regex)>> = LazyLock::new(|| {
    [
        (
            "GitHub token",
            "github_pat_",
            r"github_pat_[A-Za-z0-9_]{22,}",
        ),
        ("GitHub token", "gh?_", r"gh[pousr]_[A-Za-z0-9]{36,}"),
        ("GitLab token", "glpat-", r"glpat-[A-Za-z0-9_\-]{20,}"),
        (
            "Anthropic API key",
            "sk-ant-",
            r"sk-ant-[A-Za-z0-9_\-]{20,}",
        ),
        ("Stripe key", "sk_", r"[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"),
        ("OpenAI API key", "sk-", r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}"),
        ("Slack token", "xox?-", r"xox[abprs]-[A-Za-z0-9\-]{10,}"),
        ("AWS access key id", "AKIA", r"AKIA[0-9A-Z]{16}"),
        ("Google API key", "AIza", r"AIza[0-9A-Za-z_\-]{35}"),
        ("Linear API key", "lin_api_", r"lin_api_[A-Za-z0-9]{20,}"),
        ("Notion token", "ntn_", r"(?:ntn_|secret_)[A-Za-z0-9]{20,}"),
        ("npm token", "npm_", r"npm_[A-Za-z0-9]{36}"),
        ("Hugging Face token", "hf_", r"hf_[A-Za-z0-9]{30,}"),
        ("DigitalOcean token", "dop_v1_", r"dop_v1_[a-f0-9]{64}"),
    ]
    .into_iter()
    .map(|(kind, prefix, re)| (kind, prefix, Regex::new(re).expect("static pattern")))
    .collect()
});

/// Words that make a key name sound like it holds a secret.
const SECRET_WORDS: &[&str] = &[
    "token",
    "secret",
    "key",
    "password",
    "passwd",
    "pat",
    "auth",
    "credential",
];

/// Shortest value reported on the strength of its key name alone.
const MIN_NAMED_LEN: usize = 12;

/// Inspect one value, with the key it sits under if it has one.
pub fn detect(key: Option<&str>, value: &str) -> Option<Detection> {
    let value = value.trim();
    if value.is_empty() || is_placeholder(value) {
        return None;
    }
    for (kind, prefix, re) in KNOWN.iter() {
        if let Some(m) = re.find(value) {
            let token = m.as_str();
            if is_placeholder(token) || looks_fake(&token[prefix_len(token, prefix)..]) {
                continue;
            }
            return Some(Detection {
                kind,
                confidence: Confidence::High,
                redacted: format!(
                    "{}…, {} chars",
                    shown_prefix(token, prefix),
                    token.chars().count()
                ),
            });
        }
    }
    let key = key?.to_ascii_lowercase();
    let named = SECRET_WORDS.iter().any(|w| key.contains(w));
    if named && value.chars().count() >= MIN_NAMED_LEN && !looks_like_plain_setting(value) {
        return Some(Detection {
            kind: "possible secret",
            confidence: Confidence::Medium,
            redacted: format!("…, {} chars", value.chars().count()),
        });
    }
    None
}

/// The public part of a token's prefix as it appears (`ghp_` for `gh?_`).
fn shown_prefix<'a>(token: &'a str, prefix: &str) -> &'a str {
    &token[..prefix_len(token, prefix)]
}

fn prefix_len(token: &str, prefix: &str) -> usize {
    // `?` in a prefix stands for one character; the rest is literal ASCII.
    prefix.len().min(token.len())
}

/// `${VAR}`, `$VAR`, `{{…}}`, `<…>`, `your-token`, `changeme`, `op://…`, …
fn is_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    value.starts_with("${")
        || value.starts_with("{{")
        || (value.starts_with('<') && value.ends_with('>'))
        || (value.starts_with('$')
            && value[1..]
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
        || lower.starts_with("op://")
        || [
            "your",
            "example",
            "changeme",
            "placeholder",
            "redacted",
            "xxxx",
            "dummy",
        ]
        .iter()
        .any(|w| lower.contains(w))
}

/// A token body made of one repeated character is a sample, not a key.
fn looks_fake(body: &str) -> bool {
    let mut chars = body.chars();
    chars.next().is_some_and(|first| chars.all(|c| c == first))
}

/// Paths, URLs without credentials, booleans and numbers are settings.
fn looks_like_plain_setting(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with("~/")
        || value.starts_with("./")
        || value.starts_with("http://")
        || value.starts_with("https://")
        || value.parse::<f64>().is_ok()
        || matches!(value, "true" | "false")
        || looks_fake(value)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A well-formed fake token: `prefix` + `len` mixed characters. Built
    /// at runtime so no token-shaped literal sits in the source.
    pub(crate) fn fake(prefix: &str, len: usize) -> String {
        const ALPHABET: &[u8] = b"Zq8Lm3RtW0xKp7Vb2Nc5Hd9Jf1Gs4Ya6Ue";
        let body: String = (0..len)
            .map(|i| ALPHABET[(i * 7 + 3) % ALPHABET.len()] as char)
            .collect();
        format!("{prefix}{body}")
    }

    fn kind(value: &str) -> Option<&'static str> {
        detect(None, value).map(|d| d.kind)
    }

    #[test]
    fn known_formats_are_high_confidence() {
        let cases = [
            (fake(&["gh", "p_"].concat(), 36), "GitHub token"),
            (fake(&["github", "_pat_"].concat(), 60), "GitHub token"),
            (fake(&["gl", "pat-"].concat(), 20), "GitLab token"),
            (fake(&["sk-", "ant-"].concat(), 40), "Anthropic API key"),
            (fake(&["sk-", "proj-"].concat(), 40), "OpenAI API key"),
            (fake(&["sk", "_live_"].concat(), 24), "Stripe key"),
            (fake(&["xo", "xb-"].concat(), 30), "Slack token"),
            (fake(&["lin", "_api_"].concat(), 30), "Linear API key"),
            (fake(&["nt", "n_"].concat(), 30), "Notion token"),
            (fake(&["hf", "_"].concat(), 34), "Hugging Face token"),
        ];
        for (value, want) in &cases {
            let d = detect(Some("ANY"), value).unwrap_or_else(|| panic!("{want}"));
            assert_eq!(d.kind, *want);
            assert_eq!(d.confidence, Confidence::High);
        }
    }

    #[test]
    fn tokens_inside_longer_values_are_found() {
        let token = fake(&["gh", "p_"].concat(), 36);
        assert_eq!(kind(&format!("Bearer {token}")), Some("GitHub token"));
        assert_eq!(kind(&format!("--api-key={token}")), Some("GitHub token"));
    }

    #[test]
    fn redaction_keeps_only_the_public_prefix_and_length() {
        let token = fake(&["gh", "p_"].concat(), 36);
        let d = detect(None, &token).unwrap();
        assert_eq!(d.redacted, format!("{}…, 40 chars", ["gh", "p_"].concat()));
        let named = detect(Some("MY_API_KEY"), "q8Zr2LmP0vXk3TnB").unwrap();
        assert_eq!(named.redacted, "…, 16 chars");
        assert!(!named.redacted.contains("q8Z"));
    }

    #[test]
    fn secret_sounding_names_are_medium_confidence() {
        for key in [
            "MY_API_KEY",
            "db_password",
            "Authorization",
            "SERVICE_TOKEN",
        ] {
            let d = detect(Some(key), "q8Zr2LmP0vXk3TnB").unwrap_or_else(|| panic!("{key}"));
            assert_eq!(d.confidence, Confidence::Medium);
        }
        assert_eq!(detect(Some("LOG_LEVEL"), "q8Zr2LmP0vXk3TnB"), None);
        assert_eq!(detect(Some("API_KEY"), "short"), None);
    }

    #[test]
    fn placeholders_references_and_settings_are_ignored() {
        let sample = format!("{}{}", ["sk-", "proj-"].concat(), "x".repeat(40));
        for value in [
            "${GITHUB_TOKEN}",
            "$GITHUB_TOKEN",
            "{{ secrets.TOKEN }}",
            "<your-token-here>",
            "your_api_key_goes_here",
            "op://vault/github/token",
            "changeme-changeme",
            sample.as_str(),
            "/Users/me/.config/token-file",
            "https://example.org/token",
            "123456789012345",
            "",
        ] {
            assert_eq!(detect(Some("API_TOKEN"), value), None, "{value:?}");
        }
    }
}
