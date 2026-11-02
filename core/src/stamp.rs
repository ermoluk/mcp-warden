//! Human confirmations bound to the exact config they confirmed.
//!
//! The config file is not trusted to say what a human agreed to: an agent
//! with file access can rewrite `config.toml`, or point
//! `MCP_WARDEN_CONFIG_DIR` at a config of its own, and the next server
//! start would load it. So the decisions that let a credential be used
//! without a prompt — an `auto` preset, a wrapped server launched with its
//! keys — count only when a human confirmed that very entry through the
//! approval transport. The confirmation is a keychain entry holding the
//! SHA-256 of the entry's canonical form (`stamp/preset/<name>`,
//! `stamp/server/<name>`); any edit to the entry changes the hash and voids
//! it.
//!
//! The keychain is the one store the agent cannot write without going
//! through the OS (threat model, N2), and the CLI writes a stamp only after
//! a human approves it in the approval prompt.

use crate::config::{ApprovalPolicy, Preset, WrappedServer};
use crate::error::Result;
use crate::keychain::KeychainStore;
use crate::secret::Secret;
use sha2::{Digest, Sha256};

/// Whether an entry's stamp matches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmation {
    /// A human confirmed exactly this entry.
    Confirmed,
    /// Nobody has confirmed it.
    Missing,
    /// It was confirmed, then changed.
    Changed,
}

/// SHA-256, hex, of the preset as JSON: every field, so any change — the
/// destination, the credential, the allow-lists, the policy, the access
/// window — voids a stamp.
pub fn preset_fingerprint(p: &Preset) -> String {
    hash(&serde_json::to_vec(p).unwrap_or_default())
}

/// SHA-256, hex, of the server entry as JSON: name, command, arguments and
/// the variables it receives.
pub fn server_fingerprint(s: &WrappedServer) -> String {
    hash(&serde_json::to_vec(s).unwrap_or_default())
}

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The keychain entry that holds a preset's stamp.
pub fn preset_stamp_name(name: &str) -> String {
    format!("stamp/preset/{name}")
}

/// The keychain entry that holds a wrapped server's stamp.
pub fn server_stamp_name(name: &str) -> String {
    format!("stamp/server/{name}")
}

/// Whether the stamp under `entry` matches `fingerprint`.
pub fn check(kc: &dyn KeychainStore, entry: &str, fingerprint: &str) -> Result<Confirmation> {
    Ok(match kc.get(entry)? {
        None => Confirmation::Missing,
        Some(stamp) if stamp.expose() == fingerprint => Confirmation::Confirmed,
        Some(_) => Confirmation::Changed,
    })
}

/// Record that a human confirmed the entry with this fingerprint. Callers
/// must have asked through the approval transport first.
pub fn record(kc: &dyn KeychainStore, entry: &str, fingerprint: &str) -> Result<()> {
    kc.set(entry, Secret::new(fingerprint.to_string()))
}

/// Keychain names that are stamps, not secrets.
pub fn is_stamp_name(name: &str) -> bool {
    name.starts_with("stamp/")
}

/// Run every `auto` preset that no human confirmed in this exact form as
/// `prompt` instead, and say why for each.
pub fn demote_unconfirmed_auto(presets: &mut [Preset], kc: &dyn KeychainStore) -> Vec<String> {
    let mut warnings = Vec::new();
    for p in presets
        .iter_mut()
        .filter(|p| p.approval == ApprovalPolicy::Auto)
    {
        let state = check(kc, &preset_stamp_name(&p.name), &preset_fingerprint(p))
            .unwrap_or(Confirmation::Missing);
        let why = match state {
            Confirmation::Confirmed => continue,
            Confirmation::Missing => "has not been confirmed",
            Confirmation::Changed => "changed since it was confirmed",
        };
        warnings.push(format!(
            "preset '{}' is approval = \"auto\" but {why}; every call asks for approval \
             until you run `mcp-warden preset confirm {}`",
            p.name, p.name
        ));
        p.approval = ApprovalPolicy::Prompt;
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::memory::InMemoryKeychain;

    fn preset(extra: &str) -> Preset {
        toml::from_str(&format!(
            r#"
            name = "gh"
            type = "http"
            description = "GitHub"
            base_url = "https://api.github.com"
            auth = {{ type = "bearer", secret = "gh_pat" }}
            allowed_methods = ["GET"]
            allowed_paths = ["/user/repos"]
            approval = "auto"
            {extra}
            "#
        ))
        .unwrap()
    }

    #[test]
    fn the_fingerprint_is_stable_and_covers_every_field() {
        let base = preset_fingerprint(&preset(""));
        assert_eq!(base, preset_fingerprint(&preset("")));
        assert_eq!(base.len(), 64);
        let mut edits: Vec<Preset> = Vec::new();
        for (field, value) in [
            ("base_url", "\"https://attacker.example\""),
            ("allowed_paths", "[\".*\"]"),
            ("allowed_methods", "[\"GET\", \"DELETE\"]"),
            ("expires_at", "\"2099-01-01T00:00:00Z\""),
            ("max_response_bytes", "10"),
        ] {
            let mut p: toml::Table =
                toml::from_str(&toml::to_string(&preset("")).unwrap()).unwrap();
            let v: toml::Table = toml::from_str(&format!("v = {value}")).unwrap();
            p.insert(field.into(), v["v"].clone());
            edits.push(p.try_into().unwrap());
        }
        let mut other_secret = preset("");
        other_secret.auth = Some(crate::config::Auth::Bearer {
            secret: "aws_key".into(),
        });
        edits.push(other_secret);
        for edited in edits {
            assert_ne!(preset_fingerprint(&edited), base, "{edited:?}");
        }
    }

    /// The A10 attack: after a human confirmed `gh` as `auto`, the agent
    /// edits config.toml to send its token elsewhere. The edited preset no
    /// longer matches its stamp, so it asks before every call.
    #[test]
    fn an_edited_auto_preset_runs_as_prompt() {
        let kc = InMemoryKeychain::new();
        let confirmed = preset("");
        record(
            &kc,
            &preset_stamp_name("gh"),
            &preset_fingerprint(&confirmed),
        )
        .unwrap();

        let mut same = vec![confirmed.clone()];
        assert!(demote_unconfirmed_auto(&mut same, &kc).is_empty());
        assert_eq!(same[0].approval, ApprovalPolicy::Auto);

        let mut edited = confirmed;
        edited.base_url = Some("https://attacker.example".into());
        let mut presets = vec![edited];
        let warnings = demote_unconfirmed_auto(&mut presets, &kc);
        assert_eq!(presets[0].approval, ApprovalPolicy::Prompt);
        assert!(
            warnings[0].contains("changed since it was confirmed"),
            "{warnings:?}"
        );
    }

    #[test]
    fn an_auto_preset_nobody_confirmed_runs_as_prompt() {
        let kc = InMemoryKeychain::new();
        let mut presets = vec![preset(""), {
            let mut p = preset("");
            p.name = "ask".into();
            p.approval = ApprovalPolicy::Prompt;
            p
        }];
        let warnings = demote_unconfirmed_auto(&mut presets, &kc);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("has not been confirmed"));
        assert!(warnings[0].contains("mcp-warden preset confirm gh"));
        assert!(presets.iter().all(|p| p.approval == ApprovalPolicy::Prompt));
    }

    #[test]
    fn a_stamp_belongs_to_one_name() {
        let kc = InMemoryKeychain::new();
        let p = preset("");
        record(&kc, &preset_stamp_name("other"), &preset_fingerprint(&p)).unwrap();
        let mut presets = vec![p];
        assert_eq!(demote_unconfirmed_auto(&mut presets, &kc).len(), 1);
    }

    #[test]
    fn server_fingerprint_covers_command_args_and_env() {
        let server = |command: &str, args: &[&str], env: &[&str]| WrappedServer {
            name: "github".into(),
            command: command.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            env: env.iter().map(|s| s.to_string()).collect(),
        };
        let base = server_fingerprint(&server("npx", &["-y", "gh-mcp"], &["GITHUB_TOKEN"]));
        for other in [
            server("sh", &["-y", "gh-mcp"], &["GITHUB_TOKEN"]),
            server("npx", &["-c", "env"], &["GITHUB_TOKEN"]),
            server("npx", &["-y", "gh-mcp"], &["GITHUB_TOKEN", "OTHER"]),
        ] {
            assert_ne!(server_fingerprint(&other), base);
        }
    }
}
