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
//! a human approves it in the approval prompt: `secret add` refuses
//! `stamp/` names and no preset may use one as its secret. Because the
//! fingerprint itself is public (anyone can hash the config), a stamp is
//! not the fingerprint but its HMAC-SHA256 under a random key that lives
//! only in the keychain (`stamp/key`) and is never shown, so a stamp
//! written by any other route does not verify.

use crate::config::{ApprovalPolicy, Preset, WrappedServer};
use crate::error::Result;
use crate::keychain::KeychainStore;
use crate::secret::Secret;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// The keychain entry with the key that signs stamps.
const KEY_ENTRY: &str = "stamp/key";

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
    let Some(stamp) = kc.get(entry)? else {
        return Ok(Confirmation::Missing);
    };
    let Some(key) = kc.get(KEY_ENTRY)? else {
        return Ok(Confirmation::Changed);
    };
    Ok(if sign(&key, entry, fingerprint) == stamp.expose() {
        Confirmation::Confirmed
    } else {
        Confirmation::Changed
    })
}

/// Record that a human confirmed the entry with this fingerprint. Callers
/// must have asked through the approval transport first. Creates the
/// signing key on first use.
pub fn record(kc: &dyn KeychainStore, entry: &str, fingerprint: &str) -> Result<()> {
    let key = match kc.get(KEY_ENTRY)? {
        Some(key) => key,
        None => {
            let mut bytes = [0u8; 32];
            getrandom::fill(&mut bytes).map_err(|e| {
                crate::error::WardenError::Executor(format!("no randomness for the stamp key: {e}"))
            })?;
            let key = Secret::new(bytes.iter().map(|b| format!("{b:02x}")).collect());
            kc.set(KEY_ENTRY, Secret::new(key.expose().to_string()))?;
            key
        }
    };
    kc.set(entry, Secret::new(sign(&key, entry, fingerprint)))
}

/// HMAC-SHA256 over the entry name and the fingerprint, hex.
fn sign(key: &Secret, entry: &str, fingerprint: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.expose().as_bytes())
        .expect("HMAC takes a key of any length");
    mac.update(entry.as_bytes());
    mac.update(b"\n");
    mac.update(fingerprint.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Keychain names that are stamps, not secrets.
pub fn is_stamp_name(name: &str) -> bool {
    name.starts_with("stamp/")
}

/// Keychain names mcp-warden keeps for itself: stamps (`stamp/`) and the
/// audit anchor (`audit/`). They are not secrets, the CLI never writes or
/// removes them, and no preset, server or transport may use one: a preset
/// naming one could send it upstream or reveal it to the agent, and
/// overwriting one would forge a confirmation or move the anchor.
pub fn is_reserved_name(name: &str) -> bool {
    is_stamp_name(name) || name.starts_with("audit/")
}

/// Run every `auto` preset, and every `auto` named command, that no human
/// confirmed in this exact form as `prompt` instead, and say why for each.
pub fn demote_unconfirmed_auto(presets: &mut [Preset], kc: &dyn KeychainStore) -> Vec<String> {
    let mut warnings = Vec::new();
    for p in presets.iter_mut().filter(|p| p.has_auto()) {
        let state = check(kc, &preset_stamp_name(&p.name), &preset_fingerprint(p))
            .unwrap_or(Confirmation::Missing);
        let why = match state {
            Confirmation::Confirmed => continue,
            Confirmation::Missing => "has not been confirmed",
            Confirmation::Changed => "changed since it was confirmed",
        };
        let auto_commands: Vec<&str> = p
            .commands
            .iter()
            .filter(|c| c.approval == Some(ApprovalPolicy::Auto))
            .map(|c| c.name.as_str())
            .collect();
        let what = match (p.approval == ApprovalPolicy::Auto, auto_commands.as_slice()) {
            (true, []) => "is approval = \"auto\"".to_string(),
            (true, names) => format!(
                "is approval = \"auto\" (and so are its commands {})",
                names.join(", ")
            ),
            (false, names) => format!(
                "has commands with approval = \"auto\" ({})",
                names.join(", ")
            ),
        };
        warnings.push(format!(
            "preset '{}' {what} but {why}; every call asks for approval until you run \
             `mcp-warden preset confirm {}`",
            p.name, p.name
        ));
        if p.approval == ApprovalPolicy::Auto {
            p.approval = ApprovalPolicy::Prompt;
        }
        for c in &mut p.commands {
            if c.approval == Some(ApprovalPolicy::Auto) {
                c.approval = Some(ApprovalPolicy::Prompt);
            }
        }
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

    /// Presets in the form 0.5.4 confirmed them. A new `Preset` field must
    /// stay out of the JSON while it is unset (`skip_serializing_if`), or
    /// every confirmed `auto` preset turns back into `prompt` on upgrade.
    /// If this test fails, an upgrade would void the users' stamps.
    #[test]
    fn fingerprints_of_existing_presets_do_not_change() {
        let golden = [
            (
                r#"
                name = "gh"
                type = "http"
                description = "GitHub"
                base_url = "https://api.github.com"
                auth = { type = "bearer", secret = "gh_pat" }
                allowed_methods = ["GET"]
                allowed_paths = ["/user/repos"]
                approval = "auto"
                approval_window_seconds = 600
                "#,
                "67b19399302294aa88ad6458e06630e3cb511cab958f193605d9d1688d7eb5a3",
            ),
            (
                r#"
                name = "deploy"
                type = "ssh"
                description = "Deploy host"
                host = "deploy.example.com"
                user = "warden"
                secret = "deploy_key"
                allowed_commands = ["git pull", "systemctl status [a-z0-9][a-z0-9_-]*"]
                allow_sftp = true
                sftp_allowed_paths = ["/srv/app/"]
                approval = "auto"
                "#,
                "42eda74aabe84fc86a2951890465399df0ca1234a2619e7c4f2ce29cdfce22d1",
            ),
            (
                r#"
                name = "db"
                type = "postgres"
                description = "Reporting"
                host = "db.internal"
                user = "ro"
                database = "app"
                secret = "db_pw"
                approval = "auto"
                [[queries]]
                name = "user_by_id"
                template = "SELECT id, email FROM users WHERE id = $1"
                param_types = ["int"]
                "#,
                "e7e66ecb73a4b4b206391cfa074ac8a624171be565a44a176217d796944cde4c",
            ),
        ];
        for (toml_text, want) in golden {
            let p: Preset = toml::from_str(toml_text).unwrap();
            assert_eq!(preset_fingerprint(&p), want, "{}", p.name);
        }
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

    /// The fingerprint is public — anyone can hash the config — so a stamp
    /// written straight into the keychain (`mcp-warden secret add
    /// stamp/preset/gh` with the hash on stdin) must not count.
    #[test]
    fn a_stamp_written_without_the_key_does_not_count() {
        let kc = InMemoryKeychain::new();
        let p = preset("");
        // Make sure a key exists, as it does once anything was confirmed.
        record(&kc, &preset_stamp_name("other"), "x").unwrap();
        kc.set(
            &preset_stamp_name("gh"),
            Secret::new(preset_fingerprint(&p)),
        )
        .unwrap();
        let mut presets = vec![p];
        assert_eq!(demote_unconfirmed_auto(&mut presets, &kc).len(), 1);
        assert_eq!(presets[0].approval, ApprovalPolicy::Prompt);
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

    fn with_auto_command(preset_policy: &str) -> Preset {
        let cfg: crate::config::Config = toml::from_str(
            &include_str!("../../tests/fixtures/named_commands.toml")
                .replacen(
                    "approval = \"prompt\"",
                    &format!("approval = \"{preset_policy}\""),
                    1,
                )
                .replacen(
                    "max_output_bytes = 262144",
                    "max_output_bytes = 262144\napproval = \"auto\"",
                    1,
                ),
        )
        .unwrap();
        cfg.preset[0].clone()
    }

    /// An agent that can edit config.toml must not be able to make one
    /// command of a `prompt` preset run without asking: a command's `auto`
    /// needs a human's confirmation of the preset, like the preset's own.
    #[test]
    fn an_unconfirmed_auto_command_asks() {
        let kc = InMemoryKeychain::new();
        let p = with_auto_command("prompt");
        assert!(p.has_auto());
        assert_eq!(p.commands[0].approval, Some(ApprovalPolicy::Auto));

        let mut presets = vec![p.clone()];
        let warnings = demote_unconfirmed_auto(&mut presets, &kc);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("tail_log"), "{warnings:?}");
        assert_eq!(
            presets[0].commands[0].approval,
            Some(ApprovalPolicy::Prompt)
        );
        assert_eq!(presets[0].approval, ApprovalPolicy::Prompt);
        assert!(!presets[0].has_auto());

        // Confirmed in exactly this form, it stays auto.
        record(&kc, &preset_stamp_name(&p.name), &preset_fingerprint(&p)).unwrap();
        let mut presets = vec![p.clone()];
        assert!(demote_unconfirmed_auto(&mut presets, &kc).is_empty());
        assert_eq!(presets[0].commands[0].approval, Some(ApprovalPolicy::Auto));

        // Any edit to a command voids the confirmation.
        let mut edited = p.clone();
        edited.commands[0].template = "journalctl -n {lines}".into();
        let mut presets = vec![edited];
        assert_eq!(demote_unconfirmed_auto(&mut presets, &kc).len(), 1);
        assert_eq!(
            presets[0].commands[0].approval,
            Some(ApprovalPolicy::Prompt)
        );
    }

    #[test]
    fn an_unconfirmed_auto_preset_demotes_its_commands_too() {
        let kc = InMemoryKeychain::new();
        let mut presets = vec![with_auto_command("auto")];
        assert_eq!(demote_unconfirmed_auto(&mut presets, &kc).len(), 1);
        assert_eq!(presets[0].approval, ApprovalPolicy::Prompt);
        assert_eq!(
            presets[0].commands[0].approval,
            Some(ApprovalPolicy::Prompt)
        );
        // Commands without their own policy follow the preset's.
        assert_eq!(presets[0].commands[1].approval, None);
    }
}
