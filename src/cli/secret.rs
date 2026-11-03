use clap::Subcommand;
use is_terminal::IsTerminal;
use mcp_warden_core::error::{Result, WardenError};
use mcp_warden_core::keychain::KeychainStore;
use mcp_warden_core::secret::Secret;
use std::io::{BufRead, Write};

#[derive(Debug, Subcommand)]
pub enum SecretCmd {
    /// Add or replace a secret. Value is read from stdin (TTY-safe).
    Add { name: String },
    /// List secret names (never values).
    List,
    /// Remove a secret.
    Remove { name: String },
}

pub fn run(cmd: SecretCmd, store: &dyn KeychainStore) -> Result<()> {
    // `stamp/…` entries record what a human confirmed in an approval
    // prompt, `audit/…` how far the audit log reached. The CLI cannot tell
    // a human from an agent with a shell, so it never writes or removes
    // them.
    if let SecretCmd::Add { name } | SecretCmd::Remove { name } = &cmd
        && mcp_warden_core::stamp::is_reserved_name(name)
    {
        return Err(WardenError::Validation(format!(
            "'{name}' is reserved for mcp-warden's own records (confirmations, the audit \
             anchor); use `mcp-warden preset confirm` to confirm a preset"
        )));
    }
    match cmd {
        SecretCmd::Add { name } => add(name, store),
        SecretCmd::List => list(store),
        SecretCmd::Remove { name } => remove(name, store),
    }
}

fn add(name: String, store: &dyn KeychainStore) -> Result<()> {
    store.set(&name, read_value(&name)?)?;
    eprintln!("Stored '{}'.", name);
    Ok(())
}

/// Read one secret value from stdin — prompting on a terminal — so it never
/// appears in shell history or the process list.
pub(crate) fn read_value(label: &str) -> Result<Secret> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        eprint!("Value for '{}': ", label);
        std::io::stderr().flush().ok();
    }
    let mut buf = String::new();
    stdin.lock().read_line(&mut buf)?;
    let value = buf.trim_end_matches(['\r', '\n']).to_string();
    if value.is_empty() {
        return Err(WardenError::Validation("empty secret".into()));
    }
    Ok(Secret::new(value))
}

fn list(store: &dyn KeychainStore) -> Result<()> {
    // Confirmation stamps live in the keychain too, but are not secrets.
    let names: Vec<String> = store
        .list_names()?
        .into_iter()
        .filter(|n| !mcp_warden_core::stamp::is_reserved_name(n))
        .collect();
    if names.is_empty() {
        println!("(no secrets)");
    } else {
        for n in names {
            println!("{n}");
        }
    }
    Ok(())
}

fn remove(name: String, store: &dyn KeychainStore) -> Result<()> {
    store.delete(&name)?;
    eprintln!("Removed '{}'.", name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_warden_core::keychain::memory::InMemoryKeychain;

    /// The CLI cannot tell a human from an agent with a shell, so it must
    /// not write or remove confirmation stamps: only an approved prompt may.
    #[test]
    fn reserved_entries_cannot_be_written_or_removed_from_the_cli() {
        let kc = InMemoryKeychain::new();
        for cmd in [
            SecretCmd::Add {
                name: "stamp/preset/gh".into(),
            },
            SecretCmd::Add {
                name: "stamp/key".into(),
            },
            SecretCmd::Remove {
                name: "stamp/key".into(),
            },
            SecretCmd::Add {
                name: "audit/anchor/0123456789abcdef".into(),
            },
            SecretCmd::Remove {
                name: "audit/anchor/0123456789abcdef".into(),
            },
        ] {
            let err = run(cmd, &kc).unwrap_err().to_string();
            assert!(err.contains("reserved"), "{err}");
        }
    }
}
