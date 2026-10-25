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
    match cmd {
        SecretCmd::Add { name } => add(name, store),
        SecretCmd::List => list(store),
        SecretCmd::Remove { name } => remove(name, store),
    }
}

fn add(name: String, store: &dyn KeychainStore) -> Result<()> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        eprint!("Value for '{}': ", name);
        std::io::stderr().flush().ok();
    }
    let mut buf = String::new();
    stdin.lock().read_line(&mut buf)?;
    let value = buf.trim_end_matches(['\r', '\n']).to_string();
    if value.is_empty() {
        return Err(WardenError::Validation("empty secret".into()));
    }
    store.set(&name, Secret::new(value))?;
    eprintln!("Stored '{}'.", name);
    Ok(())
}

fn list(store: &dyn KeychainStore) -> Result<()> {
    let names = store.list_names()?;
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
