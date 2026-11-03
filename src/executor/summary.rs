//! One-line descriptions of what the agent asked for. They are shown in the
//! approval prompt and stored as the audit `summary` — both for authorised
//! calls and for calls refused before authorisation, including calls naming
//! a preset that does not exist (the MCP server builds those).
//!
//! Built only from agent-supplied request fields and the preset's host /
//! type: never from a secret, a header, a query string or a body. The
//! destination (`base_url`, the database host) is part of it, so a human
//! approving a call sees where it goes even if the config was edited to
//! point an existing preset somewhere else.

/// `GET https://api.github.com/user/repos`; without a known preset (a call
/// refused before its preset was found) just `GET /user/repos`.
pub fn http(method: &str, base_url: Option<&str>, path: &str) -> String {
    let base = base_url.map_or("", |b| b.trim_end_matches('/'));
    format!("{} {base}{path}", method.to_uppercase())
}

pub fn ssh(host: &str, command: &str) -> String {
    format!("ssh {host} -- {command}")
}

/// `deploy.trash_file: ssh deploy.example.com -- mv /srv/app/uploads/a.png
/// /srv/app/.trash/`: the preset, the command's name and the command line it
/// runs, so the prompt shows every value. Before the values are checked (a
/// refused call) the command line is not known: `deploy.trash_file: ssh
/// deploy.example.com (1 param)`. A name that is not a valid command name
/// is shown as `?`.
pub fn ssh_run(
    preset: &str,
    command_name: &str,
    host: &str,
    command: Option<&str>,
    params: usize,
) -> String {
    let name = if mcp_warden_core::commands::is_identifier(command_name) {
        command_name
    } else {
        "?"
    };
    match command {
        Some(command) => format!("{preset}.{name}: {}", ssh(host, command)),
        None => format!("{preset}.{name}: ssh {host} ({params} param)"),
    }
}

pub fn sftp(direction: &str, remote: &str, local: &str) -> String {
    format!("sftp {direction} {remote} ↔ {local}")
}

/// `db postgres db.example.com → user_by_id (1 param)`; the host is left out
/// when it is not known.
pub fn db(kind: &str, host: Option<&str>, query_name: &str, params: usize) -> String {
    match host {
        Some(host) => format!("db {kind} {host} → {query_name} ({params} param)"),
        None => format!("db {kind} → {query_name} ({params} param)"),
    }
}
