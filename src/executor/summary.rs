//! One-line descriptions of what the agent asked for. They are shown in the
//! approval prompt and stored as the audit `summary` — both for authorised
//! calls and for calls refused before authorisation, including calls naming
//! a preset that does not exist (the MCP server builds those).
//!
//! Built only from agent-supplied request fields and the preset's host /
//! type: never from a secret, a header, a query string or a body.

pub fn http(method: &str, path: &str) -> String {
    format!("{} {path}", method.to_uppercase())
}

pub fn ssh(host: &str, command: &str) -> String {
    format!("ssh {host} -- {command}")
}

pub fn sftp(direction: &str, remote: &str, local: &str) -> String {
    format!("sftp {direction} {remote} ↔ {local}")
}

pub fn db(kind: &str, query_name: &str, params: usize) -> String {
    format!("db {kind} → {query_name} ({params} param)")
}
