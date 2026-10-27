//! User-facing tool descriptions, pinned by snapshot tests so changes
//! to security-relevant copy can't slip through silently.
//!
//! The consts here MUST stay in sync with the doc comments on the tool
//! methods in `mcp::server`. The doc comments are what `rmcp` exposes to
//! the agent at runtime; the consts are what the snapshot tests pin.

#![allow(dead_code)]

pub const LIST_PRESETS_DESCRIPTION: &str = "\
List available mcp-warden presets — named, scoped actions you may invoke. \
Returns name, description, type (http|ssh), and approval policy \
(auto|prompt|deny). Read-only; never returns secret values. \
Use `proxy_http` for HTTP actions and `get_secret_for_env` only as a last \
resort when a child process must read a secret from its environment.";

pub const PROXY_HTTP_DESCRIPTION: &str = "\
Make an HTTP request through a preset. The preset selects the base URL and \
authentication; you supply `path`, `method`, and optional `body` / `query`. \
Allow-listed methods and paths are validated server-side BEFORE any \
credential is injected. Sensitive presets trigger an approval prompt the \
user must answer; you cannot bypass approval. If the user previously approved a \
time-boxed window for this preset+action, the call proceeds without a new \
prompt and is recorded as 'windowed' in the audit log. Every call is \
recorded to a local audit log.";

pub const GET_SECRET_FOR_ENV_DESCRIPTION: &str = "\
Reveal the raw secret value bound to a name. ALWAYS prompts for approval, \
regardless of preset policy. Prefer `proxy_http` — only use this if a \
child process you are about to spawn must read the secret from an \
environment variable (e.g. `terraform apply` reading AWS_SECRET_ACCESS_KEY). \
The returned value MUST NOT be quoted back into your reasoning trace.";

pub const SSH_EXEC_DESCRIPTION: &str = "\
Run a shell command on the preset's SSH host. The command must match \
one of the preset's `allowed_commands` regexes (anchored ^...$). \
Returns stdout, stderr, and exit_code. Key-based auth only; host key is \
verified against the user's known_hosts file. Sensitive presets trigger \
the approval prompt. If the user previously approved a time-boxed window \
for this preset+action, the call proceeds without a new prompt and is \
recorded as 'windowed' in the audit log. Every call is recorded to the \
audit log.";

pub const SFTP_TRANSFER_DESCRIPTION: &str = "\
Transfer a file between the preset's SSH host and the local machine. \
`direction` must be 'get' (download) or 'put' (upload). The remote path \
must match the preset's `sftp_allowed_paths` prefixes; the local path \
must be under $HOME or /tmp. Always key-based auth, host-key verified. \
If the user previously approved a time-boxed window for this preset+action, \
the call proceeds without a new prompt and is recorded as 'windowed' in \
the audit log.";

pub const DB_QUERY_DESCRIPTION: &str = "\
Run a NAMED QUERY against a database preset (PostgreSQL, MySQL, or Redis). \
You supply `query_name` (must match one declared in the preset) and `params` \
(positional). The SQL/command is FIXED at preset definition time — you cannot \
send arbitrary SQL. Returns rows as JSON. Approval prompt fires per the \
preset's policy. If the user previously approved a time-boxed window for this \
preset+action, the call proceeds without a new prompt and is recorded as \
'windowed' in the audit log.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_presets_description_pinned() {
        insta::assert_snapshot!(LIST_PRESETS_DESCRIPTION);
    }

    #[test]
    fn proxy_http_description_pinned() {
        insta::assert_snapshot!(PROXY_HTTP_DESCRIPTION);
    }

    #[test]
    fn get_secret_for_env_description_pinned() {
        insta::assert_snapshot!(GET_SECRET_FOR_ENV_DESCRIPTION);
    }

    #[test]
    fn ssh_exec_description_pinned() {
        insta::assert_snapshot!(SSH_EXEC_DESCRIPTION);
    }

    #[test]
    fn sftp_transfer_description_pinned() {
        insta::assert_snapshot!(SFTP_TRANSFER_DESCRIPTION);
    }

    #[test]
    fn db_query_description_pinned() {
        insta::assert_snapshot!(DB_QUERY_DESCRIPTION);
    }
}
