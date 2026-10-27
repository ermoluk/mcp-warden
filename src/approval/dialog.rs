//! What the native approval dialogs share — macOS (`osascript`) and Windows
//! (PowerShell): their text and buttons, running the helper program, and
//! reading its answer.

use mcp_warden_core::approval::{ApprovalDecision, ApprovalRequest, sanitise_for_prompt};
use mcp_warden_core::error::{Result, WardenError};
use std::process::Stdio;
use std::time::Duration;

pub(crate) const TITLE: &str = "mcp-warden — approval requested";
pub(crate) const DENY: &str = "Deny";
pub(crate) const APPROVE_ONCE: &str = "Approve once";

/// Seconds after which the dialog gives up (and the answer is `timeout`).
pub(crate) fn give_up_secs(req: &ApprovalRequest) -> u64 {
    req.timeout.as_secs().max(1)
}

/// The dialog's text, built from sanitised parts.
pub(crate) fn message(req: &ApprovalRequest) -> String {
    let preset = sanitise_for_prompt(&req.preset, 64);
    let action = sanitise_for_prompt(&req.action, 32);
    let summary = sanitise_for_prompt(&req.summary, 480);
    format!(
        "{action} → {preset}\n\n{summary}\n\nNo answer in {} s means Deny.",
        give_up_secs(req)
    )
}

/// Buttons left to right: the window choice (if offered), Approve once,
/// Deny — Deny last, where the default button sits.
pub(crate) fn buttons(window: Option<&str>) -> Vec<String> {
    window
        .into_iter()
        .chain([APPROVE_ONCE, DENY])
        .map(str::to_string)
        .collect()
}

/// Run the dialog helper and map its answer. The dialog gives up on its own
/// after the request timeout; `grace` only guards against a helper that
/// hangs, and dropping the future kills it.
pub(crate) async fn run(
    mut cmd: tokio::process::Command,
    name: &str,
    req: &ApprovalRequest,
    grace: Duration,
    window: Option<&str>,
) -> Result<ApprovalDecision> {
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| WardenError::Executor(format!("{name}: {e}")))?;
    let out = match tokio::time::timeout(req.timeout + grace, child.wait_with_output()).await {
        Ok(out) => out.map_err(WardenError::Io)?,
        Err(_) => return Ok(ApprovalDecision::Timeout),
    };
    parse_reply(
        name,
        out.status.success(),
        &String::from_utf8_lossy(&out.stdout),
        &String::from_utf8_lossy(&out.stderr),
        window,
    )
}

/// Map the helper's reply — a button label, `deny` or `timeout` — to a
/// decision. Anything unexpected is an error, which the executor records as
/// `failed` — never an approval.
pub(crate) fn parse_reply(
    name: &str,
    success: bool,
    stdout: &str,
    stderr: &str,
    window: Option<&str>,
) -> Result<ApprovalDecision> {
    if !success {
        return Err(WardenError::Executor(format!(
            "{name} failed: {}",
            sanitise_for_prompt(stderr.trim(), 200)
        )));
    }
    match stdout.trim() {
        "timeout" => Ok(ApprovalDecision::Timeout),
        "deny" | DENY => Ok(ApprovalDecision::Denied),
        APPROVE_ONCE => Ok(ApprovalDecision::Approved),
        reply if Some(reply) == window => Ok(ApprovalDecision::ApprovedForWindow),
        reply => Err(WardenError::Executor(format!(
            "{name}: unexpected reply {:?}",
            sanitise_for_prompt(reply, 64)
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies_map_to_decisions_and_anything_else_fails_closed() {
        let parse = |out: &str, window| parse_reply("x", true, out, "", window);
        assert_eq!(
            parse("Approve once\r\n", None).unwrap(),
            ApprovalDecision::Approved
        );
        assert_eq!(parse("Deny", None).unwrap(), ApprovalDecision::Denied);
        assert_eq!(parse("deny", None).unwrap(), ApprovalDecision::Denied);
        assert_eq!(parse("timeout", None).unwrap(), ApprovalDecision::Timeout);
        assert_eq!(
            parse("Approve for 10 min", Some("Approve for 10 min")).unwrap(),
            ApprovalDecision::ApprovedForWindow
        );
        assert!(parse("Approve for 10 min", None).is_err());
        assert!(parse("Approve", None).is_err());
        assert!(parse_reply("x", false, "Approve once", "boom", None).is_err());
    }

    #[test]
    fn deny_is_the_last_button() {
        assert_eq!(buttons(None), ["Approve once", "Deny"]);
        assert_eq!(
            buttons(Some("Approve for 10 min")),
            ["Approve for 10 min", "Approve once", "Deny"]
        );
    }
}
