use super::window_label;
use async_trait::async_trait;
use mcp_warden_core::approval::{
    ApprovalDecision, ApprovalRequest, ApprovalTransport, sanitise_for_prompt,
};
use mcp_warden_core::error::{Result, WardenError};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

/// Native approval dialog on macOS, shown with `osascript`'s `display dialog`.
///
/// Works when an MCP client launches the server with no terminal attached,
/// which is where the TUI cannot run. The script is a fixed constant: every
/// piece of request text reaches it as an argument (`argv`), never as script
/// source, so a crafted preset name or path cannot inject AppleScript.
/// Deny is both the default button (Return) and the cancel button (Esc), and
/// the dialog gives up — reported as `Timeout` — when the request times out.
pub struct OsascriptApproval {
    program: PathBuf,
    /// Arguments placed before the dialog's own; tests run a fake under `sh`.
    leading_args: Vec<PathBuf>,
    /// Extra time after the dialog's own give-up before the process is killed.
    grace: Duration,
}

const TITLE: &str = "mcp-warden — approval requested";
const DENY: &str = "Deny";
const APPROVE_ONCE: &str = "Approve once";

/// `argv`: give-up seconds, title, message, the deny button, then every
/// button left to right. Replies with a button label, `deny` (Esc) or
/// `timeout`.
const SCRIPT: &[&str] = &[
    "on run argv",
    "set secs to (item 1 of argv) as integer",
    "set ttl to item 2 of argv",
    "set msg to item 3 of argv",
    "set denyButton to item 4 of argv",
    "set btns to items 5 thru -1 of argv",
    "activate",
    "try",
    "set r to display dialog msg with title ttl buttons btns default button denyButton \
     cancel button denyButton giving up after secs with icon caution",
    "on error number -128",
    "return \"deny\"",
    "end try",
    "if gave up of r then return \"timeout\"",
    "return button returned of r",
    "end run",
];

impl OsascriptApproval {
    pub fn new() -> Self {
        Self {
            program: PathBuf::from("/usr/bin/osascript"),
            leading_args: Vec::new(),
            grace: Duration::from_secs(5),
        }
    }
}

impl Default for OsascriptApproval {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ApprovalTransport for OsascriptApproval {
    async fn request(&self, req: ApprovalRequest) -> Result<ApprovalDecision> {
        let window = req.window_seconds.map(window_label);
        let child = tokio::process::Command::new(&self.program)
            .args(&self.leading_args)
            .args(dialog_args(&req, window.as_deref()))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| WardenError::Executor(format!("osascript: {e}")))?;
        // The dialog gives up on its own; this only guards against a hung
        // osascript. Dropping the future kills the child.
        let out =
            match tokio::time::timeout(req.timeout + self.grace, child.wait_with_output()).await {
                Ok(out) => out.map_err(WardenError::Io)?,
                Err(_) => return Ok(ApprovalDecision::Timeout),
            };
        parse_reply(
            out.status.success(),
            &String::from_utf8_lossy(&out.stdout),
            &String::from_utf8_lossy(&out.stderr),
            window.as_deref(),
        )
    }
}

/// Arguments for `osascript`: the script as `-e` lines, then its `argv`.
/// The first `argv` item is all digits, so nothing after the script can be
/// taken for an `osascript` option.
fn dialog_args(req: &ApprovalRequest, window: Option<&str>) -> Vec<String> {
    let secs = req.timeout.as_secs().max(1);
    let preset = sanitise_for_prompt(&req.preset, 64);
    let action = sanitise_for_prompt(&req.action, 32);
    let summary = sanitise_for_prompt(&req.summary, 480);
    let message = format!("{action} → {preset}\n\n{summary}\n\nNo answer in {secs} s means Deny.");

    let mut args = Vec::with_capacity(SCRIPT.len() * 2 + 7);
    for line in SCRIPT {
        args.push("-e".to_string());
        args.push((*line).to_string());
    }
    args.extend([secs.to_string(), TITLE.into(), message, DENY.into()]);
    args.extend(window.map(str::to_string));
    args.extend([APPROVE_ONCE.into(), DENY.into()]);
    args
}

/// Map the script's reply to a decision. Anything unexpected is an error,
/// which the executor records as `failed` — never an approval.
fn parse_reply(
    success: bool,
    stdout: &str,
    stderr: &str,
    window: Option<&str>,
) -> Result<ApprovalDecision> {
    if !success {
        return Err(WardenError::Executor(format!(
            "osascript failed: {}",
            sanitise_for_prompt(stderr.trim(), 200)
        )));
    }
    match stdout.trim_end_matches(['\r', '\n']) {
        "timeout" => Ok(ApprovalDecision::Timeout),
        "deny" | DENY => Ok(ApprovalDecision::Denied),
        APPROVE_ONCE => Ok(ApprovalDecision::Approved),
        reply if Some(reply) == window => Ok(ApprovalDecision::ApprovedForWindow),
        reply => Err(WardenError::Executor(format!(
            "osascript: unexpected reply {:?}",
            sanitise_for_prompt(reply, 64)
        ))),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::path::Path;

    /// A fake `osascript`: a shell script that saves its arguments
    /// (NUL-separated) to `argv` next to it, then runs `body`.
    fn fake(dir: &Path, body: &str) -> OsascriptApproval {
        let script = dir.join("fake-osascript.sh");
        let argv = dir.join("argv");
        std::fs::write(
            &script,
            format!("printf '%s\\0' \"$@\" > '{}'\n{body}\n", argv.display()),
        )
        .unwrap();
        OsascriptApproval {
            program: PathBuf::from("/bin/sh"),
            leading_args: vec![script],
            grace: Duration::ZERO,
        }
    }

    fn saved_argv(dir: &Path) -> Vec<String> {
        let raw = std::fs::read_to_string(dir.join("argv")).unwrap();
        raw.split_terminator('\0').map(str::to_string).collect()
    }

    fn req() -> ApprovalRequest {
        ApprovalRequest::new(
            "github-read".into(),
            "proxy_http".into(),
            "GET /user".into(),
        )
    }

    async fn reply(body: &str, req: ApprovalRequest) -> Result<ApprovalDecision> {
        let dir = tempfile::tempdir().unwrap();
        fake(dir.path(), body).request(req).await
    }

    #[tokio::test]
    async fn approve_once_button_approves() {
        let d = reply("echo 'Approve once'", req()).await.unwrap();
        assert_eq!(d, ApprovalDecision::Approved);
    }

    #[tokio::test]
    async fn deny_button_and_escape_deny() {
        assert_eq!(
            reply("echo Deny", req()).await.unwrap(),
            ApprovalDecision::Denied
        );
        assert_eq!(
            reply("echo deny", req()).await.unwrap(),
            ApprovalDecision::Denied
        );
    }

    #[tokio::test]
    async fn giving_up_is_a_timeout() {
        let d = reply("echo timeout", req()).await.unwrap();
        assert_eq!(d, ApprovalDecision::Timeout);
    }

    #[tokio::test]
    async fn window_button_approves_for_window_only_when_offered() {
        let offered = req().with_window(Some(600));
        let d = reply("echo 'Approve for 10 min'", offered).await.unwrap();
        assert_eq!(d, ApprovalDecision::ApprovedForWindow);

        // Not offered: the same reply is unexpected and fails closed.
        assert!(reply("echo 'Approve for 10 min'", req()).await.is_err());
    }

    #[tokio::test]
    async fn window_button_is_shown_only_when_offered() {
        let dir = tempfile::tempdir().unwrap();
        let t = fake(dir.path(), "echo Deny");
        t.request(req().with_window(Some(600))).await.unwrap();
        let buttons = saved_argv(dir.path()).split_off(SCRIPT.len() * 2 + 4);
        assert_eq!(buttons, ["Approve for 10 min", "Approve once", "Deny"]);

        t.request(req()).await.unwrap();
        let buttons = saved_argv(dir.path()).split_off(SCRIPT.len() * 2 + 4);
        assert_eq!(buttons, ["Approve once", "Deny"]);
    }

    #[tokio::test]
    async fn failed_osascript_is_an_error() {
        let err = reply("echo 'execution error: boom' >&2; exit 1", req())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("boom"), "{err}");
    }

    #[tokio::test]
    async fn unexpected_reply_is_an_error() {
        assert!(reply("echo Approve", req()).await.is_err());
        assert!(reply("true", req()).await.is_err());
    }

    #[tokio::test]
    async fn hung_dialog_times_out() {
        let mut r = req();
        r.timeout = Duration::from_millis(200);
        let d = reply("sleep 30", r).await.unwrap();
        assert_eq!(d, ApprovalDecision::Timeout);
    }

    #[tokio::test]
    async fn request_text_is_passed_as_arguments_not_script() {
        let dir = tempfile::tempdir().unwrap();
        let evil = "GET /x\n\"; do shell script \"touch /tmp/pwned\" --";
        let r = ApprovalRequest::new("p\u{1b}[31m".into(), "proxy_http".into(), evil.into());
        fake(dir.path(), "echo Deny").request(r).await.unwrap();

        let argv = saved_argv(dir.path());
        let (script, rest) = argv.split_at(SCRIPT.len() * 2);
        for (pair, line) in script.chunks(2).zip(SCRIPT) {
            assert_eq!(pair, ["-e", *line]);
        }
        assert_eq!(rest[0], "60", "first argv item must be the give-up seconds");
        assert_eq!(rest[1], TITLE);
        let message = &rest[2];
        assert!(message.starts_with("proxy_http → p[31m\n\n"), "{message}");
        assert!(
            message.contains("GET /x\"; do shell script \"touch /tmp/pwned\" --"),
            "newline stripped, text kept literally: {message}"
        );
        assert!(!message.contains('\u{1b}'));
        assert_eq!(rest[3], DENY);
    }
}
