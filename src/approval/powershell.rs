use super::dialog::{self, DENY, TITLE};
use super::window_button;
use async_trait::async_trait;
use base64::Engine;
use mcp_warden_core::approval::{ApprovalDecision, ApprovalRequest, ApprovalTransport};
use mcp_warden_core::error::Result;
use std::path::PathBuf;
use std::time::Duration;

/// Native approval dialog on Windows: a small Windows Forms window shown by
/// Windows PowerShell, which every Windows install ships.
///
/// The script is a fixed constant, passed with `-EncodedCommand`; the
/// request text reaches it only through environment variables, never as
/// script source, so a crafted preset name or path cannot inject PowerShell.
/// Deny is both the accept button (Enter) and the cancel button (Esc);
/// closing the window denies; the window gives up — reported as `Timeout` —
/// when the request times out.
pub struct PowerShellApproval {
    program: PathBuf,
    /// Arguments placed before the dialog's own; tests run a fake under `sh`.
    leading_args: Vec<PathBuf>,
    /// Extra time after the dialog's own give-up before the process is killed.
    grace: Duration,
}

/// Reads `MCPW_DIALOG_*`; prints a button label, `deny` (window closed) or
/// `timeout`.
const SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$state = @{ answer = 'deny' }
$form = New-Object System.Windows.Forms.Form
$form.Text = $env:MCPW_DIALOG_TITLE
$form.TopMost = $true
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.AutoSize = $true
$form.AutoSizeMode = 'GrowAndShrink'
$form.Padding = New-Object System.Windows.Forms.Padding(12)
$layout = New-Object System.Windows.Forms.FlowLayoutPanel
$layout.FlowDirection = 'TopDown'
$layout.AutoSize = $true
$label = New-Object System.Windows.Forms.Label
$label.Text = $env:MCPW_DIALOG_MESSAGE
$label.AutoSize = $true
$label.MaximumSize = New-Object System.Drawing.Size(520, 0)
$layout.Controls.Add($label)
$row = New-Object System.Windows.Forms.FlowLayoutPanel
$row.AutoSize = $true
foreach ($text in ($env:MCPW_DIALOG_BUTTONS -split "`n")) {
  $button = New-Object System.Windows.Forms.Button
  $button.Text = $text
  $button.UseMnemonic = $false
  $button.AutoSize = $true
  $button.Add_Click({ param($sender, $e) $state.answer = $sender.Text; $form.Close() })
  $row.Controls.Add($button)
  if ($text -eq $env:MCPW_DIALOG_DENY) { $form.AcceptButton = $button; $form.CancelButton = $button }
}
$layout.Controls.Add($row)
$form.Controls.Add($layout)
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = [Math]::Max(1, [int]$env:MCPW_DIALOG_SECONDS) * 1000
$timer.Add_Tick({ $state.answer = 'timeout'; $form.Close() })
$form.Add_Shown({ $form.Activate(); $timer.Start() })
[void]$form.ShowDialog()
$timer.Stop()
[Console]::Out.Write($state.answer)
"#;

impl PowerShellApproval {
    pub fn new() -> Self {
        // The system copy, by full path, so a `powershell.exe` earlier on
        // PATH is never the one asked.
        let program = std::env::var_os("SystemRoot")
            .map(|root| PathBuf::from(root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe"))
            .unwrap_or_else(|| PathBuf::from("powershell.exe"));
        Self {
            program,
            leading_args: Vec::new(),
            grace: Duration::from_secs(10),
        }
    }
}

impl Default for PowerShellApproval {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ApprovalTransport for PowerShellApproval {
    async fn request(&self, req: ApprovalRequest) -> Result<ApprovalDecision> {
        let window = window_button(&req);
        let mut cmd = tokio::process::Command::new(&self.program);
        cmd.args(&self.leading_args)
            .args(powershell_args())
            .envs(dialog_env(&req, window.as_deref()));
        #[cfg(windows)]
        {
            // No console window flashes up behind the dialog.
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        dialog::run(cmd, "powershell", &req, self.grace, window.as_deref()).await
    }
}

/// `-EncodedCommand` takes the script as base64 of its UTF-16LE text, which
/// sidesteps Windows command-line quoting altogether.
fn powershell_args() -> Vec<String> {
    let utf16: Vec<u8> = SCRIPT.encode_utf16().flat_map(u16::to_le_bytes).collect();
    vec![
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-ExecutionPolicy".into(),
        "Bypass".into(),
        "-EncodedCommand".into(),
        base64::engine::general_purpose::STANDARD.encode(utf16),
    ]
}

/// The request, for the script: data, never code.
fn dialog_env(req: &ApprovalRequest, window: Option<&str>) -> Vec<(&'static str, String)> {
    vec![
        ("MCPW_DIALOG_TITLE", TITLE.to_string()),
        ("MCPW_DIALOG_MESSAGE", dialog::message(req)),
        ("MCPW_DIALOG_BUTTONS", dialog::buttons(window).join("\n")),
        ("MCPW_DIALOG_DENY", DENY.to_string()),
        ("MCPW_DIALOG_SECONDS", dialog::give_up_secs(req).to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_encoded_command_is_the_script_and_holds_no_request_text() {
        let args = powershell_args();
        assert_eq!(
            args[..5],
            [
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand"
            ]
        );
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&args[5])
            .unwrap();
        let utf16: Vec<u16> = bytes
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(String::from_utf16(&utf16).unwrap(), SCRIPT);
    }

    #[test]
    fn request_text_goes_in_the_environment_sanitised() {
        let evil = "GET /x\n\"; Remove-Item -Recurse C:\\ #";
        let req = ApprovalRequest::new("p\u{1b}[31m".into(), "proxy_http".into(), evil.into())
            .with_window(Some(600));
        let window = window_button(&req).unwrap();
        let env: std::collections::HashMap<_, _> =
            dialog_env(&req, Some(&window)).into_iter().collect();
        let message = &env["MCPW_DIALOG_MESSAGE"];
        assert!(message.starts_with("proxy_http → p[31m\n\n"), "{message}");
        assert!(message.contains("GET /x\"; Remove-Item -Recurse C:\\ #"));
        assert!(!message.contains('\u{1b}'));
        assert_eq!(
            env["MCPW_DIALOG_BUTTONS"],
            format!("{window}\nApprove once\nDeny")
        );
        assert!(
            window.starts_with("Approve for 10 min: every proxy_http call p[31m allows"),
            "{window}"
        );
        assert_eq!(env["MCPW_DIALOG_DENY"], "Deny");
        assert_eq!(env["MCPW_DIALOG_SECONDS"], "60");
        assert!(!SCRIPT.contains("Remove-Item"));
    }

    /// The transport end to end, with a fake `powershell` that answers from
    /// what it was given.
    #[cfg(unix)]
    #[tokio::test]
    async fn replies_from_the_helper_become_decisions() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("fake-powershell.sh");
        // Answers with the first button it was offered, after checking that
        // the script came as -EncodedCommand.
        std::fs::write(
            &fake,
            "[ \"$5\" = -EncodedCommand ] || exit 3\nprintf '%s' \"$MCPW_DIALOG_BUTTONS\" | head -n 1\n",
        )
        .unwrap();
        let t = PowerShellApproval {
            program: PathBuf::from("/bin/sh"),
            leading_args: vec![fake],
            grace: Duration::ZERO,
        };
        let req = ApprovalRequest::new("p".into(), "proxy_http".into(), "GET /x".into());
        assert_eq!(
            t.request(req.clone()).await.unwrap(),
            ApprovalDecision::Approved
        );
        assert_eq!(
            t.request(req.with_window(Some(600))).await.unwrap(),
            ApprovalDecision::ApprovedForWindow
        );
    }
}
