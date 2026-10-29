use async_trait::async_trait;
use mcp_warden_core::approval::{
    ApprovalDecision, ApprovalRequest, ApprovalTransport, sanitise_for_prompt,
};
use mcp_warden_core::error::{Result, WardenError};

/// Desktop-notification approval transport.
///
/// On Linux the notification carries Approve / Deny actions via DBus.
/// Elsewhere notifications have no actions: the notification fires and the
/// transport returns `Timeout`. macOS and Windows use their native dialogs
/// instead (`OsascriptApproval`, `PowerShellApproval`; see
/// `cli::mcp::desktop_transport`).
pub struct DesktopApproval;

#[async_trait]
impl ApprovalTransport for DesktopApproval {
    async fn request(&self, req: ApprovalRequest) -> Result<ApprovalDecision> {
        let preset = sanitise_for_prompt(&req.preset, 64);
        let action = sanitise_for_prompt(&req.action, 32);
        let summary = sanitise_for_prompt(&req.summary, 240);
        let body = format!("{action} → {preset}\n{summary}");
        let timeout_ms: i32 = req
            .timeout
            .as_millis()
            .min(i32::MAX as u128)
            .try_into()
            .unwrap_or(60_000);
        let window_seconds = req.window_seconds;
        let window_text = super::window_button(&req);

        let res = tokio::task::spawn_blocking(move || -> Result<ApprovalDecision> {
            let mut n = notify_rust::Notification::new();
            n.summary("mcp-warden — approval requested")
                .body(&body)
                .timeout(notify_rust::Timeout::Milliseconds(timeout_ms.max(1) as u32));

            #[cfg(target_os = "linux")]
            {
                n.action("approve", "Approve once");
                if let Some(text) = &window_text {
                    n.action("approve_window", text);
                }
                n.action("deny", "Deny");
                let handle = n.show().map_err(|e| WardenError::Executor(e.to_string()))?;
                let mut decision = ApprovalDecision::Timeout;
                handle.wait_for_action(|act| {
                    decision = match act {
                        "approve" => ApprovalDecision::Approved,
                        "approve_window" if window_seconds.is_some() => {
                            ApprovalDecision::ApprovedForWindow
                        }
                        "deny" => ApprovalDecision::Denied,
                        _ => ApprovalDecision::Timeout,
                    };
                });
                Ok(decision)
            }
            #[cfg(not(target_os = "linux"))]
            {
                // window_seconds is unused on non-Linux because no interactive
                // notification actions are wired up.
                let _ = (window_seconds, window_text);
                let _ = n.show().map_err(|e| WardenError::Executor(e.to_string()))?;
                Ok(ApprovalDecision::Timeout)
            }
        })
        .await
        .map_err(|e| WardenError::Executor(e.to_string()))??;
        Ok(res)
    }
}
