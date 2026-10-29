//! Core approval surface — trait + request/decision types.
//!
//! Concrete transports (`DesktopApproval`, `TuiApproval`, `TelegramApproval`,
//! `AlwaysDeny`) live in the `mcp-warden` binary crate. Paid implementations
//! (mobile push, cloud relay, …) can be added as additional impls of
//! `ApprovalTransport` without touching this crate — that's the whole point
//! of the trait seam.

use crate::error::Result;
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub preset: String,
    pub action: String,
    pub summary: String,
    pub timeout: std::time::Duration,
    /// Cap (seconds) for an approve-for-window option. `None` means the
    /// preset disables windowing for this action; the transport must NOT
    /// offer the window choice. `Some(n)` is the maximum window length
    /// the executor will honour if the user chooses it.
    pub window_seconds: Option<u64>,
    /// When an approve-for-window choice made now would end, as the prompt
    /// shows it. The executor fixes it when the prompt is shown and ends the
    /// window at exactly this time, so a late click gets a shorter window,
    /// never a longer one. `None` when no window is offered (or the caller
    /// left it to the transport, which then counts from its own `now`).
    pub window_until: Option<chrono::DateTime<chrono::Local>>,
}

impl ApprovalRequest {
    pub fn new(preset: String, action: String, summary: String) -> Self {
        Self {
            preset,
            action,
            summary,
            timeout: std::time::Duration::from_secs(60),
            window_seconds: None,
            window_until: None,
        }
    }

    pub fn with_window(mut self, window_seconds: Option<u64>) -> Self {
        self.window_seconds = window_seconds.filter(|n| *n > 0);
        self
    }

    pub fn with_window_until(mut self, until: chrono::DateTime<chrono::Local>) -> Self {
        self.window_until = Some(until);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approved,
    /// Approved AND the executor should remember this approval for the
    /// preset+action pair until the window expires. Transports only emit
    /// this when `ApprovalRequest.window_seconds` was `Some`.
    ApprovedForWindow,
    Denied,
    Timeout,
}

#[async_trait]
pub trait ApprovalTransport: Send + Sync {
    async fn request(&self, req: ApprovalRequest) -> Result<ApprovalDecision>;
}

/// Sanitise text destined for an OS notification or terminal prompt.
///
/// Strips control characters (so a malicious preset name with newlines or
/// terminal-escape sequences cannot spoof the prompt body) and truncates
/// to `max_len` characters.
pub fn sanitise_for_prompt(input: &str, max_len: usize) -> String {
    input
        .chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(max_len)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitise_strips_newlines_and_escapes() {
        let evil = "preset\n\u{1b}[31mfake\u{1b}[0m";
        let s = sanitise_for_prompt(evil, 100);
        assert!(!s.contains('\n'));
        assert!(!s.contains('\u{1b}'));
    }

    #[test]
    fn sanitise_truncates() {
        let s = sanitise_for_prompt(&"a".repeat(1000), 10);
        assert_eq!(s.len(), 10);
    }
}
