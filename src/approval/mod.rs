//! Concrete approval transports — impls of `mcp_warden_core::approval::ApprovalTransport`.
//!
//! Each transport delivers an approval request to the human and waits for
//! Approve / Deny / Timeout. The trait + request/decision types live in
//! `mcp_warden_core::approval`; this module only contains the impls.

pub mod always_deny;
pub mod desktop;
pub mod osascript;
pub mod telegram;
pub mod tui;

/// Button text for the approve-for-window choice: whole minutes when the
/// window is a multiple of 60 s, seconds otherwise.
pub fn window_label(seconds: u64) -> String {
    if seconds >= 60 && seconds.is_multiple_of(60) {
        format!("Approve for {} min", seconds / 60)
    } else {
        format!("Approve for {seconds} s")
    }
}
