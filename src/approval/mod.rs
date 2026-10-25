//! Concrete approval transports — impls of `mcp_warden_core::approval::ApprovalTransport`.
//!
//! Each transport delivers an approval request to the human and waits for
//! Approve / Deny / Timeout. The trait + request/decision types live in
//! `mcp_warden_core::approval`; this module only contains the impls.

pub mod always_deny;
pub mod desktop;
pub mod telegram;
pub mod tui;
