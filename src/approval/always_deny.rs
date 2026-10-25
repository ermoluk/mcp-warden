use async_trait::async_trait;
use mcp_warden_core::approval::{ApprovalDecision, ApprovalRequest, ApprovalTransport};
use mcp_warden_core::error::Result;

/// A transport that denies every approval request.
///
/// Used as a structural safety default in tests and as the placeholder while
/// the executor is being constructed. Never wired into a release binary.
#[allow(dead_code)]
pub struct AlwaysDeny;

#[async_trait]
impl ApprovalTransport for AlwaysDeny {
    async fn request(&self, _req: ApprovalRequest) -> Result<ApprovalDecision> {
        Ok(ApprovalDecision::Denied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn always_deny_returns_denied() {
        let t = AlwaysDeny;
        let req = ApprovalRequest::new("preset".into(), "proxy_http".into(), "GET /x".into());
        assert_eq!(t.request(req).await.unwrap(), ApprovalDecision::Denied);
    }
}
