use mcp_warden_core::error::{Result, WardenError};
use std::path::Path;

/// Launch the read-only local web UI.
///
/// The server always binds to 127.0.0.1 — see `src/web/server.rs` for the
/// security invariant comment.
pub async fn run(port: u16, config_path: &Path, audit_db: &Path) -> Result<()> {
    eprintln!("mcp-warden web UI starting on http://127.0.0.1:{port}");
    crate::web::server::serve(port, config_path.to_path_buf(), audit_db.to_path_buf())
        .await
        .map_err(|e| WardenError::Executor(format!("web server: {e}")))
}
