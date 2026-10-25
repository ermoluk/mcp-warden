use crate::web::handlers;
use axum::extract::Request;
use axum::{
    Router,
    middleware::{self, Next},
    response::Response,
    routing::get,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

/// Shared state passed to every handler.
#[derive(Clone)]
pub struct AppState {
    pub config_path: PathBuf,
    pub audit_db: PathBuf,
}

/// Start the axum HTTP server.
///
/// # Security
///
/// SECURITY: The bind address is hardcoded to 127.0.0.1. There is no CLI flag
/// or environment variable to override this to 0.0.0.0 or any other address.
/// The web UI is local-only by design — it exposes audit data and preset
/// metadata, and relies entirely on the loopback restriction instead of
/// authentication. Do not change this without adding auth first.
pub async fn serve(port: u16, config_path: PathBuf, audit_db: PathBuf) -> anyhow::Result<()> {
    let state = Arc::new(AppState {
        config_path,
        audit_db,
    });

    let app = Router::new()
        .route("/", get(handlers::index))
        .route("/presets", get(handlers::presets_list))
        .route("/presets/:name", get(handlers::preset_detail))
        .route("/audit", get(handlers::audit_log))
        .with_state(state)
        .layer(middleware::from_fn(security_headers));

    // SECURITY: Hardcoded loopback — no flag, no env override possible.
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("mcp-warden web UI listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Inject mandatory security headers on every response.
///
/// SECURITY: These headers prevent clickjacking, MIME sniffing, and inline
/// script injection for the local UI. Because there is no auth layer, keeping
/// the UI's attack surface minimal is important.
async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        axum::http::header::HeaderName::from_static("content-security-policy"),
        axum::http::HeaderValue::from_static("default-src 'self'"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("x-frame-options"),
        axum::http::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("x-content-type-options"),
        axum::http::HeaderValue::from_static("nosniff"),
    );
    response
}
