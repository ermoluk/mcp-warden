use crate::web::handlers;
use axum::extract::{Request, State};
use axum::http::header::{HOST, HeaderName, ORIGIN};
use axum::http::{Method, StatusCode};
use axum::{
    Router,
    middleware::{self, Next},
    response::{IntoResponse, Response},
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

    // SECURITY: Hardcoded loopback — no flag, no env override possible.
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("mcp-warden web UI listening on http://{addr}");
    axum::serve(listener, router(state, port)).await?;
    Ok(())
}

/// Every route, behind the security middleware.
pub(crate) fn router(state: Arc<AppState>, port: u16) -> Router {
    Router::new()
        .route("/", get(handlers::index))
        .route("/presets", get(handlers::presets_list))
        .route("/presets/:name", get(handlers::preset_detail))
        .route("/audit", get(handlers::audit_log))
        .with_state(state)
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn_with_state(port, only_this_ui))
}

/// Serve only requests addressed to this UI.
///
/// SECURITY: The loopback bind keeps other machines out, not other web
/// pages. With DNS rebinding a page on `evil.example` points its own name at
/// 127.0.0.1 and reads the UI as same-origin — but its requests still say
/// `Host: evil.example:<port>`. So the `Host` header must name this UI
/// (`127.0.0.1`, `localhost` or `[::1]`, with this port), or the request is
/// refused with 421 before any handler runs.
///
/// Anything but GET / HEAD (there are no such routes yet) must also come
/// from a page of this UI: an `Origin` naming it and no cross-site
/// `Sec-Fetch-Site`. Otherwise 403, so a form on another site cannot post
/// here once state-changing routes exist.
async fn only_this_ui(State(port): State<u16>, request: Request, next: Next) -> Response {
    let headers = request.headers();
    let header = |name: HeaderName| headers.get(name).and_then(|v| v.to_str().ok());
    let right_host = header(HOST).is_some_and(|host| is_this_ui(host, port));
    let same_origin = header(ORIGIN)
        .and_then(|o| o.strip_prefix("http://"))
        .is_some_and(|host| is_this_ui(host, port))
        && header(HeaderName::from_static("sec-fetch-site"))
            .is_none_or(|site| site.eq_ignore_ascii_case("same-origin"));
    if !right_host {
        return (
            StatusCode::MISDIRECTED_REQUEST,
            "mcp-warden web UI: wrong Host header\n",
        )
            .into_response();
    }
    if !matches!(*request.method(), Method::GET | Method::HEAD) && !same_origin {
        return (
            StatusCode::FORBIDDEN,
            "mcp-warden web UI: cross-origin request refused\n",
        )
            .into_response();
    }
    next.run(request).await
}

/// `host` (a `Host` header or the host part of an `Origin`) names this UI.
fn is_this_ui(host: &str, port: u16) -> bool {
    ["127.0.0.1", "localhost", "[::1]"]
        .iter()
        .any(|name| host.eq_ignore_ascii_case(&format!("{name}:{port}")))
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn start() -> (u16, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(AppState {
            config_path: dir.path().join("config.toml"),
            audit_db: dir.path().join("audit.db"),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(axum::serve(listener, router(state, port)).into_future());
        (port, dir)
    }

    /// The status code for a raw request: `head` is the request line and
    /// headers, without the final blank line.
    async fn status(port: u16, head: &str) -> u16 {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        s.write_all(format!("{head}\r\nConnection: close\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        let text = String::from_utf8_lossy(&out);
        text.split(' ').nth(1).unwrap().parse().unwrap()
    }

    /// DNS rebinding: a page on evil.example re-points its own name at
    /// 127.0.0.1 and reads the UI as same-origin. Its requests still carry
    /// `Host: evil.example:<port>`.
    #[tokio::test]
    async fn requests_for_another_host_are_refused() {
        let (port, _dir) = start().await;
        for path in ["/", "/presets", "/presets/x", "/audit"] {
            let evil = format!("GET {path} HTTP/1.1\r\nHost: evil.example:{port}");
            assert_eq!(status(port, &evil).await, 421, "{path}");
        }
        for host in [
            format!("evil.example:{port}"),
            "127.0.0.1".into(),
            format!("127.0.0.1:{}", port.wrapping_add(1)),
            format!("127.0.0.1.evil.example:{port}"),
            format!("localhost.:{port}"),
        ] {
            let head = format!("GET /audit HTTP/1.1\r\nHost: {host}");
            assert_eq!(status(port, &head).await, 421, "{host}");
        }
        // HTTP/1.0 may leave Host out; without one there is nothing to trust.
        assert_eq!(status(port, "GET /audit HTTP/1.0").await, 421);
    }

    #[tokio::test]
    async fn requests_for_this_ui_are_served() {
        let (port, _dir) = start().await;
        for host in [
            format!("127.0.0.1:{port}"),
            format!("localhost:{port}"),
            format!("LOCALHOST:{port}"),
            format!("[::1]:{port}"),
        ] {
            let head = format!("GET /audit HTTP/1.1\r\nHost: {host}");
            assert_eq!(status(port, &head).await, 200, "{host}");
        }
    }

    /// Anything but GET / HEAD must also come from a page of this UI.
    #[tokio::test]
    async fn state_changing_requests_need_this_origin() {
        let (port, _dir) = start().await;
        let host = format!("Host: 127.0.0.1:{port}");
        for extra in [
            "Origin: http://evil.example".to_string(),
            "Sec-Fetch-Site: cross-site".to_string(),
            format!("Origin: http://127.0.0.1:{port}\r\nSec-Fetch-Site: cross-site"),
        ] {
            let head = format!("POST /audit HTTP/1.1\r\n{host}\r\n{extra}\r\nContent-Length: 0");
            assert_eq!(status(port, &head).await, 403, "{extra}");
        }
        // A missing Origin is refused too: browsers always send one on POST.
        let head = format!("POST /audit HTTP/1.1\r\n{host}\r\nContent-Length: 0");
        assert_eq!(status(port, &head).await, 403);
        // From the UI itself it reaches the router (no POST route yet: 405).
        let head = format!(
            "POST /audit HTTP/1.1\r\n{host}\r\nOrigin: http://127.0.0.1:{port}\r\n\
             Sec-Fetch-Site: same-origin\r\nContent-Length: 0"
        );
        assert_eq!(status(port, &head).await, 405);
    }
}
