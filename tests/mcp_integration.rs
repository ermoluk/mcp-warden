//! MCP stdio protocol integration tests.
//!
//! Pin: stdout is the JSON-RPC channel — every byte on it must be JSON.
//! Logs, panics, and incidental prints must go to stderr or the protocol
//! breaks. CLAUDE.md "What NOT to do" #11 names this guarantee explicitly;
//! this test enforces it.

use assert_cmd::cargo::cargo_bin;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn stdout_contains_only_json() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bin = cargo_bin("mcp-warden");

    let mut child = Command::new(&bin)
        .arg("mcp")
        .env("MCP_WARDEN_BACKEND", "memory")
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        // Force verbose tracing — we want to prove that even with logs
        // enabled, none of them leak from stderr onto stdout.
        .env("RUST_LOG", "debug")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp-warden mcp");

    let mut stdin = child.stdin.take().expect("stdin pipe");
    let stdout = child.stdout.take().expect("stdout pipe");

    let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let lines_w = Arc::clone(&lines);
    let reader = thread::spawn(move || {
        let r = BufReader::new(stdout);
        for line in r.lines().map_while(Result::ok) {
            lines_w.lock().unwrap().push(line);
        }
    });

    let initialize = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "warden-stdout-test", "version": "0.0.0" }
        }
    });
    writeln!(stdin, "{initialize}").expect("write initialize");
    stdin.flush().expect("flush stdin");

    // Wait for the initialize response (at most ~5s).
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if !lines.lock().unwrap().is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }

    let initialized = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    let _ = writeln!(stdin, "{initialized}");
    drop(stdin); // EOF should cause the server to shut down.

    // Give the server a moment to exit on its own; kill if it doesn't.
    let exit_deadline = Instant::now() + Duration::from_secs(5);
    let exited = loop {
        match child.try_wait() {
            Ok(Some(_)) => break true,
            Ok(None) if Instant::now() < exit_deadline => {
                thread::sleep(Duration::from_millis(50));
            }
            _ => break false,
        }
    };
    if !exited {
        let _ = child.kill();
        let _ = child.wait();
    }
    let _ = reader.join();

    let captured = lines.lock().unwrap().clone();
    assert!(
        !captured.is_empty(),
        "expected the initialize response on stdout — got nothing"
    );

    for (idx, line) in captured.iter().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        if let Err(e) = serde_json::from_str::<serde_json::Value>(line) {
            panic!(
                "stdout line {idx} is not valid JSON-RPC: {line:?}\n\
                 parse error: {e}\n\
                 stdout MUST contain only JSON-RPC frames. \
                 All captured lines: {captured:?}"
            );
        }
    }
}

/// A running `mcp-warden mcp` that has completed the MCP handshake.
struct McpSession {
    child: Child,
    stdin: ChildStdin,
    responses: mpsc::Receiver<Value>,
}

impl McpSession {
    /// Start the server on `config_dir` (memory keychain) and return once it
    /// has answered `initialize` — by then the startup config check has run.
    fn start(config_dir: &Path) -> Self {
        let mut child = Command::new(cargo_bin("mcp-warden"))
            .arg("mcp")
            .env("MCP_WARDEN_BACKEND", "memory")
            .env("MCP_WARDEN_CONFIG_DIR", config_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn mcp-warden mcp");
        let stdin = child.stdin.take().expect("stdin pipe");
        let stdout = child.stdout.take().expect("stdout pipe");
        let (tx, responses) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Ok(v) = serde_json::from_str::<Value>(&line)
                    && tx.send(v).is_err()
                {
                    break;
                }
            }
        });

        let mut session = Self {
            child,
            stdin,
            responses,
        };
        session.request(
            1,
            "initialize",
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "warden-frozen-test", "version": "0.0.0" }
            }),
        );
        session.send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        session
    }

    fn send(&mut self, msg: Value) {
        writeln!(self.stdin, "{msg}").expect("write to server");
        self.stdin.flush().expect("flush stdin");
    }

    /// Send a request and wait (at most ~10s) for the response with `id`.
    fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let msg = self
                .responses
                .recv_timeout(left)
                .unwrap_or_else(|e| panic!("no response to {method} (id {id}): {e}"));
            if msg["id"] == json!(id) {
                return msg;
            }
        }
    }

    fn call_tool(&mut self, id: u64, name: &str, arguments: Value) -> Value {
        self.request(
            id,
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        )
    }
}

impl Drop for McpSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// An `auto` HTTP preset whose secret is not in the (empty) keychain: the
/// startup check would refuse it, and `auto` without `--confirm-auto` is
/// exactly the edit invariant 4 guards against.
const LATE_PRESET: &str = r#"
[[preset]]
name = "late"
type = "http"
description = "added after startup"
base_url = "https://127.0.0.1:9"
auth = { type = "bearer", secret = "late-token" }
allowed_methods = ["GET"]
approval = "auto"
"#;

/// Invariant 10: a preset written to `config.toml` after the server started
/// was never validated, so the server must not serve it until a restart.
#[test]
fn presets_added_after_startup_are_not_served() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut server = McpSession::start(tmp.path());

    std::fs::write(tmp.path().join("config.toml"), LATE_PRESET).expect("rewrite config");

    let listed = server.call_tool(2, "list_presets", json!({}));
    assert_eq!(
        listed["result"]["structuredContent"]["presets"],
        json!([]),
        "list_presets must reflect the startup config: {listed}"
    );

    let proxied = server.call_tool(
        3,
        "proxy_http",
        json!({ "preset_name": "late", "path": "/", "method": "GET" }),
    );
    let message = proxied["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("preset 'late' not found"),
        "proxy_http must not see a preset added after startup: {proxied}"
    );
}

/// Invariant 10: the config is loaded once and frozen, so the server keeps
/// working from its startup snapshot even if the file becomes unreadable.
#[test]
fn config_is_not_reread_after_startup() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut server = McpSession::start(tmp.path());

    std::fs::write(tmp.path().join("config.toml"), "this is [[not toml").expect("rewrite");

    let listed = server.call_tool(2, "list_presets", json!({}));
    assert_eq!(
        listed["result"]["structuredContent"]["presets"],
        json!([]),
        "list_presets must not re-read config.toml: {listed}"
    );
}

/// `mcp-warden lock` stops a running server at its next call, and the
/// server stays locked even if the lock file is deleted by hand.
#[test]
fn lock_refuses_every_call_and_latches() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut server = McpSession::start(tmp.path());
    let listed = server.call_tool(2, "list_presets", json!({}));
    assert!(
        listed["error"].is_null(),
        "unlocked server answers: {listed}"
    );

    let status = Command::new(cargo_bin("mcp-warden"))
        .args(["lock", "--reason", "integration test"])
        .env("MCP_WARDEN_BACKEND", "memory")
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .status()
        .expect("run mcp-warden lock");
    assert!(status.success());

    let locked = server.call_tool(3, "list_presets", json!({}));
    let message = locked["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("locked"),
        "locked server refuses: {locked}"
    );

    std::fs::remove_file(tmp.path().join("lock")).expect("remove lock file");
    let still = server.call_tool(
        4,
        "proxy_http",
        json!({ "preset_name": "any", "path": "/", "method": "GET" }),
    );
    let message = still["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("locked"),
        "deleting the file must not unlock a running server: {still}"
    );
}
