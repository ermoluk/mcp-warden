//! MCP stdio protocol integration tests.
//!
//! Pin: stdout is the JSON-RPC channel — every byte on it must be JSON.
//! Logs, panics, and incidental prints must go to stderr or the protocol
//! breaks. CLAUDE.md "What NOT to do" #11 names this guarantee explicitly;
//! this test enforces it.

use assert_cmd::cargo::cargo_bin;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
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
