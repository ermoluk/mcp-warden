use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::Path;

fn cmd() -> Command {
    let mut c = Command::cargo_bin("mcp-warden").unwrap();
    c.env("MCP_WARDEN_BACKEND", "memory");
    c
}

/// Seed a config dir with a single preset that has approval = "prompt"
/// and no window set, then return the dir's path.
fn seed_prompt_preset(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    let cfg = r#"
[[preset]]
name = "github-read"
type = "http"
description = "GitHub API"
base_url = "https://api.github.com"
auth = { type = "bearer", secret = "gh_pat" }
allowed_methods = ["GET"]
approval = "prompt"
"#;
    fs::write(dir.join("config.toml"), cfg).unwrap();
}

#[test]
fn secret_list_empty() {
    cmd()
        .args(["secret", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("(no secrets)"));
}

#[test]
fn secret_add_then_list() {
    // Each `assert_cmd` call is a separate subprocess with a fresh in-memory
    // store, so add + list happens in one invocation isn't possible. Instead
    // we add and verify success; list-after-add coverage lives in the unit
    // tests of the InMemoryKeychain.
    cmd()
        .args(["secret", "add", "github_pat"])
        .write_stdin("ghp_fake\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("Stored 'github_pat'"));
}

#[test]
fn secret_add_rejects_empty_value() {
    cmd()
        .args(["secret", "add", "x"])
        .write_stdin("\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("empty secret"));
}

#[test]
fn secret_remove_succeeds_even_if_absent() {
    cmd()
        .args(["secret", "remove", "never-existed"])
        .assert()
        .success();
}

#[test]
fn approval_command_sets_window_seconds() {
    let tmp = tempfile::tempdir().unwrap();
    seed_prompt_preset(tmp.path());
    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .args(["approval", "github-read", "prompt", "--window", "900"])
        .assert()
        .success()
        .stderr(predicate::str::contains("window: 900s"));

    let cfg = fs::read_to_string(tmp.path().join("config.toml")).unwrap();
    assert!(
        cfg.contains("approval_window_seconds = 900"),
        "config did not contain window field: {cfg}"
    );
}

#[test]
fn approval_command_window_zero_clears_field() {
    let tmp = tempfile::tempdir().unwrap();
    seed_prompt_preset(tmp.path());
    // First set a window.
    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .args(["approval", "github-read", "prompt", "--window", "600"])
        .assert()
        .success();
    // Then clear it.
    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .args(["approval", "github-read", "prompt", "--window", "0"])
        .assert()
        .success();

    let cfg = fs::read_to_string(tmp.path().join("config.toml")).unwrap();
    assert!(
        !cfg.contains("approval_window_seconds"),
        "field should have been removed: {cfg}"
    );
}

#[test]
fn approval_command_clears_window_when_switching_to_deny() {
    let tmp = tempfile::tempdir().unwrap();
    seed_prompt_preset(tmp.path());
    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .args(["approval", "github-read", "prompt", "--window", "600"])
        .assert()
        .success();
    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .args(["approval", "github-read", "deny"])
        .assert()
        .success();

    let cfg = fs::read_to_string(tmp.path().join("config.toml")).unwrap();
    assert!(!cfg.contains("approval_window_seconds"), "{cfg}");
    assert!(cfg.contains("approval = \"deny\""), "{cfg}");
}

const OPEN_PATHS_WARNING: &str =
    "preset 'github-read' has no allowed_paths: every path under https://api.github.com is allowed";

#[test]
fn doctor_warns_on_http_preset_without_allowed_paths() {
    let tmp = tempfile::tempdir().unwrap();
    seed_prompt_preset(tmp.path());
    // The in-memory keychain is empty, so validation fails; the warning is
    // about the config itself and must still be printed.
    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains(OPEN_PATHS_WARNING));
}

#[test]
fn doctor_does_not_warn_when_allowed_paths_set() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = r#"
[[preset]]
name = "github-read"
type = "http"
description = "GitHub API"
base_url = "https://api.github.com"
auth = { type = "bearer", secret = "gh_pat" }
allowed_methods = ["GET"]
allowed_paths = ["/user/repos"]
approval = "prompt"
"#;
    fs::write(tmp.path().join("config.toml"), cfg).unwrap();
    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .arg("doctor")
        .assert()
        .success()
        // Parsed (validation then fails on the empty in-memory keychain), so
        // the absence of the warning is meaningful.
        .stdout(predicate::str::contains("validation: FAIL"))
        .stdout(predicate::str::contains("has no allowed_paths").not());
}

fn preset_add_github(dir: &Path, extra: &[&str]) -> assert_cmd::assert::Assert {
    fs::write(dir.join("config.toml"), "").unwrap();
    let mut args = vec![
        "preset",
        "add",
        "github-read",
        "--type",
        "http",
        "--base-url",
        "https://api.github.com",
        "--auth-bearer",
        "gh_pat",
        "--allowed-methods",
        "GET",
    ];
    args.extend_from_slice(extra);
    // Each subprocess gets an empty in-memory keychain, so the command still
    // fails validation on the missing secret after warning. The success path
    // (warning does not fail the add) is covered by the unit tests in
    // src/cli/preset.rs.
    cmd().env("MCP_WARDEN_CONFIG_DIR", dir).args(&args).assert()
}

#[test]
fn preset_add_http_without_allowed_paths_warns() {
    let tmp = tempfile::tempdir().unwrap();
    preset_add_github(tmp.path(), &[]).stderr(predicate::str::contains(format!(
        "warning: {OPEN_PATHS_WARNING}"
    )));
}

#[test]
fn preset_add_http_with_allowed_paths_does_not_warn() {
    let tmp = tempfile::tempdir().unwrap();
    preset_add_github(tmp.path(), &["--allowed-paths", "/user/repos"])
        // Reached validation, i.e. past the point where the warning is printed.
        .stderr(predicate::str::contains("missing secret"))
        .stderr(predicate::str::contains("has no allowed_paths").not());
}

#[test]
fn scaffold_github_read_dry_run_explains_open_paths() {
    let out = cmd()
        .args(["preset", "scaffold", "github-read", "--dry-run"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let out = String::from_utf8(out).unwrap();
    let note = out
        .find("#   allowed_paths = [\"/user/repos\", \"/repos/OWNER/[^/]+\"]")
        .unwrap_or_else(|| panic!("missing allowed_paths example: {out}"));
    assert!(out.contains("fine-grained"), "missing PAT advice: {out}");
    let preset = out.find("[[preset]]").unwrap();
    assert!(note < preset, "note must sit above the preset: {out}");
    // The comment must not change what the preset does.
    let parsed: toml::Value = toml::from_str(&out).unwrap();
    assert!(parsed["preset"][0].get("allowed_paths").is_none(), "{out}");
}

#[test]
fn scaffold_github_read_warns_when_writing_config() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("config.toml"), "").unwrap();
    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .args(["preset", "scaffold", "github-read"])
        .assert()
        .success()
        .stderr(predicate::str::contains(format!(
            "warning: {OPEN_PATHS_WARNING}"
        )));
}

fn seed_refused_event(dir: &Path, summary: &str) {
    use mcp_warden_core::audit::{AuditDecision, AuditOutcome, AuditSink};
    let sink =
        mcp_warden_core::audit::sqlite_sink::LocalSqlite::open(&dir.join("audit.db")).unwrap();
    let id = sink
        .record_pending("github-read", "proxy_http", summary)
        .unwrap();
    sink.record_decision(id, AuditDecision::Refused).unwrap();
    sink.record_outcome(
        id,
        AuditOutcome::Err {
            message: "validation error: path not allowed".into(),
        },
    )
    .unwrap();
}

#[test]
fn audit_prints_what_the_agent_asked_for() {
    let tmp = tempfile::tempdir().unwrap();
    seed_refused_event(tmp.path(), "DELETE /repos/me/app");
    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .arg("audit")
        .assert()
        .success()
        .stdout(predicate::str::contains("DELETE /repos/me/app"))
        .stdout(predicate::str::contains("Refused"));
}

fn seed_event(dir: &Path, summary: &str, decision: mcp_warden_core::audit::AuditDecision) {
    use mcp_warden_core::audit::AuditSink;
    let sink =
        mcp_warden_core::audit::sqlite_sink::LocalSqlite::open(&dir.join("audit.db")).unwrap();
    let id = sink
        .record_pending("github-read", "proxy_http", summary)
        .unwrap();
    sink.record_decision(id, decision).unwrap();
}

#[test]
fn audit_filters_by_decision_and_repeats_the_flag() {
    use mcp_warden_core::audit::AuditDecision;
    let tmp = tempfile::tempdir().unwrap();
    seed_event(tmp.path(), "GET /approved", AuditDecision::Approved);
    seed_event(tmp.path(), "GET /refused", AuditDecision::Refused);
    seed_event(tmp.path(), "GET /failed", AuditDecision::Failed);
    seed_event(tmp.path(), "GET /windowed", AuditDecision::Windowed);
    let out = cmd()
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .args(["audit", "--decision", "refused", "--decision", "failed"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let out = String::from_utf8(out).unwrap();
    assert!(
        out.contains("GET /refused") && out.contains("GET /failed"),
        "{out}"
    );
    assert!(
        !out.contains("GET /approved") && !out.contains("GET /windowed"),
        "{out}"
    );

    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .args(["audit", "--decision", "denied"])
        .assert()
        .success()
        .stdout(predicate::str::contains("(no events)"));
    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .args(["audit", "--decision", "maybe"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("approved"));
}

#[test]
fn audit_truncates_long_summaries_and_strips_control_chars() {
    let tmp = tempfile::tempdir().unwrap();
    let summary = format!("GET /\u{1b}[2J{}TAIL", "a".repeat(500));
    seed_refused_event(tmp.path(), &summary);
    let out = cmd()
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .arg("audit")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let out = String::from_utf8(out).unwrap();
    assert!(out.contains("GET /[2Jaaa"), "summary missing: {out}");
    assert!(out.contains('…'), "long summary not marked as cut: {out}");
    assert!(!out.contains("TAIL"), "long summary not truncated: {out}");
    assert!(
        !out.contains('\u{1b}'),
        "control chars reach the terminal: {out}"
    );
}

/// Config with one preset of each kind the policy simulator handles.
fn seed_simulator_presets(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    let cfg = r#"
[[preset]]
name = "gh"
type = "http"
description = "GitHub"
base_url = "https://api.github.com"
auth = { type = "bearer", secret = "gh_pat" }
allowed_methods = ["GET"]
allowed_paths = ["/repos/o/[^/]+"]
approval = "prompt"
approval_window_seconds = 600

[[preset]]
name = "deploy"
type = "ssh"
description = "deploy box"
host = "example.com"
user = "deploy"
secret = "deploy_key"
allowed_commands = ["docker compose (pull|up -d)"]
approval = "auto"

[[preset]]
name = "pg"
type = "postgres"
description = "db"
host = "localhost"
secret = "pg_pw"
approval = "deny"

[[preset.queries]]
name = "user_by_id"
template = "select * from users where id = $1"
param_types = ["int8"]
"#;
    fs::write(dir.join("config.toml"), cfg).unwrap();
}

fn simulate(dir: &Path, args: &[&str]) -> assert_cmd::assert::Assert {
    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", dir)
        .args(["preset", "test"])
        .args(args)
        .assert()
}

#[test]
fn preset_test_simulates_an_allowed_http_call() {
    let tmp = tempfile::tempdir().unwrap();
    seed_simulator_presets(tmp.path());
    simulate(tmp.path(), &["gh", "GET", "/repos/o/r"])
        .success()
        .stdout(predicate::str::contains(
            "ALLOWED — would ask for approval (prompt; approve for 10 min available)",
        ));
}

#[test]
fn preset_test_refuses_a_path_outside_the_allow_list() {
    let tmp = tempfile::tempdir().unwrap();
    seed_simulator_presets(tmp.path());
    simulate(tmp.path(), &["gh", "GET", "/repos/o/r/collaborators"])
        .code(1)
        .stdout(predicate::str::starts_with("REFUSED — "));
    simulate(tmp.path(), &["gh", "DELETE", "/repos/o/r"])
        .code(1)
        .stdout(predicate::str::contains("DELETE"));
}

#[test]
fn preset_test_simulates_ssh_and_db_calls() {
    let tmp = tempfile::tempdir().unwrap();
    seed_simulator_presets(tmp.path());
    simulate(tmp.path(), &["deploy", "--command", "docker compose pull"])
        .success()
        .stdout(predicate::str::contains(
            "ALLOWED — runs without asking (auto)",
        ));
    simulate(
        tmp.path(),
        &["deploy", "--command", "docker compose pull; id"],
    )
    .code(1);
    simulate(
        tmp.path(),
        &["pg", "--query", "user_by_id", "--params", "1"],
    )
    .code(1)
    .stdout(predicate::str::contains("REFUSED — preset policy is deny"));
    simulate(tmp.path(), &["deploy", "GET", "/"])
        .code(1)
        .stdout(predicate::str::contains("not an http preset"));
}

#[test]
fn preset_test_json_verdict() {
    let tmp = tempfile::tempdir().unwrap();
    seed_simulator_presets(tmp.path());
    let out = simulate(tmp.path(), &["gh", "GET", "/repos/o/r", "--format", "json"])
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["tool"], "proxy_http");
    assert_eq!(v["allowed"], true);
    assert_eq!(v["approval"], "prompt");
    assert_eq!(v["approval_window_seconds"], 600);
}

#[test]
fn preset_test_unknown_preset_fails() {
    let tmp = tempfile::tempdir().unwrap();
    seed_simulator_presets(tmp.path());
    simulate(tmp.path(), &["nope", "GET", "/"]).failure();
}

#[test]
fn preset_grant_and_revoke_set_and_clear_expiry() {
    let tmp = tempfile::tempdir().unwrap();
    seed_simulator_presets(tmp.path());
    let cfg = || fs::read_to_string(tmp.path().join("config.toml")).unwrap();
    let preset = |name: &str| -> toml::Value {
        let v: toml::Value = toml::from_str(&cfg()).unwrap();
        v["preset"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"].as_str() == Some(name))
            .unwrap()
            .clone()
    };
    let expiry = |name: &str| -> Option<chrono::DateTime<chrono::Utc>> {
        preset(name)
            .get("expires_at")
            .map(|v| v.as_str().unwrap().parse().unwrap())
    };

    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .args(["preset", "grant", "gh", "--for", "1h"])
        .assert()
        .success();
    let until = expiry("gh").expect("grant sets expires_at");
    let left = until - chrono::Utc::now();
    assert!(left > chrono::Duration::minutes(59) && left <= chrono::Duration::hours(1));
    simulate(tmp.path(), &["gh", "GET", "/repos/o/r"]).success();

    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .args(["preset", "revoke", "gh"])
        .assert()
        .success();
    assert!(expiry("gh").unwrap() <= chrono::Utc::now());
    simulate(tmp.path(), &["gh", "GET", "/repos/o/r"])
        .code(1)
        .stdout(predicate::str::contains("expired"));

    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .args(["preset", "grant", "gh", "--permanent"])
        .assert()
        .success();
    assert_eq!(expiry("gh"), None);

    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .args(["preset", "grant", "gh", "--for", "31d"])
        .assert()
        .failure();
    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .args(["preset", "grant", "gh"])
        .assert()
        .failure();
}

#[test]
fn server_add_list_remove() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", dir)
        .args(["server", "add", "github", "--env", "GITHUB_TOKEN", "--"])
        .args(["npx", "-y", "@modelcontextprotocol/server-github"])
        .write_stdin("test-value\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("\"args\": [\"run\", \"github\"]"))
        .stderr(predicate::str::contains("test-value").not());
    let cfg = fs::read_to_string(dir.join("config.toml")).unwrap();
    assert!(
        cfg.contains("[[server]]") && cfg.contains("env = [\"GITHUB_TOKEN\"]"),
        "{cfg}"
    );
    assert!(!cfg.contains("test-value"));

    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", dir)
        .args(["server", "add", "github", "--", "true"])
        .assert()
        .failure();
    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", dir)
        .args(["server", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[GITHUB_TOKEN]"));
    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", dir)
        .args(["server", "remove", "github"])
        .assert()
        .success();
    assert!(
        !fs::read_to_string(dir.join("config.toml"))
            .unwrap()
            .contains("[[server]]")
    );
}

/// The value of a server key never goes on the command line, and the
/// config can't point a server at another keychain entry.
#[test]
fn server_add_refuses_values_and_foreign_entries() {
    let tmp = tempfile::tempdir().unwrap();
    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .args(["server", "add", "evil", "--env", "X=github_pat", "--", "sh"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("pass only the variable name"));
    // The old `VAR = "entry"` mapping is not a valid config any more.
    fs::write(
        tmp.path().join("config.toml"),
        "[[server]]\nname = \"evil\"\ncommand = \"sh\"\nenv = { X = \"github_pat\" }\n",
    )
    .unwrap();
    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .args(["run", "evil"])
        .assert()
        .failure()
        .stdout("");
}

#[cfg(unix)]
#[test]
fn run_execs_the_server_with_stdio_passed_through() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("config.toml"),
        "[[server]]\nname = \"echo\"\ncommand = \"/bin/sh\"\nargs = [\"-c\", \"read line; echo got:$line\"]\n",
    )
    .unwrap();
    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .args(["run", "echo"])
        .write_stdin("ping\n")
        .assert()
        .success()
        .stdout("got:ping\n");
}

#[test]
fn run_refuses_missing_secret_unknown_server_and_lock_without_stdout() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("config.toml"),
        "[[server]]\nname = \"gh\"\ncommand = \"/bin/sh\"\nenv = [\"TOKEN\"]\n",
    )
    .unwrap();
    let run = |name: &str| {
        cmd()
            .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
            .args(["run", name])
            .assert()
            .failure()
            .stdout("")
    };
    run("gh").stderr(predicate::str::contains(
        "keychain has no 'server/gh/TOKEN'",
    ));
    run("nope").stderr(predicate::str::contains("no [[server]] named 'nope'"));
    cmd()
        .env("MCP_WARDEN_CONFIG_DIR", tmp.path())
        .args(["lock"])
        .assert()
        .success();
    run("gh").stderr(predicate::str::contains("locked"));
}

/// A token-shaped fake, built at runtime so no token literal sits in the
/// repository (and secret scanners don't flag the fixture).
fn fake_github_token() -> String {
    let body: String = (0..36)
        .map(|i| b"Zq8Lm3RtW0xKp7Vb2Nc5Hd9Jf1Gs4Ya6Ue"[(i * 7 + 3) % 34] as char)
        .collect();
    format!("{}{body}", ["gh", "p_"].concat())
}

#[cfg(unix)]
fn scan_fixture() -> (tempfile::TempDir, tempfile::TempDir, String) {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let token = fake_github_token();
    let claude = serde_json::json!({ "mcpServers": {
        "github": { "command": "npx", "env": { "GITHUB_TOKEN": token } }
    }});
    fs::write(home.path().join(".claude.json"), claude.to_string()).unwrap();
    fs::write(project.path().join(".env"), format!("API_TOKEN={token}\n")).unwrap();
    (home, project, token)
}

#[cfg(unix)]
fn scan_cmd(home: &Path, project: &Path) -> Command {
    let mut c = cmd();
    c.env("HOME", home).current_dir(project).arg("scan");
    c
}

// `HOME` redirects the home directory only on unix; on Windows `dirs`
// asks the OS for the profile folder. `scan` itself is covered by
// portable unit tests that pass the home directory explicitly.
#[cfg(unix)]
#[test]
fn scan_reports_locations_without_values() {
    let (home, project, token) = scan_fixture();
    let out = scan_cmd(home.path(), project.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("~/.claude.json (Claude Code)"))
        .stdout(predicate::str::contains(
            "mcpServers.github.env.GITHUB_TOKEN",
        ))
        .stdout(predicate::str::contains("importable"))
        .stdout(predicate::str::contains("API_TOKEN (line 1)"))
        .stdout(predicate::str::contains("Found 2 plaintext secrets"))
        .get_output()
        .clone();
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !all.contains(&token[4..]),
        "a secret leaked into scan output"
    );
}

// `HOME` redirects the home directory only on unix; on Windows `dirs`
// asks the OS for the profile folder. `scan` itself is covered by
// portable unit tests that pass the home directory explicitly.
#[cfg(unix)]
#[test]
fn scan_json_and_fail_on_findings() {
    let (home, project, token) = scan_fixture();
    let out = scan_cmd(home.path(), project.path())
        .args(["--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(!text.contains(&token[4..]));
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["findings"].as_array().unwrap().len(), 2);
    assert_eq!(v["findings"][0]["file"], "~/.claude.json");
    assert_eq!(v["findings"][0]["import"]["var"], "GITHUB_TOKEN");

    scan_cmd(home.path(), project.path())
        .arg("--fail-on-findings")
        .assert()
        .code(1);
    scan_cmd(home.path(), project.path())
        .args(["--no-home", "--format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"files_checked\": 1"));
}

// `HOME` redirects the home directory only on unix; on Windows `dirs`
// asks the OS for the profile folder. `scan` itself is covered by
// portable unit tests that pass the home directory explicitly.
#[cfg(unix)]
#[test]
fn scan_with_nothing_to_find() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    scan_cmd(home.path(), project.path())
        .arg("--fail-on-findings")
        .assert()
        .success()
        .stdout(predicate::str::contains("No plaintext secrets found"));
}

fn import_fixture() -> (tempfile::TempDir, tempfile::TempDir, String) {
    let project = tempfile::tempdir().unwrap();
    let warden = tempfile::tempdir().unwrap();
    let token = fake_github_token();
    let mcp = serde_json::json!({ "mcpServers": {
        "github": { "command": "npx", "args": ["-y", "server-github"], "env": { "GITHUB_TOKEN": token } }
    }});
    fs::write(project.path().join(".mcp.json"), mcp.to_string()).unwrap();
    (project, warden, token)
}

fn import_cmd(project: &Path, warden: &Path) -> Command {
    let mut c = cmd();
    c.env("MCP_WARDEN_CONFIG_DIR", warden)
        .current_dir(project)
        .args(["import", "--no-home"]);
    c
}

#[test]
fn import_rewrites_the_client_config_without_echoing_the_key() {
    let (project, warden, token) = import_fixture();
    let out = import_cmd(project.path(), warden.path())
        .arg("--yes")
        .assert()
        .success()
        .stderr(predicate::str::contains("Moved mcpServers.github"))
        .get_output()
        .clone();
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !all.contains(&token[4..]),
        "the key leaked into import output"
    );
    let after = fs::read_to_string(project.path().join(".mcp.json")).unwrap();
    assert!(!after.contains(&token[4..]));
    let v: serde_json::Value = serde_json::from_str(&after).unwrap();
    assert_eq!(
        v["mcpServers"]["github"]["args"],
        serde_json::json!(["run", "github"])
    );
    let cfg = fs::read_to_string(warden.path().join("config.toml")).unwrap();
    assert!(cfg.contains("env = [\"GITHUB_TOKEN\"]"), "{cfg}");
}

#[test]
fn import_without_a_terminal_needs_yes() {
    let (project, warden, _token) = import_fixture();
    let before = fs::read_to_string(project.path().join(".mcp.json")).unwrap();
    import_cmd(project.path(), warden.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("--yes"));
    import_cmd(project.path(), warden.path())
        .arg("--dry-run")
        .assert()
        .success()
        .stderr(predicate::str::contains("Nothing changed"));
    assert_eq!(
        fs::read_to_string(project.path().join(".mcp.json")).unwrap(),
        before
    );
}
