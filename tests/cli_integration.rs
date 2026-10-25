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
