use crate::scan::{Finding, Options, scan};
use clap::Args;
use mcp_warden_core::error::{Result, WardenError};
use std::path::{Path, PathBuf};

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Also scan this project directory (repeatable). The current
    /// directory is always scanned.
    #[arg(long = "path", value_name = "DIR")]
    pub paths: Vec<PathBuf>,
    /// Skip user-level client configs (~/.claude.json, Claude Desktop,
    /// Cursor, Windsurf, VS Code, Codex).
    #[arg(long)]
    pub no_home: bool,
    /// Output format: `text` or `json`.
    #[arg(long, default_value = "text")]
    pub format: String,
    /// Exit 1 when anything is found (for CI).
    #[arg(long)]
    pub fail_on_findings: bool,
}

/// `mcp-warden scan`: report plaintext secrets — where they are and what
/// they look like, never their values.
pub fn run(args: ScanArgs) -> Result<()> {
    let mut dirs = vec![std::env::current_dir().map_err(WardenError::Io)?];
    dirs.extend(args.paths);
    let home = (!args.no_home).then(dirs::home_dir).flatten();
    let report = scan(&Options {
        config_dir: home.as_ref().and_then(|_| dirs::config_dir()),
        home: home.clone(),
        dirs,
    });
    let show = |p: &Path| display_path(p, home.as_deref());

    if args.format == "json" {
        let findings: Vec<serde_json::Value> = report
            .findings
            .iter()
            .map(|f| {
                let mut v = serde_json::to_value(f).unwrap_or_default();
                v["file"] = show(&f.file).into();
                v
            })
            .collect();
        let out = serde_json::json!({
            "files_checked": report.files_checked,
            "findings": findings,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    } else {
        print_text(&report.findings, report.files_checked, &show);
    }
    if args.fail_on_findings && !report.findings.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

fn print_text(findings: &[Finding], files_checked: usize, show: &dyn Fn(&Path) -> String) {
    if findings.is_empty() {
        println!("No plaintext secrets found ({files_checked} files checked).");
        return;
    }
    let mut files = 0;
    let mut last: Option<&Path> = None;
    for f in findings {
        if last != Some(f.file.as_path()) {
            if last.is_some() {
                println!();
            }
            println!("{} ({})", show(&f.file), f.client);
            last = Some(&f.file);
            files += 1;
        }
        let status = if f.import.is_some() { "importable" } else { "" };
        println!(
            "  {:52} {:20} {:22} {status}",
            f.location, f.kind, f.redacted
        );
        if let Some(hint) = f.hint {
            println!("      ↳ {hint}");
        }
    }
    let importable = findings.iter().filter(|f| f.import.is_some()).count();
    println!();
    println!(
        "Found {} plaintext secret{} in {files} of {files_checked} files checked; \
         {importable} can be moved with `mcp-warden import`.",
        findings.len(),
        if findings.len() == 1 { "" } else { "s" },
    );
}

/// `~/…` for paths under the home directory.
fn display_path(path: &Path, home: Option<&Path>) -> String {
    match home.and_then(|h| path.strip_prefix(h).ok()) {
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    }
}
