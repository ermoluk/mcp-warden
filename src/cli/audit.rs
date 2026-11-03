use clap::{Args, Subcommand, ValueEnum};
use mcp_warden_core::approval::sanitise_for_prompt;
use mcp_warden_core::audit::anchor::{self, AnchorCheck};
use mcp_warden_core::audit::{
    AuditDecision, AuditFilter, AuditOutcome, AuditSink, clip, sqlite_sink::LocalSqlite,
};
use mcp_warden_core::error::{Result, WardenError};
use mcp_warden_core::keychain::KeychainStore;
use std::path::Path;

const PRESET_WIDTH: usize = 40;
const SUMMARY_WIDTH: usize = 80;
/// Client names come from the MCP client; keep them short.
const CLIENT_WIDTH: usize = 40;
const MESSAGE_WIDTH: usize = 120;

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub cmd: Option<AuditCmd>,
    /// Number of recent events to display.
    #[arg(long, default_value = "20")]
    pub last: usize,
    /// RFC3339 timestamp; show events at or after this time instead of `--last`.
    #[arg(long)]
    pub since: Option<String>,
    /// Show only events with this decision. Repeat to show several.
    #[arg(long = "decision", value_enum, value_name = "DECISION")]
    pub decisions: Vec<Decision>,
    /// Show approval #N and every call that ran inside the window it opened,
    /// oldest first.
    #[arg(long, value_name = "N", conflicts_with_all = ["since", "last"])]
    pub window: Option<i64>,
}

#[derive(Debug, Subcommand)]
pub enum AuditCmd {
    /// Check the audit log's hash chain, and the log against its anchor in
    /// the keychain. Exits 1 if anything does not hold.
    Verify {
        /// `text` or `json`.
        #[arg(long, default_value = "text")]
        format: String,
    },
}

/// `AuditDecision`, as typed on the command line.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Decision {
    Approved,
    Denied,
    Auto,
    Timeout,
    Windowed,
    Refused,
    Failed,
}

impl From<Decision> for AuditDecision {
    fn from(d: Decision) -> Self {
        match d {
            Decision::Approved => AuditDecision::Approved,
            Decision::Denied => AuditDecision::Denied,
            Decision::Auto => AuditDecision::Auto,
            Decision::Timeout => AuditDecision::Timeout,
            Decision::Windowed => AuditDecision::Windowed,
            Decision::Refused => AuditDecision::Refused,
            Decision::Failed => AuditDecision::Failed,
        }
    }
}

pub fn run(
    args: AuditArgs,
    db_path: &Path,
    kc: &dyn KeychainStore,
    config_dir: &Path,
) -> Result<()> {
    if let Some(AuditCmd::Verify { format }) = args.cmd {
        return verify(&format, db_path, kc, config_dir);
    }
    if !db_path.exists() {
        println!("(no events)");
        return Ok(());
    }
    let sink = LocalSqlite::open(db_path)?;
    let mut filter = AuditFilter {
        decisions: args.decisions.into_iter().map(Into::into).collect(),
        window: args.window,
        ..Default::default()
    };
    if args.window.is_some() {
        // The whole window, however long.
    } else if let Some(s) = args.since {
        let ts = chrono::DateTime::parse_from_rfc3339(&s)
            .map_err(|e| WardenError::Validation(e.to_string()))?
            .with_timezone(&chrono::Utc);
        filter.since = Some(ts);
    } else {
        filter.limit = Some(args.last);
    }
    let mut events = sink.query(&filter)?;
    if let Some(n) = args.window {
        if !events.iter().any(|e| e.id == n) {
            println!("(no event #{n})");
            return Ok(());
        }
        // The approval, then the calls it let through, in order.
        events.reverse();
    }
    if events.is_empty() {
        println!("(no events)");
        return Ok(());
    }
    for e in events {
        let via = e
            .via_event
            .map(|n| format!(" via approval #{n}"))
            .unwrap_or_default();
        let outcome = e.outcome.map(|o| match o {
            AuditOutcome::Err { message } => AuditOutcome::Err {
                message: for_terminal(&message, MESSAGE_WIDTH),
            },
            ok => ok,
        });
        let who = match (&e.client, &e.session) {
            (Some(c), Some(s)) => format!("  ({}, session {s})", for_terminal(c, CLIENT_WIDTH)),
            (None, Some(s)) => format!("  (session {s})"),
            (Some(c), None) => format!("  ({})", for_terminal(c, CLIENT_WIDTH)),
            (None, None) => String::new(),
        };
        println!(
            "{} [{}] {:24} {} {} → {:?}{via} {:?}{who}",
            e.created_at.to_rfc3339(),
            e.id,
            for_terminal(&e.preset, PRESET_WIDTH),
            e.action,
            for_terminal(&e.summary, SUMMARY_WIDTH),
            e.decision,
            outcome,
        );
    }
    Ok(())
}

/// `mcp-warden audit verify`: the chain, then the anchor. A log that holds
/// moves the anchor up to its tip.
fn verify(format: &str, db_path: &Path, kc: &dyn KeychainStore, config_dir: &Path) -> Result<()> {
    if !db_path.exists() {
        let anchored = anchor::read(kc, db_path)?;
        let (ok, text) = match &anchored {
            Some(a) => (
                false,
                format!(
                    "the audit log is missing, but its anchor names record {}: it was deleted",
                    a.seq
                ),
            ),
            None => (true, "no audit log yet".to_string()),
        };
        let problems: Vec<&str> = if ok { vec![] } else { vec![&text] };
        let json = serde_json::json!({ "intact": ok, "problems": problems });
        print_verdict(format, &json, &text);
        return finish(ok);
    }
    let sink = LocalSqlite::open(db_path)?;
    let report = sink.verify_chain()?;
    let check = anchor::check(kc, &sink, db_path)?;
    let anchor_holds = check.holds();
    let ok = report.intact() && anchor_holds;
    let anchor_text = match check {
        AnchorCheck::NotAnchored => "not anchored yet (a new log, or the keychain lost the \
                                     anchor)"
            .to_string(),
        AnchorCheck::Anchored { seq, later: 0 } => format!("anchored through record {seq}"),
        AnchorCheck::Anchored { seq, later } => format!(
            "anchored through record {seq}; {later} later record(s) are covered by the chain \
             only"
        ),
        AnchorCheck::Removed { seq } => format!(
            "records up to {seq} were anchored but are gone: the log was cut short, rolled back \
             or replaced"
        ),
        AnchorCheck::Rewritten { seq } => {
            format!("the log was rewritten: record {seq} no longer has its anchored hash")
        }
    };
    // A log that holds moves its anchor to the tip.
    if ok {
        anchor::advance(kc, &sink, db_path, Some(&config_dir.join("locks")))?;
    }
    let mut text = if report.intact() {
        format!("chain:  intact, {} records", report.records)
    } else {
        "chain:  BROKEN".to_string()
    };
    if report.legacy_rows > 0 {
        text.push_str(&format!(
            " ({} events from before 0.6.0 are not chained)",
            report.legacy_rows
        ));
    }
    for p in &report.problems {
        text.push_str(&format!("\n  - {}", for_terminal(p, 300)));
    }
    if report.more_problems {
        text.push_str("\n  - … and more");
    }
    text.push_str(&format!("\nanchor: {anchor_text}"));
    let json = serde_json::json!({
        "intact": ok,
        "records": report.records,
        "legacy_rows": report.legacy_rows,
        "problems": report.problems,
        "more_problems": report.more_problems,
        "anchor": anchor_text,
        "anchor_holds": anchor_holds,
    });
    print_verdict(format, &json, &text);
    finish(ok)
}

fn print_verdict(format: &str, json: &serde_json::Value, text: &str) {
    if format == "json" {
        println!("{json}");
    } else {
        println!("{text}");
    }
}

/// The verdict is the output; exit 1 so scripts can branch on it.
fn finish(ok: bool) -> Result<()> {
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

/// Preset names, summaries and errors can be agent-supplied (refused calls
/// record them verbatim): strip control characters so they cannot drive the
/// terminal, and cap the width so one event stays one readable line.
fn for_terminal(s: &str, max_chars: usize) -> String {
    clip(&sanitise_for_prompt(s, usize::MAX), max_chars)
}
