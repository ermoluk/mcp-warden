use clap::{Args, ValueEnum};
use mcp_warden_core::approval::sanitise_for_prompt;
use mcp_warden_core::audit::{
    AuditDecision, AuditFilter, AuditOutcome, AuditSink, clip, sqlite_sink::LocalSqlite,
};
use mcp_warden_core::error::{Result, WardenError};
use std::path::Path;

const PRESET_WIDTH: usize = 40;
const SUMMARY_WIDTH: usize = 80;
/// Client names come from the MCP client; keep them short.
const CLIENT_WIDTH: usize = 40;
const MESSAGE_WIDTH: usize = 120;

#[derive(Debug, Args)]
pub struct AuditArgs {
    /// Number of recent events to display.
    #[arg(long, default_value = "20")]
    pub last: usize,
    /// RFC3339 timestamp; show events at or after this time instead of `--last`.
    #[arg(long)]
    pub since: Option<String>,
    /// Show only events with this decision. Repeat to show several.
    #[arg(long = "decision", value_enum, value_name = "DECISION")]
    pub decisions: Vec<Decision>,
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

pub fn run(args: AuditArgs, db_path: &Path) -> Result<()> {
    if !db_path.exists() {
        println!("(no events)");
        return Ok(());
    }
    let sink = LocalSqlite::open(db_path)?;
    let mut filter = AuditFilter {
        decisions: args.decisions.into_iter().map(Into::into).collect(),
        ..Default::default()
    };
    if let Some(s) = args.since {
        let ts = chrono::DateTime::parse_from_rfc3339(&s)
            .map_err(|e| WardenError::Validation(e.to_string()))?
            .with_timezone(&chrono::Utc);
        filter.since = Some(ts);
    } else {
        filter.limit = Some(args.last);
    }
    let events = sink.query(&filter)?;
    if events.is_empty() {
        println!("(no events)");
        return Ok(());
    }
    for e in events {
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
            "{} [{}] {:24} {} {} → {:?} {:?}{who}",
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

/// Preset names, summaries and errors can be agent-supplied (refused calls
/// record them verbatim): strip control characters so they cannot drive the
/// terminal, and cap the width so one event stays one readable line.
fn for_terminal(s: &str, max_chars: usize) -> String {
    clip(&sanitise_for_prompt(s, usize::MAX), max_chars)
}
