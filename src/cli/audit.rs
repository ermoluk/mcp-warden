use clap::Args;
use mcp_warden_core::audit::{AuditSink, sqlite_sink::LocalSqlite};
use mcp_warden_core::error::{Result, WardenError};
use std::path::Path;

#[derive(Debug, Args)]
pub struct AuditArgs {
    /// Number of recent events to display.
    #[arg(long, default_value = "20")]
    pub last: usize,
    /// RFC3339 timestamp; show events at or after this time instead of `--last`.
    #[arg(long)]
    pub since: Option<String>,
}

pub fn run(args: AuditArgs, db_path: &Path) -> Result<()> {
    if !db_path.exists() {
        println!("(no events)");
        return Ok(());
    }
    let sink = LocalSqlite::open(db_path)?;
    let events = if let Some(s) = args.since {
        let ts = chrono::DateTime::parse_from_rfc3339(&s)
            .map_err(|e| WardenError::Validation(e.to_string()))?
            .with_timezone(&chrono::Utc);
        sink.since(ts)?
    } else {
        sink.recent(args.last)?
    };
    if events.is_empty() {
        println!("(no events)");
        return Ok(());
    }
    for e in events {
        println!(
            "{} [{}] {:24} {} → {:?} {:?}",
            e.created_at.to_rfc3339(),
            e.id,
            e.preset,
            e.action,
            e.decision,
            e.outcome,
        );
    }
    Ok(())
}
