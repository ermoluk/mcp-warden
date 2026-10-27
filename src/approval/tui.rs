use async_trait::async_trait;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use mcp_warden_core::approval::{
    ApprovalDecision, ApprovalRequest, ApprovalTransport, sanitise_for_prompt,
};
use mcp_warden_core::error::{Result, WardenError};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use std::time::{Duration, Instant};

/// Full-screen ratatui approval dialog. Renders to **stderr** (alternate
/// screen + raw mode) so it never collides with the MCP JSON-RPC channel
/// on stdout. Visible in Claude Code / Cursor's MCP output panel; users
/// can also see it directly when running `mcp-warden mcp` in a TTY.
pub struct TuiApproval {
    default_timeout: Duration,
}

impl TuiApproval {
    pub fn from_stderr() -> Self {
        Self {
            default_timeout: Duration::from_secs(60),
        }
    }
}

impl Default for TuiApproval {
    fn default() -> Self {
        Self::from_stderr()
    }
}

#[async_trait]
impl ApprovalTransport for TuiApproval {
    async fn request(&self, req: ApprovalRequest) -> Result<ApprovalDecision> {
        let timeout = if req.timeout.is_zero() {
            self.default_timeout
        } else {
            req.timeout
        };
        let preset = sanitise_for_prompt(&req.preset, 64);
        let action = sanitise_for_prompt(&req.action, 32);
        let summary = sanitise_for_prompt(&req.summary, 480);
        let window_seconds = req.window_seconds;

        tokio::task::spawn_blocking(move || -> Result<ApprovalDecision> {
            run_dialog(preset, action, summary, timeout, window_seconds)
        })
        .await
        .map_err(|e| WardenError::Executor(e.to_string()))?
    }
}

fn run_dialog(
    preset: String,
    action: String,
    summary: String,
    timeout: Duration,
    window_seconds: Option<u64>,
) -> Result<ApprovalDecision> {
    enable_raw_mode().map_err(WardenError::Io)?;
    let mut stderr = std::io::stderr();
    execute!(stderr, EnterAlternateScreen).map_err(WardenError::Io)?;
    let backend = CrosstermBackend::new(std::io::stderr());
    let mut terminal = Terminal::new(backend).map_err(WardenError::Io)?;

    let started = Instant::now();
    let mut decision: Option<ApprovalDecision> = None;

    let result: Result<ApprovalDecision> = (|| {
        loop {
            let elapsed = started.elapsed();
            if elapsed >= timeout {
                return Ok(ApprovalDecision::Timeout);
            }
            let remaining = timeout.saturating_sub(elapsed);

            terminal
                .draw(|f| draw(f, &preset, &action, &summary, remaining, window_seconds))
                .map_err(WardenError::Io)?;

            // Poll briefly so the countdown refreshes.
            if event::poll(Duration::from_millis(200)).map_err(WardenError::Io)? {
                if let Event::Key(key) = event::read().map_err(WardenError::Io)? {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    match key.code {
                        KeyCode::Char('a' | 'A' | 'y' | 'Y') | KeyCode::Enter => {
                            decision = Some(ApprovalDecision::Approved);
                            break;
                        }
                        KeyCode::Char('w' | 'W') if window_seconds.is_some() => {
                            decision = Some(ApprovalDecision::ApprovedForWindow);
                            break;
                        }
                        KeyCode::Char('d' | 'D' | 'n' | 'N') | KeyCode::Esc => {
                            decision = Some(ApprovalDecision::Denied);
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(decision.unwrap_or(ApprovalDecision::Timeout))
    })();

    // Always restore terminal, even on error.
    let _ = disable_raw_mode();
    let _ = execute!(stderr, LeaveAlternateScreen);
    result
}

/// Format an "Approve for Nm" / "Approve for Ns" string.
fn format_window_label(seconds: u64) -> String {
    format!("[ W ] {}", super::window_label(seconds))
}

fn draw(
    f: &mut ratatui::Frame<'_>,
    preset: &str,
    action: &str,
    summary: &str,
    remaining: Duration,
    window_seconds: Option<u64>,
) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Length(3), // action line
            Constraint::Min(3),    // summary
            Constraint::Length(3), // countdown
            Constraint::Length(3), // hints
        ])
        .split(area);

    let header = Paragraph::new("mcp-warden — approval requested")
        .style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(header, chunks[0]);

    let action_line = Paragraph::new(Line::from(vec![
        Span::styled(
            action.to_string(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  →  "),
        Span::styled(
            preset.to_string(),
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
    ]))
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::ALL).title("action"));
    f.render_widget(action_line, chunks[1]);

    let summary_w = Paragraph::new(summary.to_string())
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title("request"));
    f.render_widget(summary_w, chunks[2]);

    let secs = remaining.as_secs();
    let countdown_color = if secs > 10 { Color::Gray } else { Color::Red };
    let countdown = Paragraph::new(format!("Auto-deny in {secs}s"))
        .style(Style::default().fg(countdown_color))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(countdown, chunks[3]);

    let hints_text = match window_seconds {
        Some(n) => format!(
            "[ A ] / [ Enter ] Approve once   {}   [ D ] / [ Esc ] Deny",
            format_window_label(n)
        ),
        None => "[ A ] / [ Y ] / [ Enter ] Approve     [ D ] / [ N ] / [ Esc ] Deny".to_string(),
    };
    let hints = Paragraph::new(hints_text)
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(hints, chunks[4]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_window_label_uses_minutes_when_aligned() {
        assert_eq!(format_window_label(600), "[ W ] Approve for 10 min");
        assert_eq!(format_window_label(1800), "[ W ] Approve for 30 min");
        assert_eq!(format_window_label(60), "[ W ] Approve for 1 min");
    }

    #[test]
    fn format_window_label_uses_seconds_when_misaligned() {
        assert_eq!(format_window_label(45), "[ W ] Approve for 45 s");
        assert_eq!(format_window_label(90), "[ W ] Approve for 90 s");
    }
}
