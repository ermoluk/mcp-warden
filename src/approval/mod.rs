//! Concrete approval transports — impls of `mcp_warden_core::approval::ApprovalTransport`.
//!
//! Each transport delivers an approval request to the human and waits for
//! Approve / Deny / Timeout. The trait + request/decision types live in
//! `mcp_warden_core::approval`; this module only contains the impls.

pub mod always_deny;
pub mod desktop;
mod dialog;
pub mod osascript;
pub mod powershell;
pub mod telegram;
pub mod tui;

use chrono::{DateTime, Local, Timelike};
use mcp_warden_core::approval::{ApprovalRequest, sanitise_for_prompt};

/// Button text for the approve-for-window choice: whole minutes when the
/// window is a multiple of 60 s, seconds otherwise.
pub fn window_label(seconds: u64) -> String {
    if seconds >= 60 && seconds.is_multiple_of(60) {
        format!("Approve for {} min", seconds / 60)
    } else {
        format!("Approve for {seconds} s")
    }
}

/// The approve-for-window choice, spelled out for every transport — the
/// macOS and Windows dialogs, the Linux notification, Telegram and the TUI:
///
/// `Approve for 10 min: every proxy_http call github-read allows runs without asking until 14:32`
///
/// `None` when the request offers no window. The time is the request's
/// `window_until` (which the executor fixes when the prompt is shown);
/// without one it counts from now.
pub fn window_button(req: &ApprovalRequest) -> Option<String> {
    let seconds = req.window_seconds?;
    let now = Local::now();
    let until = req
        .window_until
        .unwrap_or_else(|| window_deadline(now, seconds));
    Some(window_text(&req.action, &req.preset, seconds, until, now))
}

/// `window_button`'s text for a window of `seconds` ending at `until`, as
/// seen at `now`. Preset and action are sanitised like the rest of the
/// prompt, so the text is one line without control characters.
pub fn window_text(
    action: &str,
    preset: &str,
    seconds: u64,
    until: DateTime<Local>,
    now: DateTime<Local>,
) -> String {
    let action = sanitise_for_prompt(action, 32);
    let preset = sanitise_for_prompt(preset, 64);
    format!(
        "{}: every {action} call {preset} allows runs without asking until {}",
        window_label(seconds),
        clock_time(seconds, until, now)
    )
}

/// When a window of `seconds` offered at `now` ends: `now + seconds`, rounded
/// down to what the prompt shows — the minute for windows of ten minutes or
/// more, the second otherwise — so the window ends exactly at the time on
/// the button.
pub fn window_deadline(now: DateTime<Local>, seconds: u64) -> DateTime<Local> {
    let end = now + chrono::Duration::seconds(i64::try_from(seconds).unwrap_or(i64::MAX / 2));
    let end = end.with_nanosecond(0).unwrap_or(end);
    if shown_to_the_minute(seconds) {
        end.with_second(0).unwrap_or(end)
    } else {
        end
    }
}

fn shown_to_the_minute(seconds: u64) -> bool {
    seconds >= 600
}

/// `14:32` (or `14:32:05` for a short window), with the date in front when
/// it isn't today: `Oct 30 09:15`.
fn clock_time(seconds: u64, at: DateTime<Local>, now: DateTime<Local>) -> String {
    let time = if shown_to_the_minute(seconds) {
        "%H:%M"
    } else {
        "%H:%M:%S"
    };
    if at.date_naive() == now.date_naive() {
        at.format(time).to_string()
    } else {
        at.format(&format!("%b %-d {time}")).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Local, NaiveDate, TimeZone};

    fn at(h: u32, m: u32, s: u32) -> chrono::DateTime<Local> {
        let naive = NaiveDate::from_ymd_opt(2026, 1, 15)
            .unwrap()
            .and_hms_opt(h, m, s)
            .unwrap();
        Local.from_local_datetime(&naive).earliest().unwrap()
    }

    fn req(window: Option<u64>) -> ApprovalRequest {
        ApprovalRequest::new("github-read".into(), "proxy_http".into(), "GET /x".into())
            .with_window(window)
    }

    #[test]
    fn window_text_says_what_the_window_covers() {
        assert_eq!(
            window_text(
                "proxy_http",
                "github-read",
                600,
                at(14, 32, 0),
                at(14, 22, 0)
            ),
            "Approve for 10 min: every proxy_http call github-read allows runs \
             without asking until 14:32"
        );
    }

    #[test]
    fn window_text_names_the_day_when_it_ends_tomorrow() {
        let until = at(0, 5, 0) + chrono::Duration::days(1);
        let text = window_text("ssh_exec", "deploy", 1800, until, at(23, 35, 0));
        assert!(
            text.ends_with(&until.format("until %b %-d 00:05").to_string()),
            "{text}"
        );
    }

    #[test]
    fn window_text_shows_seconds_for_short_windows() {
        let text = window_text("db_query", "pg", 90, at(9, 1, 45), at(9, 0, 15));
        assert!(text.starts_with("Approve for 90 s: "), "{text}");
        assert!(text.ends_with("until 09:01:45"), "{text}");
    }

    #[test]
    fn window_text_is_sanitised_and_one_line() {
        let text = window_text(
            "proxy_http\n",
            "evil\nApproval: auto\u{1b}[0m",
            600,
            at(14, 32, 0),
            at(14, 22, 0),
        );
        assert!(!text.chars().any(char::is_control), "{text:?}");
        assert!(text.contains("call evilApproval: auto[0m allows"), "{text}");
        let long = "p".repeat(200);
        let text = window_text("proxy_http", &long, 600, at(14, 32, 0), at(14, 22, 0));
        assert!(text.contains(&"p".repeat(64)) && !text.contains(&"p".repeat(65)));
    }

    #[test]
    fn deadline_is_rounded_down_to_what_is_shown() {
        // Ten minutes or more: shown and ended to the minute.
        assert_eq!(window_deadline(at(14, 22, 40), 600), at(14, 32, 0));
        assert_eq!(window_deadline(at(14, 22, 0), 600), at(14, 32, 0));
        // Shorter windows: to the second, so they never shrink to nothing.
        assert_eq!(window_deadline(at(14, 22, 59), 60), at(14, 23, 59));
        let ms = at(14, 22, 10) + chrono::Duration::milliseconds(700);
        assert_eq!(window_deadline(ms, 45), at(14, 22, 55));
    }

    #[test]
    fn window_button_uses_the_requested_deadline() {
        assert_eq!(window_button(&req(None)), None);
        let r = req(Some(600)).with_window_until(at(14, 32, 0));
        let text = window_button(&r).unwrap();
        assert!(text.starts_with("Approve for 10 min: every proxy_http call github-read"));
        assert!(text.contains("until "), "{text}");
        assert!(!text.contains('\n'));
    }
}
