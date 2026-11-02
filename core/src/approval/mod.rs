//! Core approval surface — trait + request/decision types.
//!
//! Concrete transports (`DesktopApproval`, `TuiApproval`, `TelegramApproval`,
//! `AlwaysDeny`) live in the `mcp-warden` binary crate. Paid implementations
//! (mobile push, cloud relay, …) can be added as additional impls of
//! `ApprovalTransport` without touching this crate — that's the whole point
//! of the trait seam.

use crate::error::Result;
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub preset: String,
    pub action: String,
    pub summary: String,
    pub timeout: std::time::Duration,
    /// Cap (seconds) for an approve-for-window option. `None` means the
    /// preset disables windowing for this action; the transport must NOT
    /// offer the window choice. `Some(n)` is the maximum window length
    /// the executor will honour if the user chooses it.
    pub window_seconds: Option<u64>,
    /// When an approve-for-window choice made now would end, as the prompt
    /// shows it. The executor fixes it when the prompt is shown and ends the
    /// window at exactly this time, so a late click gets a shorter window,
    /// never a longer one. `None` when no window is offered (or the caller
    /// left it to the transport, which then counts from its own `now`).
    pub window_until: Option<chrono::DateTime<chrono::Local>>,
}

impl ApprovalRequest {
    pub fn new(preset: String, action: String, summary: String) -> Self {
        Self {
            preset,
            action,
            summary,
            timeout: std::time::Duration::from_secs(60),
            window_seconds: None,
            window_until: None,
        }
    }

    pub fn with_window(mut self, window_seconds: Option<u64>) -> Self {
        self.window_seconds = window_seconds.filter(|n| *n > 0);
        self
    }

    pub fn with_window_until(mut self, until: chrono::DateTime<chrono::Local>) -> Self {
        self.window_until = Some(until);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approved,
    /// Approved AND the executor should remember this approval for the
    /// preset+action pair until the window expires. Transports only emit
    /// this when `ApprovalRequest.window_seconds` was `Some`.
    ApprovedForWindow,
    Denied,
    Timeout,
}

#[async_trait]
pub trait ApprovalTransport: Send + Sync {
    async fn request(&self, req: ApprovalRequest) -> Result<ApprovalDecision>;
}

/// Sanitise text destined for an OS notification, a dialog, a terminal or
/// the audit views.
///
/// - Control characters (Unicode category Cc: newlines, terminal escapes)
///   are removed, so a crafted name cannot add lines or drive a terminal.
/// - Characters that are invisible or reorder what is around them are
///   turned into a visible `\u{XXXX}` escape: format characters (Cf — bidi
///   overrides, embeddings and isolates, zero-width spaces and joiners,
///   the BOM, soft hyphen, tag characters), the line and paragraph
///   separators (Zl, Zp, which many UIs break lines on) and the Hangul
///   fillers, which render as blank letters. A path such as
///   `/srv/app/\u{202E}gol.cod` then reads as written instead of reversed.
/// - A character keeps at most two combining marks; further ones in the
///   same run are escaped, so stacked marks cannot paint over other lines.
///
/// The result is at most `max_len` characters, an escape counting as its
/// full length.
pub fn sanitise_for_prompt(input: &str, max_len: usize) -> String {
    const MAX_MARKS: usize = 2;
    let mut out = String::new();
    let mut len = 0;
    let mut marks = 0;
    for c in input.chars() {
        if c.is_control() {
            continue;
        }
        let mark = unicode_normalization::char::is_combining_mark(c);
        marks = if mark { marks + 1 } else { 0 };
        if is_hidden(c) || marks > MAX_MARKS {
            let escape = format!("\\u{{{:04X}}}", c as u32);
            let n = escape.chars().count();
            if len + n > max_len {
                break;
            }
            out.push_str(&escape);
            len += n;
        } else {
            if len + 1 > max_len {
                break;
            }
            out.push(c);
            len += 1;
        }
    }
    out
}

/// Format characters (Cf), the line and paragraph separators (Zl, Zp) and
/// the Hangul fillers: characters a reader cannot see, or that change how
/// the text around them is laid out. The Cf ranges are those of Unicode 16.
fn is_hidden(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{115F}'..='\u{1160}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitise_strips_newlines_and_escapes() {
        let evil = "preset\n\u{1b}[31mfake\u{1b}[0m";
        let s = sanitise_for_prompt(evil, 100);
        assert!(!s.contains('\n'));
        assert!(!s.contains('\u{1b}'));
    }

    /// Every class of character that can hide, reorder or break the text a
    /// human reads in a prompt comes out as a visible `\u{XXXX}` escape.
    #[test]
    fn invisible_and_reordering_characters_are_made_visible() {
        for (class, c) in [
            ("bidi override RLO", '\u{202E}'),
            ("bidi embedding LRE", '\u{202A}'),
            ("bidi isolate RLI", '\u{2067}'),
            ("bidi isolate end PDI", '\u{2069}'),
            ("right-to-left mark", '\u{200F}'),
            ("arabic letter mark", '\u{061C}'),
            ("zero-width space", '\u{200B}'),
            ("zero-width joiner", '\u{200D}'),
            ("word joiner", '\u{2060}'),
            ("byte order mark", '\u{FEFF}'),
            ("soft hyphen", '\u{00AD}'),
            ("tag character", '\u{E0041}'),
            ("interlinear annotation", '\u{FFF9}'),
            ("line separator", '\u{2028}'),
            ("paragraph separator", '\u{2029}'),
            ("hangul filler", '\u{3164}'),
        ] {
            let got = sanitise_for_prompt(&format!("a{c}b"), 100);
            assert_eq!(
                got,
                format!("a\\u{{{:04X}}}b", c as u32),
                "{class} (U+{:04X})",
                c as u32
            );
        }
    }

    /// `get /srv/x` followed by U+202E and a reversed tail reads, once
    /// rendered, as something else; with the override escaped it cannot.
    #[test]
    fn a_bidi_spoofed_path_reads_as_written() {
        let spoof = "sftp put /srv/app/\u{202E}gol.cod\u{202C} ↔ /Users/me/.ssh/id_ed25519";
        let shown = sanitise_for_prompt(spoof, 480);
        assert!(
            !shown
                .chars()
                .any(|c| ('\u{202A}'..='\u{202E}').contains(&c))
        );
        assert!(shown.contains("\\u{202E}gol.cod\\u{202C}"), "{shown}");
    }

    /// Long runs of combining marks (Zalgo text) stack over neighbouring
    /// lines; the first two marks on a character stay, the rest are escaped.
    #[test]
    fn long_combining_runs_are_cut_to_two_marks() {
        let zalgo = format!("x{}y", "\u{0301}".repeat(40));
        let shown = sanitise_for_prompt(&zalgo, 10_000);
        assert!(shown.starts_with("x\u{0301}\u{0301}\\u{0301}"), "{shown}");
        assert_eq!(shown.matches('\u{0301}').count(), 2, "{shown}");
        assert!(shown.ends_with('y'));
    }

    #[test]
    fn ordinary_text_is_untouched() {
        for text in [
            "GET /repos/o/r",
            "привет мир",
            "日本語のテキスト",
            "café ệ",
            "e\u{0301}\u{0302}",
            "❤\u{FE0F} 👍🏽",
        ] {
            assert_eq!(sanitise_for_prompt(text, 100), text);
        }
    }

    #[test]
    fn escapes_count_towards_the_limit() {
        let s = sanitise_for_prompt(&"\u{202E}".repeat(100), 20);
        assert!(s.chars().count() <= 20, "{s}");
        assert_eq!(s, "\\u{202E}\\u{202E}");
    }

    #[test]
    fn sanitise_truncates() {
        let s = sanitise_for_prompt(&"a".repeat(1000), 10);
        assert_eq!(s.len(), 10);
    }
}
