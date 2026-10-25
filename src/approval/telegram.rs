//! Telegram approval transport.
//!
//! When a preset has `approval = "prompt"`, this transport sends the
//! approval request as a Telegram message with two inline keyboard
//! buttons (Approve / Deny), then long-polls `getUpdates` for the
//! callback. After a decision (or timeout) it edits the message to show
//! the outcome.
//!
//! ## Security
//!
//! 1. **Bot token lives in the keychain.** It is read once at construction
//!    via the OS keychain backend. The token is never logged, never echoed
//!    to stderr, never embedded in the message body.
//! 2. **The chat_id is verified on every callback.** A callback from any
//!    other chat is rejected (so even if someone forwards the prompt and
//!    clicks the button on another account, nothing happens).
//! 3. **The summary passed in `ApprovalRequest.summary` is sanitised** via
//!    `sanitise_for_prompt` before going into the message body, same as
//!    the desktop/TUI transports.
//! 4. **The message uses `protect_content: true`** so it cannot be
//!    forwarded out of the chat.

use async_trait::async_trait;
use mcp_warden_core::approval::{
    ApprovalDecision, ApprovalRequest, ApprovalTransport, sanitise_for_prompt,
};
use mcp_warden_core::error::{Result, WardenError};
use mcp_warden_core::secret::Secret;
use serde::Deserialize;
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const POLL_TIMEOUT_SECS: u64 = 30;
/// Per-prompt timeout when `[approval.telegram] timeout_seconds` is unset.
const DEFAULT_PROMPT_TIMEOUT_SECS: u64 = 120;
const SUMMARY_MAX_CHARS: usize = 600;

pub struct TelegramApproval {
    bot_token: Secret,
    chat_id: i64,
    client: reqwest::Client,
    /// How long one prompt waits for a button press before timing out.
    prompt_timeout: Duration,
    /// Tracks the next `getUpdates` offset so we don't re-consume old
    /// updates if the process restarts mid-poll within one approval.
    next_offset: AtomicU64,
}

impl TelegramApproval {
    /// Build a transport from the bot token and chat id.
    ///
    /// `bot_token` should come from the OS keychain (`KeychainStore::get`).
    /// `chat_id` is the numeric Telegram chat id authorised to approve
    /// requests for this warden instance.
    pub fn new(bot_token: Secret, chat_id: i64) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(POLL_TIMEOUT_SECS + 5))
            .build()
            .unwrap_or_default();
        Self {
            bot_token,
            chat_id,
            client,
            prompt_timeout: Duration::from_secs(DEFAULT_PROMPT_TIMEOUT_SECS),
            next_offset: AtomicU64::new(0),
        }
    }

    /// Override the per-prompt timeout (`[approval.telegram] timeout_seconds`).
    /// `None` or `0` keeps the default.
    pub fn with_timeout(mut self, timeout_seconds: Option<u64>) -> Self {
        if let Some(secs) = timeout_seconds.filter(|n| *n > 0) {
            self.prompt_timeout = Duration::from_secs(secs);
        }
        self
    }

    fn api(&self, method: &str) -> String {
        format!(
            "https://api.telegram.org/bot{}/{}",
            self.bot_token.expose(),
            method
        )
    }
}

#[derive(Debug, Deserialize)]
struct TgResult<T> {
    ok: bool,
    result: Option<T>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SentMessage {
    message_id: i64,
}

#[derive(Debug, Deserialize)]
struct Update {
    update_id: u64,
    #[serde(default)]
    callback_query: Option<CallbackQuery>,
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    id: String,
    #[serde(default)]
    data: Option<String>,
    message: Option<CbMessage>,
}

#[derive(Debug, Deserialize)]
struct CbMessage {
    message_id: i64,
    chat: CbChat,
}

#[derive(Debug, Deserialize)]
struct CbChat {
    id: i64,
}

#[async_trait]
impl ApprovalTransport for TelegramApproval {
    async fn request(&self, req: ApprovalRequest) -> Result<ApprovalDecision> {
        let request_id = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );

        let body = render_body(&req);
        let approve_data = format!("approve:{request_id}");
        let deny_data = format!("deny:{request_id}");
        let window_data = req
            .window_seconds
            .map(|n| format!("window:{n}:{request_id}"));

        let keyboard = build_inline_keyboard(&approve_data, &deny_data, window_data.as_deref());

        let sent: SentMessage = self
            .send_message(&body, &keyboard)
            .await
            .map_err(|e| WardenError::Executor(format!("telegram send_message: {e}")))?;
        let message_id = sent.message_id;

        let deadline = tokio::time::Instant::now() + self.prompt_timeout;
        let decision = self
            .wait_for_callback(
                deadline,
                message_id,
                &approve_data,
                &deny_data,
                window_data.as_deref(),
            )
            .await;

        let (outcome, label) = match &decision {
            Ok(ApprovalDecision::Approved) => (decision.as_ref().ok().copied(), "✓ Approved"),
            Ok(ApprovalDecision::ApprovedForWindow) => {
                (decision.as_ref().ok().copied(), "✓ Approved for window")
            }
            Ok(ApprovalDecision::Denied) => (decision.as_ref().ok().copied(), "✗ Denied"),
            Ok(ApprovalDecision::Timeout) => (decision.as_ref().ok().copied(), "⏱ Timeout"),
            Err(_) => (None, "⚠ Transport error"),
        };

        let _ = self
            .edit_message(message_id, &format!("{body}\n\n{label}"))
            .await;

        match decision {
            Ok(d) => {
                let _ = outcome;
                Ok(d)
            }
            Err(e) => Err(e),
        }
    }
}

impl TelegramApproval {
    async fn send_message(
        &self,
        text: &str,
        reply_markup: &serde_json::Value,
    ) -> std::result::Result<SentMessage, String> {
        let payload = json!({
            "chat_id": self.chat_id,
            "text": text,
            "reply_markup": reply_markup,
            "protect_content": true,
            "disable_web_page_preview": true,
        });
        let resp = self
            .client
            .post(self.api("sendMessage"))
            .json(&payload)
            .send()
            .await
            .map_err(redact)?;
        let body: TgResult<SentMessage> = resp.json().await.map_err(redact)?;
        if !body.ok {
            return Err(body
                .description
                .unwrap_or_else(|| "telegram sendMessage failed".into()));
        }
        body.result.ok_or_else(|| "no result in sendMessage".into())
    }

    async fn edit_message(&self, message_id: i64, text: &str) -> std::result::Result<(), String> {
        let payload = json!({
            "chat_id": self.chat_id,
            "message_id": message_id,
            "text": text,
            "reply_markup": json!({"inline_keyboard": []}),
        });
        let resp = self
            .client
            .post(self.api("editMessageText"))
            .json(&payload)
            .send()
            .await
            .map_err(redact)?;
        let body: TgResult<serde_json::Value> = resp.json().await.map_err(redact)?;
        if !body.ok {
            return Err(body
                .description
                .unwrap_or_else(|| "telegram editMessageText failed".into()));
        }
        Ok(())
    }

    async fn answer_callback(&self, callback_id: &str) -> std::result::Result<(), String> {
        let payload = json!({ "callback_query_id": callback_id });
        let _ = self
            .client
            .post(self.api("answerCallbackQuery"))
            .json(&payload)
            .send()
            .await;
        // We intentionally swallow errors here — the decision is already
        // captured; answer_callback is a UX nicety to dismiss the spinner.
        Ok(())
    }

    async fn wait_for_callback(
        &self,
        deadline: tokio::time::Instant,
        message_id: i64,
        approve_data: &str,
        deny_data: &str,
        window_data: Option<&str>,
    ) -> Result<ApprovalDecision> {
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Ok(ApprovalDecision::Timeout);
            }
            let remaining = deadline.saturating_duration_since(now).as_secs();
            let poll_timeout = remaining.clamp(1, POLL_TIMEOUT_SECS);

            let offset = self.next_offset.load(Ordering::Relaxed);
            let payload = json!({
                "timeout": poll_timeout,
                "offset": offset,
                "allowed_updates": ["callback_query"],
            });
            let resp = match self
                .client
                .post(self.api("getUpdates"))
                .json(&payload)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("telegram getUpdates network error: {}", redact(e));
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };
            let body: TgResult<Vec<Update>> = match resp.json().await {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("telegram getUpdates parse error: {}", redact(e));
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };
            if !body.ok {
                tracing::warn!(
                    "telegram getUpdates not ok: {}",
                    body.description.as_deref().unwrap_or("unknown")
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            let updates = body.result.unwrap_or_default();
            for update in &updates {
                self.next_offset
                    .store(update.update_id + 1, Ordering::Relaxed);
                let Some(cb) = &update.callback_query else {
                    continue;
                };
                let Some(msg) = &cb.message else { continue };
                // SECURITY: verify the callback came from the configured chat
                // and from the prompt we sent for this request.
                if !is_callback_for(msg, self.chat_id, message_id) {
                    tracing::warn!(
                        "telegram callback from chat {} / message {} ignored",
                        msg.chat.id,
                        msg.message_id
                    );
                    continue;
                }
                let Some(data) = &cb.data else { continue };
                let decision = classify_callback_data(data, approve_data, deny_data, window_data);
                let Some(decision) = decision else { continue };
                let _ = self.answer_callback(&cb.id).await;
                return Ok(decision);
            }
        }
    }
}

fn render_body(req: &ApprovalRequest) -> String {
    let preset = sanitise_for_prompt(&req.preset, 80);
    let action = sanitise_for_prompt(&req.action, 80);
    let summary = sanitise_for_prompt(&req.summary, SUMMARY_MAX_CHARS);
    let mut out =
        format!("🔐 mcp-warden approval\n\nPreset: {preset}\nAction: {action}\n\n{summary}");
    if let Some(secs) = req.window_seconds {
        out.push_str(&format!(
            "\n\n(Approve for window: allows follow-up calls for {secs}s)"
        ));
    }
    out
}

fn build_inline_keyboard(
    approve_data: &str,
    deny_data: &str,
    window_data: Option<&str>,
) -> serde_json::Value {
    let mut row = vec![
        json!({ "text": "✓ Approve", "callback_data": approve_data }),
        json!({ "text": "✗ Deny", "callback_data": deny_data }),
    ];
    if let Some(w) = window_data {
        row.push(json!({ "text": "⏱ Approve for window", "callback_data": w }));
    }
    json!({ "inline_keyboard": [row] })
}

/// Render a transport error WITHOUT its URL — every Bot API URL embeds the
/// bot token (`/bot<token>/<method>`), and reqwest's `Display` prints it.
fn redact(e: reqwest::Error) -> String {
    e.without_url().to_string()
}

fn is_callback_for(msg: &CbMessage, chat_id: i64, message_id: i64) -> bool {
    msg.chat.id == chat_id && msg.message_id == message_id
}

fn classify_callback_data(
    data: &str,
    approve_data: &str,
    deny_data: &str,
    window_data: Option<&str>,
) -> Option<ApprovalDecision> {
    if data == approve_data {
        Some(ApprovalDecision::Approved)
    } else if data == deny_data {
        Some(ApprovalDecision::Denied)
    } else if window_data.is_some_and(|w| data == w) {
        Some(ApprovalDecision::ApprovedForWindow)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> ApprovalRequest {
        ApprovalRequest::new(
            "stripe-write".into(),
            "proxy_http".into(),
            "POST /charges, body ~120 bytes".into(),
        )
    }

    #[test]
    fn render_body_includes_all_pieces() {
        let body = render_body(&req());
        assert!(body.contains("stripe-write"));
        assert!(body.contains("proxy_http"));
        assert!(body.contains("/charges"));
    }

    #[test]
    fn render_body_strips_control_chars() {
        let mut r = req();
        r.summary = "POST /charges\n\u{1b}[31mfake\u{1b}[0m".into();
        let body = render_body(&r);
        assert!(!body.contains('\u{1b}'));
    }

    #[test]
    fn render_body_mentions_window_when_set() {
        let r = req().with_window(Some(120));
        let body = render_body(&r);
        assert!(body.contains("120"));
    }

    #[test]
    fn keyboard_has_approve_deny_buttons() {
        let kb = build_inline_keyboard("approve:1", "deny:1", None);
        let s = serde_json::to_string(&kb).unwrap();
        assert!(s.contains("approve:1"));
        assert!(s.contains("deny:1"));
        assert!(!s.contains("window:"));
    }

    #[test]
    fn keyboard_adds_window_button_when_offered() {
        let kb = build_inline_keyboard("approve:1", "deny:1", Some("window:120:1"));
        let s = serde_json::to_string(&kb).unwrap();
        assert!(s.contains("window:120:1"));
    }

    fn tg() -> TelegramApproval {
        TelegramApproval::new(Secret::new("t".into()), 42)
    }

    #[test]
    fn prompt_timeout_defaults_and_honours_config() {
        assert_eq!(tg().prompt_timeout, Duration::from_secs(120));
        assert_eq!(
            tg().with_timeout(Some(30)).prompt_timeout,
            Duration::from_secs(30)
        );
        assert_eq!(
            tg().with_timeout(Some(0)).prompt_timeout,
            Duration::from_secs(120)
        );
        assert_eq!(
            tg().with_timeout(None).prompt_timeout,
            Duration::from_secs(120)
        );
    }

    #[tokio::test]
    async fn transport_errors_never_contain_the_bot_token() {
        // Port 1 on loopback refuses immediately; reqwest's error Display
        // would include the full URL — and with it the token.
        let err = reqwest::Client::new()
            .post("http://127.0.0.1:1/botSUPERSECRET/getUpdates")
            .send()
            .await
            .unwrap_err();
        assert!(err.to_string().contains("SUPERSECRET"), "precondition");
        assert!(!redact(err).contains("SUPERSECRET"));
    }

    #[test]
    fn callback_must_come_from_our_chat_and_message() {
        let msg = |chat: i64, id: i64| CbMessage {
            message_id: id,
            chat: CbChat { id: chat },
        };
        assert!(is_callback_for(&msg(42, 7), 42, 7));
        assert!(!is_callback_for(&msg(43, 7), 42, 7), "foreign chat");
        assert!(!is_callback_for(&msg(42, 8), 42, 7), "other prompt");
    }

    #[test]
    fn classify_callback_data_matches_correctly() {
        assert_eq!(
            classify_callback_data("approve:1", "approve:1", "deny:1", None),
            Some(ApprovalDecision::Approved)
        );
        assert_eq!(
            classify_callback_data("deny:1", "approve:1", "deny:1", None),
            Some(ApprovalDecision::Denied)
        );
        assert_eq!(
            classify_callback_data("window:120:1", "approve:1", "deny:1", Some("window:120:1")),
            Some(ApprovalDecision::ApprovedForWindow)
        );
        assert_eq!(
            classify_callback_data("garbage", "approve:1", "deny:1", None),
            None
        );
        // Stale callback for a previous request must not match.
        assert_eq!(
            classify_callback_data("approve:old", "approve:new", "deny:new", None),
            None
        );
    }
}
