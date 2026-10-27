//! Telegram approval transport and the `/lock` command.
//!
//! When a preset has `approval = "prompt"`, this transport sends the
//! approval request as a Telegram message with inline buttons (Approve /
//! Deny / Approve for window), waits for the press, then edits the message
//! to show the outcome. A `/lock` message from the configured chat locks
//! mcp-warden (`mcp-warden lock`) — at any time, while a server runs.
//!
//! ## One poller at a time
//!
//! Telegram hands each update to one `getUpdates` caller, and every Claude
//! session runs its own `mcp-warden mcp`. So polling is taken in turns
//! across processes through a file lock (`<config dir>/telegram/poll.lock`),
//! and the offset is shared through `telegram/offset`. Whoever polls
//! dispatches every update: `/lock` is handled on the spot; a button press
//! for a prompt of this process is delivered in memory, and one for another
//! process is left in `telegram/inbox/<button token>` for that process to
//! pick up.
//!
//! Every button of every prompt carries its own 128-bit random token, and
//! the token *is* the answer: the owner knows which of its tokens means
//! Approve. An inbox file only says "this button was pressed" (plus the
//! message id, which the owner checks). The Approve token exists only in
//! the owner's memory and in the Telegram message, so a process that can
//! write to the inbox — the agent included — can't forge or flip an
//! answer: at best it can delete one, and an unanswered prompt times out.
//!
//! ## Security
//!
//! 1. **Bot token lives in the keychain.** It is read once at startup. The
//!    token is never logged, never echoed to stderr, never embedded in the
//!    message body; transport errors are printed without their URL.
//! 2. **The chat is verified on every update.** Presses and `/lock` from any
//!    other chat are ignored and logged.
//! 3. **A press counts only for the prompt it was sent with** (chat,
//!    message id and per-request id all match).
//! 4. **The summary is sanitised** via `sanitise_for_prompt`, same as the
//!    desktop/TUI transports.
//! 5. **The message uses `protect_content: true`** so it cannot be
//!    forwarded out of the chat.
//! 6. **`/lock` only locks.** Unlocking needs `mcp-warden unlock` on the
//!    computer.

use crate::executor::lock::{self, LockInfo};
use async_trait::async_trait;
use chrono::SubsecRound;
use mcp_warden_core::approval::{
    ApprovalDecision, ApprovalRequest, ApprovalTransport, sanitise_for_prompt,
};
use mcp_warden_core::error::{Result, WardenError};
use mcp_warden_core::secret::Secret;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Long-poll length of one `getUpdates` call.
const POLL_TIMEOUT_SECS: u64 = 25;
/// Per-prompt timeout when `[approval.telegram] timeout_seconds` is unset.
const DEFAULT_PROMPT_TIMEOUT_SECS: u64 = 120;
const SUMMARY_MAX_CHARS: usize = 600;
/// How often a waiting prompt looks for its answer when someone else polls.
const WAIT_TICK: Duration = Duration::from_millis(300);
/// Inbox files nobody claimed are removed after this long.
const INBOX_MAX_AGE: Duration = Duration::from_secs(3600);

/// The bot, shared by the approval transport and the background listener.
pub struct TelegramBot {
    bot_token: Secret,
    chat_id: i64,
    client: reqwest::Client,
    api_base: String,
    /// `<config dir>/telegram`: poll lock, shared offset, inbox.
    dir: PathBuf,
    /// `<config dir>/lock`, written by `/lock`.
    lock_path: PathBuf,
    poll_timeout_secs: u64,
    /// Buttons of this process's waiting prompts: token → (prompt id,
    /// message id, what the button means).
    pending: Mutex<HashMap<String, Button>>,
    /// Answers for prompts of this process, delivered by whoever polled here:
    /// prompt id → decision.
    decided: Mutex<HashMap<String, ApprovalDecision>>,
    /// One `getUpdates` at a time within this process.
    polling: tokio::sync::Mutex<()>,
}

impl TelegramBot {
    /// `bot_token` comes from the OS keychain; `chat_id` is the one chat
    /// allowed to approve and to lock; `config_dir` holds the shared state.
    pub fn new(bot_token: Secret, chat_id: i64, config_dir: &Path) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(POLL_TIMEOUT_SECS + 10))
            .build()
            .unwrap_or_default();
        Self {
            bot_token,
            chat_id,
            client,
            api_base: "https://api.telegram.org".into(),
            dir: config_dir.join("telegram"),
            lock_path: config_dir.join(lock::LOCK_FILE),
            poll_timeout_secs: POLL_TIMEOUT_SECS,
            pending: Mutex::new(HashMap::new()),
            decided: Mutex::new(HashMap::new()),
            polling: tokio::sync::Mutex::new(()),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_api_base(mut self, base: &str, poll_timeout_secs: u64) -> Self {
        self.api_base = base.trim_end_matches('/').to_string();
        self.poll_timeout_secs = poll_timeout_secs;
        self
    }

    fn api(&self, method: &str) -> String {
        format!(
            "{}/bot{}/{}",
            self.api_base,
            self.bot_token.expose(),
            method
        )
    }

    /// The MCP server's background listener: poll whenever it is this
    /// process's turn, so `/lock` works even when nothing is asking.
    pub async fn listen(self: Arc<Self>) {
        let mut rounds: u64 = 0;
        loop {
            if !self.poll_once(self.poll_timeout_secs).await {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            rounds += 1;
            if rounds.is_multiple_of(100) {
                self.clean_inbox();
            }
        }
    }

    /// One `getUpdates` round, if no other poller — in this process or
    /// another — is polling right now. Returns whether it polled.
    pub async fn poll_once(&self, timeout_secs: u64) -> bool {
        let Ok(_turn) = self.polling.try_lock() else {
            return false;
        };
        if std::fs::create_dir_all(self.dir.join("inbox")).is_err() {
            return false;
        }
        let Ok(lock_file) = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.dir.join("poll.lock"))
        else {
            return false;
        };
        if lock_file.try_lock().is_err() {
            return false;
        }
        let offset_path = self.dir.join("offset");
        let offset: u64 = std::fs::read_to_string(&offset_path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        match self.get_updates(offset, timeout_secs).await {
            Ok(updates) => {
                let next = updates.iter().map(|u| u.update_id + 1).max();
                for update in updates {
                    self.dispatch(update).await;
                }
                if let Some(next) = next.filter(|n| *n > offset) {
                    let _ = crate::fsutil::replace_atomic(
                        &offset_path,
                        next.to_string().as_bytes(),
                        None,
                    );
                }
            }
            Err(e) => {
                tracing::warn!("telegram getUpdates: {e}");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
        drop(lock_file);
        true
    }

    async fn get_updates(
        &self,
        offset: u64,
        timeout_secs: u64,
    ) -> std::result::Result<Vec<Update>, String> {
        let payload = json!({
            "timeout": timeout_secs,
            "offset": offset,
            "allowed_updates": ["message", "callback_query"],
        });
        let resp = self
            .client
            .post(self.api("getUpdates"))
            .json(&payload)
            .send()
            .await
            .map_err(redact)?;
        let body: TgResult<Vec<Update>> = resp.json().await.map_err(redact)?;
        if !body.ok {
            return Err(body.description.unwrap_or_else(|| "not ok".into()));
        }
        Ok(body.result.unwrap_or_default())
    }

    /// Handle one update, whichever process it was meant for.
    pub(crate) async fn dispatch(&self, update: Update) {
        if let Some(msg) = update.message {
            if msg.chat.id != self.chat_id {
                tracing::warn!("telegram message from chat {} ignored", msg.chat.id);
                return;
            }
            if let Some(reason) = msg.text.as_deref().and_then(lock_command) {
                self.lock_from_telegram(reason).await;
            }
            return;
        }
        let Some(cb) = update.callback_query else {
            return;
        };
        let Some(msg) = &cb.message else { return };
        if msg.chat.id != self.chat_id {
            tracing::warn!(
                "telegram callback from chat {} / message {} ignored",
                msg.chat.id,
                msg.message_id
            );
            return;
        }
        let Some(token) = cb.data.as_deref().filter(|d| is_token(d)) else {
            return;
        };
        let _ = self.answer_callback(&cb.id).await;
        let mine = self.pending.lock().unwrap().get(token).cloned();
        match mine {
            Some(b) if b.message_id == msg.message_id => {
                self.decided.lock().unwrap().insert(b.prompt, b.decision);
            }
            Some(_) => tracing::warn!("telegram callback for another message ignored"),
            None => {
                // Another process's button: say it was pressed. The token
                // alone tells its owner which answer it is.
                let inbox = self.dir.join("inbox");
                let _ = std::fs::create_dir_all(&inbox);
                let _ = crate::fsutil::replace_atomic(
                    &inbox.join(token),
                    msg.message_id.to_string().as_bytes(),
                    None,
                );
            }
        }
    }

    /// `/lock [reason]` from the configured chat.
    async fn lock_from_telegram(&self, reason: &str) {
        let reply = if lock::is_present(&self.lock_path) {
            "mcp-warden is already locked.".to_string()
        } else {
            let reason = sanitise_for_prompt(reason.trim(), 200);
            let info = LockInfo {
                since: chrono::Utc::now().trunc_subsecs(0),
                reason: Some(if reason.is_empty() {
                    "Telegram /lock".to_string()
                } else {
                    format!("Telegram /lock: {reason}")
                }),
            };
            match lock::write(&self.lock_path, &info) {
                Ok(()) => "🔒 mcp-warden is locked. Every MCP server refuses every call from its \
                     next one on. Unlock on the computer: `mcp-warden unlock`."
                    .to_string(),
                Err(e) => format!("Could not lock mcp-warden: {e}"),
            }
        };
        let _ = self.send_message(&reply, None).await;
    }

    /// The answer for `prompt`, if one arrived — in memory or, from another
    /// process's poll, as one of its buttons in the inbox.
    fn take_decision(&self, prompt: &Prompt) -> Option<ApprovalDecision> {
        if let Some(d) = self.decided.lock().unwrap().remove(&prompt.id) {
            return Some(d);
        }
        for (token, decision) in &prompt.buttons {
            let path = self.dir.join("inbox").join(token);
            let Ok(raw) = std::fs::read_to_string(&path) else {
                continue;
            };
            let _ = std::fs::remove_file(&path);
            if raw.trim().parse::<i64>().ok() == Some(prompt.message_id) {
                return Some(*decision);
            }
            tracing::warn!("telegram inbox answer for another message ignored");
        }
        None
    }

    fn register(&self, prompt: &Prompt) {
        let mut pending = self.pending.lock().unwrap();
        for (token, decision) in &prompt.buttons {
            pending.insert(
                token.clone(),
                Button {
                    prompt: prompt.id.clone(),
                    message_id: prompt.message_id,
                    decision: *decision,
                },
            );
        }
    }

    fn forget(&self, prompt: &Prompt) {
        let mut pending = self.pending.lock().unwrap();
        for (token, _) in &prompt.buttons {
            pending.remove(token);
        }
        self.decided.lock().unwrap().remove(&prompt.id);
    }

    /// Drop inbox answers nobody claimed (their prompt timed out or its
    /// process exited).
    fn clean_inbox(&self) {
        let Ok(entries) = std::fs::read_dir(self.dir.join("inbox")) else {
            return;
        };
        for entry in entries.flatten() {
            let old = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age > INBOX_MAX_AGE);
            if old {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    async fn send_message(
        &self,
        text: &str,
        reply_markup: Option<&serde_json::Value>,
    ) -> std::result::Result<SentMessage, String> {
        let mut payload = json!({
            "chat_id": self.chat_id,
            "text": text,
            "protect_content": true,
            "disable_web_page_preview": true,
        });
        if let Some(markup) = reply_markup {
            payload["reply_markup"] = markup.clone();
        }
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

    /// `getMe`: the bot's @username, which also proves the token works.
    pub async fn username(&self) -> std::result::Result<String, String> {
        let resp = self
            .client
            .post(self.api("getMe"))
            .send()
            .await
            .map_err(redact)?;
        let body: TgResult<BotUser> = resp.json().await.map_err(redact)?;
        if !body.ok {
            return Err(body
                .description
                .unwrap_or_else(|| "telegram getMe failed".into()));
        }
        Ok(body.result.and_then(|u| u.username).unwrap_or_default())
    }
}

/// The approval transport: one prompt per request, answered through the
/// shared bot.
pub struct TelegramApproval {
    bot: Arc<TelegramBot>,
    /// How long one prompt waits for a button press before timing out.
    prompt_timeout: Duration,
}

impl TelegramApproval {
    pub fn new(bot: Arc<TelegramBot>) -> Self {
        Self {
            bot,
            prompt_timeout: Duration::from_secs(DEFAULT_PROMPT_TIMEOUT_SECS),
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

    pub fn timeout(&self) -> Duration {
        self.prompt_timeout
    }
}

/// What one button of a waiting prompt means.
#[derive(Debug, Clone)]
struct Button {
    prompt: String,
    message_id: i64,
    decision: ApprovalDecision,
}

/// A prompt this process sent: its id and one token per button.
struct Prompt {
    id: String,
    message_id: i64,
    buttons: Vec<(String, ApprovalDecision)>,
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
struct BotUser {
    #[serde(default)]
    username: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Update {
    update_id: u64,
    #[serde(default)]
    message: Option<Message>,
    #[serde(default)]
    callback_query: Option<CallbackQuery>,
}

#[derive(Debug, Deserialize)]
struct Message {
    chat: Chat,
    #[serde(default)]
    text: Option<String>,
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
    chat: Chat,
}

#[derive(Debug, Deserialize)]
struct Chat {
    id: i64,
}

#[async_trait]
impl ApprovalTransport for TelegramApproval {
    async fn request(&self, req: ApprovalRequest) -> Result<ApprovalDecision> {
        let bot = &self.bot;
        let mut buttons = vec![
            (random_token()?, ApprovalDecision::Approved),
            (random_token()?, ApprovalDecision::Denied),
        ];
        if req.window_seconds.is_some() {
            buttons.push((random_token()?, ApprovalDecision::ApprovedForWindow));
        }
        let body = render_body(&req);
        let keyboard = build_inline_keyboard(&buttons);
        let sent = bot
            .send_message(&body, Some(&keyboard))
            .await
            .map_err(|e| WardenError::Executor(format!("telegram send_message: {e}")))?;
        let prompt = Prompt {
            id: random_token()?,
            message_id: sent.message_id,
            buttons,
        };
        bot.register(&prompt);

        let deadline = tokio::time::Instant::now() + self.prompt_timeout;
        let decision = loop {
            if let Some(d) = bot.take_decision(&prompt) {
                break d;
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break ApprovalDecision::Timeout;
            }
            // Poll ourselves when nobody else is; otherwise wait for the
            // poller to deliver the answer.
            let remaining = deadline.saturating_duration_since(now);
            let poll = remaining.as_secs().clamp(1, bot.poll_timeout_secs.max(1));
            if !bot.poll_once(poll).await {
                tokio::time::sleep(WAIT_TICK.min(remaining)).await;
            }
        };
        bot.forget(&prompt);

        let label = match decision {
            ApprovalDecision::Approved => "✓ Approved",
            ApprovalDecision::ApprovedForWindow => "✓ Approved for window",
            ApprovalDecision::Denied => "✗ Denied",
            ApprovalDecision::Timeout => "⏱ Timeout",
        };
        let _ = bot
            .edit_message(sent.message_id, &format!("{body}\n\n{label}"))
            .await;
        Ok(decision)
    }
}

/// 128 random bits, hex: unguessable, so an inbox file can't be forged.
fn random_token() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|e| WardenError::Executor(format!("no randomness for a request id: {e}")))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
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

/// One button per token; its callback data is the token and nothing else.
fn build_inline_keyboard(buttons: &[(String, ApprovalDecision)]) -> serde_json::Value {
    let row: Vec<serde_json::Value> = buttons
        .iter()
        .map(|(token, decision)| {
            let text = match decision {
                ApprovalDecision::Approved => "✓ Approve",
                ApprovalDecision::Denied => "✗ Deny",
                ApprovalDecision::ApprovedForWindow => "⏱ Approve for window",
                ApprovalDecision::Timeout => "⏱ Timeout",
            };
            json!({ "text": text, "callback_data": token })
        })
        .collect();
    json!({ "inline_keyboard": [row] })
}

/// A button token: exactly 32 hex digits (also safe as a file name).
fn is_token(data: &str) -> bool {
    data.len() == 32 && data.chars().all(|c| c.is_ascii_hexdigit())
}

/// `/lock`, `/lock@my_bot` or `/lock <reason>`: the reason, if this is one.
fn lock_command(text: &str) -> Option<&str> {
    let text = text.trim();
    let (cmd, rest) = text.split_once(char::is_whitespace).unwrap_or((text, ""));
    let cmd = cmd.split('@').next().unwrap_or(cmd);
    (cmd == "/lock").then_some(rest)
}

/// Render a transport error WITHOUT its URL — every Bot API URL embeds the
/// bot token (`/bot<token>/<method>`), and reqwest's `Display` prints it.
fn redact(e: reqwest::Error) -> String {
    e.without_url().to_string()
}

/// The token of a waiting button that means `decision` (for tests).
#[cfg(test)]
impl TelegramBot {
    pub(crate) fn pending_token(&self, decision: ApprovalDecision) -> Option<String> {
        self.pending
            .lock()
            .unwrap()
            .iter()
            .find(|(_, b)| b.decision == decision)
            .map(|(t, _)| t.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const CHAT: i64 = 42;

    fn req() -> ApprovalRequest {
        ApprovalRequest::new(
            "stripe-write".into(),
            "proxy_http".into(),
            "POST /charges, body ~120 bytes".into(),
        )
    }

    fn bot(server: &MockServer, dir: &Path) -> Arc<TelegramBot> {
        Arc::new(
            TelegramBot::new(Secret::new("TESTTOKEN".into()), CHAT, dir)
                .with_api_base(&server.uri(), 0),
        )
    }

    /// A Telegram API that accepts every send / edit / answer, and serves
    /// `updates` from `getUpdates` once, then nothing.
    async fn telegram(updates: serde_json::Value) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex("/sendMessage$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"ok": true, "result": {"message_id": 7}})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex("/getUpdates$"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"ok": true, "result": updates})),
            )
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(
                "/(getUpdates|editMessageText|answerCallbackQuery)$",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"ok": true, "result": []})),
            )
            .mount(&server)
            .await;
        server
    }

    fn press(update_id: u64, chat: i64, message_id: i64, data: &str) -> serde_json::Value {
        json!({ "update_id": update_id, "callback_query": {
            "id": "cb1", "data": data,
            "message": { "message_id": message_id, "chat": { "id": chat } } } })
    }

    fn text(update_id: u64, chat: i64, text: &str) -> serde_json::Value {
        json!({ "update_id": update_id, "message": { "chat": { "id": chat }, "text": text } })
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
        assert!(render_body(&r).contains("120"));
    }

    #[test]
    fn keyboard_buttons_carry_only_their_token() {
        let approve = "a".repeat(32);
        let deny = "d".repeat(32);
        let kb = build_inline_keyboard(&[
            (approve.clone(), ApprovalDecision::Approved),
            (deny.clone(), ApprovalDecision::Denied),
        ]);
        let row = kb["inline_keyboard"][0].as_array().unwrap();
        assert_eq!(row.len(), 2);
        assert_eq!(row[0]["callback_data"], approve);
        assert_eq!(row[1]["callback_data"], deny);
        assert!(!kb.to_string().contains("window"));
    }

    #[test]
    fn prompt_timeout_defaults_and_honours_config() {
        let tg = || {
            TelegramApproval::new(Arc::new(TelegramBot::new(
                Secret::new("t".into()),
                CHAT,
                Path::new("."),
            )))
        };
        assert_eq!(tg().timeout(), Duration::from_secs(120));
        assert_eq!(
            tg().with_timeout(Some(30)).timeout(),
            Duration::from_secs(30)
        );
        assert_eq!(
            tg().with_timeout(Some(0)).timeout(),
            Duration::from_secs(120)
        );
        assert_eq!(tg().with_timeout(None).timeout(), Duration::from_secs(120));
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
    fn tokens_and_commands_parse_strictly() {
        assert!(is_token("0123456789abcdef0123456789abcdef"));
        for bad in [
            "approve:0123",
            "../../etc/passwd",
            "0123456789abcdef0123456789abcde",
            "",
        ] {
            assert!(!is_token(bad), "{bad}");
        }
        assert_eq!(lock_command("/lock"), Some(""));
        assert_eq!(
            lock_command("/lock@warden_bot agent went rogue"),
            Some("agent went rogue")
        );
        assert_eq!(lock_command("/locked"), None);
        assert_eq!(lock_command("please /lock"), None);
    }

    /// A prompt of `bot` with three buttons, registered as waiting.
    fn waiting_prompt(bot: &TelegramBot, message_id: i64) -> Prompt {
        let prompt = Prompt {
            id: random_token().unwrap(),
            message_id,
            buttons: vec![
                (random_token().unwrap(), ApprovalDecision::Approved),
                (random_token().unwrap(), ApprovalDecision::Denied),
                (random_token().unwrap(), ApprovalDecision::ApprovedForWindow),
            ],
        };
        bot.register(&prompt);
        prompt
    }

    #[tokio::test]
    async fn a_press_answers_the_prompt_of_this_process() {
        let dir = tempfile::tempdir().unwrap();
        let server = telegram(json!([])).await;
        let bot = bot(&server, dir.path());
        let t = TelegramApproval::new(bot.clone()).with_timeout(Some(5));
        let waiter = tokio::spawn(async move { t.request(req()).await });
        let approve = loop {
            if let Some(token) = bot.pending_token(ApprovalDecision::Approved) {
                break token;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        bot.dispatch(serde_json::from_value(press(1, CHAT, 7, &approve)).unwrap())
            .await;
        assert_eq!(waiter.await.unwrap().unwrap(), ApprovalDecision::Approved);
        assert_eq!(
            bot.pending_token(ApprovalDecision::Approved),
            None,
            "forgotten"
        );
    }

    #[tokio::test]
    async fn presses_from_another_chat_or_message_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let server = telegram(json!([])).await;
        let bot = bot(&server, dir.path());
        let prompt = waiting_prompt(&bot, 7);
        let approve = prompt.buttons[0].0.clone();
        for update in [press(1, 999, 7, &approve), press(2, CHAT, 8, &approve)] {
            bot.dispatch(serde_json::from_value(update).unwrap()).await;
        }
        assert_eq!(bot.take_decision(&prompt), None);
    }

    #[tokio::test]
    async fn a_press_for_another_process_reaches_it_through_the_inbox() {
        let dir = tempfile::tempdir().unwrap();
        let server = telegram(json!([])).await;
        let poller = bot(&server, dir.path());
        let owner = bot(&server, dir.path());
        let prompt = waiting_prompt(&owner, 7);
        let deny = prompt.buttons[1].0.clone();

        poller
            .dispatch(serde_json::from_value(press(1, CHAT, 7, &deny)).unwrap())
            .await;
        assert_eq!(owner.take_decision(&prompt), Some(ApprovalDecision::Denied));
        assert_eq!(
            owner.take_decision(&prompt),
            None,
            "an answer is taken once"
        );
    }

    /// Someone who can write to the inbox sees a pressed button's token, but
    /// can't turn it into another answer: only the owner knows which token
    /// means Approve, and that token never touches the disk.
    #[tokio::test]
    async fn the_inbox_cannot_be_used_to_forge_an_approval() {
        let dir = tempfile::tempdir().unwrap();
        let server = telegram(json!([])).await;
        let owner = bot(&server, dir.path());
        let prompt = waiting_prompt(&owner, 7);
        let inbox = dir.path().join("telegram/inbox");
        std::fs::create_dir_all(&inbox).unwrap();
        // A made-up token, and an answer for another message.
        std::fs::write(inbox.join(random_token().unwrap()), "7").unwrap();
        std::fs::write(inbox.join(&prompt.buttons[0].0), "8").unwrap();
        assert_eq!(owner.take_decision(&prompt), None);
    }

    #[tokio::test]
    async fn lock_from_the_configured_chat_locks_and_replies() {
        let dir = tempfile::tempdir().unwrap();
        let server = telegram(json!([
            text(1, 999, "/lock not you"),
            text(2, CHAT, "/lock agent went rogue"),
        ]))
        .await;
        let bot = bot(&server, dir.path());
        assert!(bot.poll_once(0).await);
        let info = lock::read(&dir.path().join(lock::LOCK_FILE)).expect("locked");
        assert_eq!(
            info.reason.as_deref(),
            Some("Telegram /lock: agent went rogue")
        );

        let replies: Vec<String> = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.url.path().ends_with("/sendMessage"))
            .map(|r| String::from_utf8_lossy(&r.body).into_owned())
            .collect();
        assert_eq!(replies.len(), 1, "one reply, to our chat only");
        assert!(
            replies[0].contains("mcp-warden is locked") && replies[0].contains("\"chat_id\":42")
        );
    }

    #[tokio::test]
    async fn the_offset_is_shared_and_polls_take_turns() {
        let dir = tempfile::tempdir().unwrap();
        let server = telegram(json!([text(41, CHAT, "hello")])).await;
        let a = bot(&server, dir.path());
        let b = bot(&server, dir.path());
        assert!(a.poll_once(0).await);
        let offset = std::fs::read_to_string(dir.path().join("telegram/offset")).unwrap();
        assert_eq!(offset.trim(), "42");

        // While another process holds the poll lock, nobody else polls.
        let held = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.path().join("telegram/poll.lock"))
            .unwrap();
        held.lock().unwrap();
        assert!(!b.poll_once(0).await);
        held.unlock().unwrap();
        assert!(b.poll_once(0).await);
    }

    #[test]
    fn tokens_are_random_hex() {
        let a = random_token().unwrap();
        let b = random_token().unwrap();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }
}
