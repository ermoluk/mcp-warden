use crate::approval::telegram::{TelegramApproval, TelegramBot};
use clap::Args;
use mcp_warden_core::approval::{ApprovalDecision, ApprovalRequest, ApprovalTransport};
use mcp_warden_core::config::{ApprovalPolicy, Config};
use mcp_warden_core::error::{Result, WardenError};
use std::fs;
use std::path::Path;

#[derive(Debug, Args)]
pub struct ApprovalArgs {
    /// Preset name.
    pub preset: String,
    /// New approval policy. Omit it in `approval telegram-test`, which
    /// checks the Telegram transport instead.
    #[arg(value_parser = ["auto", "prompt", "deny"])]
    pub policy: Option<String>,
    /// Required when setting `auto` (spec §9.4).
    #[arg(long)]
    pub confirm_auto: bool,
    /// Time-boxed approval window for `policy=prompt`.
    ///
    /// When set to a positive value, the approval prompt offers an
    /// "Approve for N seconds" choice that suppresses re-prompting for
    /// subsequent calls to the same preset+action within the window.
    /// `--window 0` removes any previously-configured window.
    /// Has no effect when policy is `auto` or `deny`.
    #[arg(long)]
    pub window: Option<u64>,
}

impl ApprovalArgs {
    /// `mcp-warden approval telegram-test` (no policy).
    pub fn is_telegram_test(&self) -> bool {
        self.preset == "telegram-test" && self.policy.is_none()
    }
}

pub fn run(args: ApprovalArgs, config_path: &Path) -> Result<()> {
    let policy = args.policy.clone().ok_or_else(|| {
        WardenError::Validation(
            "missing policy: auto, prompt or deny (or `approval telegram-test` to check Telegram)"
                .into(),
        )
    })?;
    if policy == "auto" && !args.confirm_auto {
        return Err(WardenError::Validation(
            "setting policy=auto requires --confirm-auto (spec §9.4)".into(),
        ));
    }
    let raw = fs::read_to_string(config_path).map_err(WardenError::Io)?;
    let mut cfg: Config = toml::from_str(&raw).map_err(|e| WardenError::Config(e.to_string()))?;
    let p = cfg
        .preset
        .iter_mut()
        .find(|p| p.name == args.preset)
        .ok_or_else(|| WardenError::PresetNotFound(args.preset.clone()))?;
    p.approval = match policy.as_str() {
        "auto" => ApprovalPolicy::Auto,
        "deny" => ApprovalPolicy::Deny,
        _ => ApprovalPolicy::Prompt,
    };
    // Window only makes sense for prompt; clear it otherwise so an
    // operator switching auto→prompt→auto doesn't carry a stale value.
    if p.approval != ApprovalPolicy::Prompt {
        p.approval_window_seconds = None;
    } else if let Some(w) = args.window {
        p.approval_window_seconds = if w == 0 { None } else { Some(w) };
    }
    let window_summary = match p.approval_window_seconds {
        Some(n) => format!(" (window: {n}s)"),
        None => String::new(),
    };
    let toml_str = toml::to_string_pretty(&cfg).map_err(|e| WardenError::Config(e.to_string()))?;
    fs::write(config_path, toml_str).map_err(WardenError::Io)?;
    eprintln!(
        "Set approval policy for '{}' to {}{}.",
        args.preset, policy, window_summary
    );
    Ok(())
}

/// `mcp-warden approval telegram-test`: check `[approval.telegram]` end to
/// end — the token works, the chat gets a prompt, a press comes back.
pub async fn telegram_test(
    config_dir: &Path,
    kc: std::sync::Arc<dyn mcp_warden_core::keychain::KeychainStore>,
) -> Result<()> {
    let raw = fs::read_to_string(config_dir.join("config.toml")).unwrap_or_default();
    let cfg: Config = toml::from_str(&raw).map_err(|e| WardenError::Config(e.to_string()))?;
    let tg = cfg
        .approval
        .as_ref()
        .and_then(|a| a.telegram.as_ref())
        .ok_or_else(|| {
            WardenError::Validation(
                "no [approval.telegram] in the config — see docs/approval-transports.md".into(),
            )
        })?;
    let bot = crate::cli::mcp::telegram_bot(tg, kc.as_ref(), config_dir)?;
    let transport = TelegramApproval::new(bot.clone()).with_timeout(tg.timeout_seconds);
    let pressed = check_telegram(&bot, &transport, tg.chat_id).await?;
    eprintln!(
        "✓ Telegram approvals work: you pressed {pressed}.\n\
         Send /lock in that chat to lock mcp-warden while an MCP server runs."
    );
    Ok(())
}

/// The token works (`getMe`), and a test prompt in `chat_id` gets a press
/// back within the prompt timeout. Returns which button was pressed.
async fn check_telegram(
    bot: &TelegramBot,
    transport: &TelegramApproval,
    chat_id: i64,
) -> Result<&'static str> {
    let name = bot
        .username()
        .await
        .map_err(|e| WardenError::Validation(format!("the bot token doesn't work (getMe: {e})")))?;
    eprintln!(
        "Bot @{name} answers. Sent a test prompt to chat {chat_id} — press a button in Telegram \
         (nothing runs)…"
    );
    let req = ApprovalRequest::new(
        "mcp-warden".into(),
        "telegram-test".into(),
        "Test prompt from `mcp-warden approval telegram-test`. Press any button — nothing runs."
            .into(),
    );
    match transport.request(req).await? {
        ApprovalDecision::Approved | ApprovalDecision::ApprovedForWindow => Ok("Approve"),
        ApprovalDecision::Denied => Ok("Deny"),
        ApprovalDecision::Timeout => Err(WardenError::Validation(format!(
            "no button was pressed within {} s. Check that chat_id {chat_id} is your chat with \
             @{name} and that you sent the bot a message first",
            transport.timeout().as_secs()
        ))),
    }
}

#[cfg(test)]
mod telegram_test_tests {
    use super::*;
    use mcp_warden_core::secret::Secret;
    use serde_json::json;
    use std::sync::Arc;
    use std::time::Duration;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn telegram(get_me: serde_json::Value) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex("/getMe$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(get_me))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex("/sendMessage$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"ok": true, "result": {"message_id": 7}})),
            )
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

    fn test_bot(server: &MockServer, dir: &Path) -> Arc<TelegramBot> {
        Arc::new(
            TelegramBot::new(Secret::new("TESTTOKEN".into()), 42, dir)
                .with_api_base(&server.uri(), 0),
        )
    }

    #[tokio::test]
    async fn reports_the_pressed_button() {
        let dir = tempfile::tempdir().unwrap();
        let server = telegram(json!({"ok": true, "result": {"username": "warden_bot"}})).await;
        let bot = test_bot(&server, dir.path());
        let transport = TelegramApproval::new(bot.clone()).with_timeout(Some(5));
        let presser = {
            let bot = bot.clone();
            tokio::spawn(async move {
                let token = loop {
                    if let Some(t) = bot.pending_token(ApprovalDecision::Denied) {
                        break t;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                };
                let update = json!({ "update_id": 1, "callback_query": { "id": "cb", "data": token,
                    "message": { "message_id": 7, "chat": { "id": 42 } } } });
                bot.dispatch(serde_json::from_value(update).unwrap()).await;
            })
        };
        assert_eq!(check_telegram(&bot, &transport, 42).await.unwrap(), "Deny");
        presser.await.unwrap();
    }

    #[tokio::test]
    async fn a_bad_token_and_no_press_are_explained() {
        let dir = tempfile::tempdir().unwrap();
        let server = telegram(json!({"ok": false, "description": "Unauthorized"})).await;
        let bot = test_bot(&server, dir.path());
        let transport = TelegramApproval::new(bot.clone()).with_timeout(Some(1));
        let err = check_telegram(&bot, &transport, 42)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("token doesn't work") && err.contains("Unauthorized"),
            "{err}"
        );
        assert!(!err.contains("TESTTOKEN"));

        let server = telegram(json!({"ok": true, "result": {"username": "warden_bot"}})).await;
        let bot = test_bot(&server, dir.path());
        let transport = TelegramApproval::new(bot.clone()).with_timeout(Some(1));
        let err = check_telegram(&bot, &transport, 42)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("no button was pressed within 1 s"), "{err}");
    }
}
