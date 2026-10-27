# Approval transports

When a preset's approval policy is `prompt` (the default), `mcp-warden`
asks a human before running the action. *How* it asks is the job of an
`ApprovalTransport`. The OSS binary ships three.

| Transport  | How it asks                                                                 | Good for                                   |
|------------|-----------------------------------------------------------------------------|--------------------------------------------|
| `desktop`  | macOS: native dialog. Linux: notification with Approve / Deny actions       | The default on macOS and Linux desktops    |
| `tui`      | Full-screen prompt drawn on the terminal (stderr)                           | Running `mcp-warden mcp` by hand in a terminal |
| `telegram` | Bot message with inline Approve / Deny buttons                              | Approving from your phone; Windows; machines without a desktop |

Every decision — `approved`, `denied`, `timeout`, `windowed`, plus `refused`
(the allow-list turned the call away before anyone was asked) and `failed`
(the prompt could not be shown) — is written to the append-only audit log
regardless of transport.

## How the transport is chosen

Resolved once when `mcp-warden mcp` starts (config is load-once-and-freeze):

1. **`MCP_WARDEN_APPROVAL_TRANSPORT`** env var — `telegram`, `desktop` or
   `tui`. Wins over everything else.
2. **`[approval.telegram]`** block present in `config.toml` → Telegram is
   primary.
3. **Default** → the `desktop` prompt: the native dialog on macOS, a
   notification on Linux.

The fallback is asked only when the primary **times out** — nobody answered,
or (for Telegram) polling kept failing until the deadline — so it has to be a
prompt you can actually see:

| Primary    | Fallback on macOS | Fallback on Linux / Windows                      |
|------------|-------------------|--------------------------------------------------|
| `desktop`  | none              | `tui`, only if the server's stderr is a terminal |
| `telegram` | the native dialog | `tui`, only if the server's stderr is a terminal |
| `tui`      | none              | none                                             |

An MCP client (Claude Code, Cursor, …) captures the server's stderr and feeds
JSON-RPC through its stdin, so a TUI prompt there can't be seen — and on
macOS can't read keys at all. That is why the TUI is never a silent fallback
under a client; choose it explicitly only when you run `mcp-warden mcp`
yourself in a terminal.

If a transport returns an error outright (e.g. Telegram rejects
`sendMessage`, or no desktop session is available for the dialog), the call
is refused without asking the fallback and audited as `failed`; the agent is
told the prompt could not be shown. Errors fail closed; they never become
approvals.

## macOS dialog

On macOS the `desktop` transport shows a native dialog through
`/usr/bin/osascript`:

```
mcp-warden — approval requested

proxy_http → stripe-write

POST /charges, body ~120 bytes

No answer in 60 s means Deny.

        [Approve for 10 min]  [Approve once]  [ Deny ]
```

- **Deny is the default.** Return and Esc both deny; approving takes a click.
- **Approve for N min** appears only when the preset has a time-boxed window
  (`mcp-warden approval <preset> prompt --window N`).
- **Unanswered means no.** The dialog closes itself after 60 s and the call
  is refused as `timeout`.
- **No script injection.** The AppleScript is a fixed constant; the preset
  name, action and summary are passed to it as arguments, never as script
  source, and are sanitised like every other prompt.
- **No extra permissions.** The dialog needs no Automation or Accessibility
  grant. It may open behind other windows if you are busy elsewhere.

A local dialog is only as trustworthy as the screen it is on: an agent that
can drive your desktop (computer-use tools) could click it. If you give an
agent screen control, approve through Telegram instead.

Windows has no native dialog yet; use Telegram there.

## Telegram

### Setup

1. Create a bot with [@BotFather](https://t.me/BotFather) and copy its token.
2. Send any message to your bot, then find your numeric chat id
   (e.g. via `https://api.telegram.org/bot<token>/getUpdates`, field
   `message.chat.id`).
3. Store the token in the OS keychain — paste it when prompted:

   ```bash
   mcp-warden secret add tg_bot_token
   ```

4. Add to your `config.toml` (`mcp-warden doctor` prints where it is):

   ```toml
   [approval.telegram]
   bot_token_secret = "tg_bot_token"   # keychain entry NAME, not the token
   chat_id = 123456789                  # your numeric chat id
   timeout_seconds = 120                # optional, default 120
   ```

`mcp-warden mcp` refuses to start if `bot_token_secret` is not in the
keychain or `chat_id` is zero.

### What you see

```
🔐 mcp-warden approval

Preset: stripe-write
Action: proxy_http

POST /charges, body ~120 bytes

[✓ Approve] [✗ Deny] [⏱ Approve for window]
```

The window button only appears when the preset has a time-boxed approval
window (`mcp-warden approval <preset> prompt --window N`). After you press a
button — or the prompt times out — the message is edited to show the outcome.

### Security properties

- **Token in the keychain only.** The config holds the entry name, never the
  token value.
- **Chat pinning.** Button presses from any chat other than `chat_id` are
  ignored and logged.
- **Prompt pinning.** A press is accepted only from the message sent for
  *this* request, and its callback data carries a per-request id — a stale
  button from an earlier prompt cannot approve a new one.
- **`protect_content: true`.** Telegram blocks forwarding and saving of the
  prompt message.
- **Sanitised summaries.** Control characters and ANSI escapes are stripped
  from preset / action / summary text before sending; the summary is capped
  at 600 characters. Secrets are never part of the summary.
- **Timeout means no.** If nobody answers within `timeout_seconds`, the
  decision is `timeout` and the action does not run.

Note that the Telegram transport polls `getUpdates`. Don't point it at a bot
that another process also polls or has a webhook set — Telegram delivers
each update to only one consumer.

## Writing your own transport

`ApprovalTransport` lives in the `mcp-warden-core` crate, so an alternate
implementation (Slack, mobile push, web UI, …) depends only on core:

```rust
use async_trait::async_trait;
use mcp_warden_core::approval::{ApprovalDecision, ApprovalRequest, ApprovalTransport};
use mcp_warden_core::error::Result;

struct MyTransport;

#[async_trait]
impl ApprovalTransport for MyTransport {
    async fn request(&self, req: ApprovalRequest) -> Result<ApprovalDecision> {
        // Show req.preset / req.action / req.summary to a human.
        // Offer "approve for window" only if req.window_seconds is Some.
        // Return Timeout — never Approved — if nobody answers.
        Ok(ApprovalDecision::Denied)
    }
}
```

Rules every transport must follow:

- Never display or log secret values; render only `preset`, `action`,
  `summary` and sanitise them for the target medium.
- Never offer `ApprovedForWindow` when `window_seconds` is `None`.
- Fail closed: errors and timeouts must not be reported as approvals.
