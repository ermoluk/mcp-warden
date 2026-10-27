# Approval transports

When a preset's approval policy is `prompt` (the default), `mcp-warden`
asks a human before running the action. *How* it asks is the job of an
`ApprovalTransport`. The OSS binary ships three.

| Transport  | How it asks                                                                 | Good for                                   |
|------------|-----------------------------------------------------------------------------|--------------------------------------------|
| `desktop`  | macOS and Windows: native dialog. Linux: notification with Approve / Deny actions | The default on desktops                    |
| `tui`      | Full-screen prompt drawn on the terminal (stderr)                           | Running `mcp-warden mcp` by hand in a terminal |
| `telegram` | Bot message with inline Approve / Deny buttons; `/lock` from the chat       | Approving from your phone; machines without a desktop; an out-of-band kill switch |

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

| Primary    | Fallback on macOS / Windows | Fallback on Linux                                |
|------------|-----------------------------|--------------------------------------------------|
| `desktop`  | none                        | `tui`, only if the server's stderr is a terminal |
| `telegram` | the native dialog           | `tui`, only if the server's stderr is a terminal |
| `tui`      | none                        | none                                             |

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

## Windows dialog

On Windows the `desktop` transport is a small window drawn with Windows
Forms by the system Windows PowerShell — the same buttons and rules as on
macOS: Deny is both the accept (Enter) and cancel (Esc) button, closing the
window denies, and it gives up after 60 s. The script is a fixed constant
passed with `-EncodedCommand`; the request text reaches it only through
environment variables, sanitised. No extra permissions are needed.

This dialog is new and has been checked only by CI on `windows-latest` and
with a stand-in helper, not by hand on a desktop. If it misbehaves, use
Telegram and please open an issue.

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
- **Answers can't be forged locally.** Each button carries its own random
  128-bit token as its callback data, and the token *is* the answer. When
  one server process receives a press meant for another (see below), it
  leaves only "this button was pressed" in `telegram/inbox/<token>`; the
  owner knows which of its tokens means Approve, and that token never
  touches the disk — so whoever can write to the inbox, the agent included,
  can't turn a Deny into an Approve or invent one.

### Check the setup

```bash
mcp-warden approval telegram-test
```

checks the token (`getMe`), sends a test prompt to `chat_id`, and tells you
which button you pressed — or what to fix if no press arrives.

### `/lock` from your phone

Send `/lock` (optionally `/lock <reason>`) to the bot from the configured
chat and mcp-warden locks, exactly like `mcp-warden lock`: every MCP server
refuses every call from its next one on, and the bot confirms. Unlocking
still needs `mcp-warden unlock` on the computer. `/lock` from any other chat
is ignored.

For `/lock` to arrive when nothing is asking, every `mcp-warden mcp` with
`[approval.telegram]` listens in the background. Telegram hands each update
to one `getUpdates` caller, so the servers — one per Claude session — take
turns through a file lock (`<config dir>/telegram/poll.lock`) and share the
offset (`telegram/offset`); whoever polls handles `/lock` and passes button
presses to the server that asked. Don't point the bot at another program
that also polls it or has a webhook set.

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
