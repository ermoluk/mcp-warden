# mcp-warden

> A local-first credential broker for the Model Context Protocol — lets any AI coding agent (Claude Code, Cursor, Cline, Codex, Continue, Zed) take real actions without ever seeing your secrets.

The agent calls high-level tools (`proxy_http`); `mcp-warden` injects the secret server-side, executes the action, and returns only the result. Your context window stays clean. A leaked transcript leaks nothing useful.

[![ci](https://github.com/ermoluk/mcp-warden/actions/workflows/ci.yml/badge.svg)](https://github.com/ermoluk/mcp-warden/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/mcp-warden.svg)](https://crates.io/crates/mcp-warden)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

![mcp-warden demo: the agent calls the GitHub API through a preset without seeing the token, a prompt-injected DELETE is refused before any request is sent and lands in the audit log as refused, an SSH deploy runs after approval in Telegram, and `mcp-warden scan` finds a plaintext key in ~/.claude.json that `import` moves into the keychain](docs/demo.gif)

## How it works

1. You store a credential once in the OS keychain via the `mcp-warden` CLI.
2. You define **presets** — named, scoped actions (e.g. `github-read`, `stripe-charges`).
3. The AI agent connects to `mcp-warden` as an MCP server (stdio).
4. When the agent wants to act, it calls `proxy_http` with a preset name and a path/method.
5. `mcp-warden` validates the request against the preset's allow-list, injects the credential, executes, and returns only the response.
6. Sensitive presets trigger an approval prompt: a native dialog on macOS and Windows, a desktop notification with Approve / Deny on Linux, or a Telegram message on any OS — where `/lock` also works as a kill switch from your phone. Opt in to **time-boxed approvals** per preset so one OK can cover a short burst of follow-up calls without re-prompt spam.
7. Every action lands in a local SQLite audit log — including a `windowed` decision for calls authorised by an active approval window, a `refused` decision (with the raw requested path or command) for calls the allow-list turned away, and a `failed` decision when the approval prompt could not be shown.

The agent's context window contains zero secrets.

## Install

```bash
cargo install --locked mcp-warden # from crates.io
cargo install --locked --path .   # or from a clone
```

Pre-built binaries for macOS (x86_64, aarch64) and Linux (x86_64), each with a SHA-256 checksum, are attached to every [GitHub release](https://github.com/ermoluk/mcp-warden/releases).

## 90-second quickstart

```bash
mcp-warden init
mcp-warden secret add gh_pat                  # paste your GitHub PAT when prompted
mcp-warden preset add github-read \
  --type http \
  --base-url https://api.github.com \
  --auth-bearer gh_pat \
  --allowed-methods GET \
  --allowed-paths /user/repos \
  --approval auto --confirm-auto
```

The preset auto-approves only `GET /user/repos`; any other path is refused before the token is touched. To let the agent read more, widen the allow-list (e.g. `--allowed-paths '/user/repos,/repos/OWNER/[^/]+'`) and prefer a fine-grained PAT limited to specific repos. Patterns match the whole path, as exact strings or regexes anchored as `^(?:…)$`, never as prefixes; `[^/]+` is safer than `.*` for one segment. They see the percent-decoded path, so `%2F` is a separator: a GitLab-style id like `/projects/group%2Fproject` needs `/projects/[^/]+/[^/]+`. An HTTP preset with no `allowed_paths` allows every path under `base_url` — `preset add` and `doctor` warn about it, and the built-in `github-read` / `gitea-read` / `stripe-read` templates ship with `approval = "prompt"` for that reason.

Wire `mcp-warden` into your agent — see [`docs/claude-code-setup.md`](docs/claude-code-setup.md) or [`docs/cursor-setup.md`](docs/cursor-setup.md).

In your agent: ask "list my GitHub repos via mcp-warden". Watch the agent call `list_presets`, then `proxy_http` — and watch your PAT stay out of the prompt.

```bash
mcp-warden audit --last 5                     # see what the agent did
```

## Find and fix plaintext keys

Keys pasted into MCP client configs sit on disk in plaintext, where the agent, a synced dotfile or a screenshot can pick them up. Three commands fix that:

```bash
mcp-warden scan                     # where are plaintext keys? (shows type + length, never values)
mcp-warden import                   # move them into the keychain and rewire the client entries
mcp-warden run github               # what the rewired entry runs: the server, with its key injected
```

`scan` reads Claude Code, Claude Desktop, Cursor, Windsurf, VS Code and Codex configs plus `.mcp.json` / `.env` files in the current directory (`--path DIR` for more). `import` handles keys in a stdio server's `env`; for keys in arguments, headers, URLs or `.env` files, `scan` says what to do instead. To wrap a server by hand: `mcp-warden server add github --env GITHUB_PERSONAL_ACCESS_TOKEN -- npx -y @modelcontextprotocol/server-github` (the value is read from stdin). Details: [`docs/scan-and-import.md`](docs/scan-and-import.md).

## CLI reference

| Command                                    | Description                                              |
|--------------------------------------------|----------------------------------------------------------|
| `mcp-warden init`                          | Create the config directory and a template config        |
| `mcp-warden secret add <name>`             | Store a secret (value read from stdin, never argv)       |
| `mcp-warden secret list`                   | List secret names (never values)                         |
| `mcp-warden secret remove <name>`          | Delete a secret from the keychain                        |
| `mcp-warden preset add <name> ...`         | Define a preset (`--confirm-auto` required for `auto`)   |
| `mcp-warden preset list`                   | Show all presets                                         |
| `mcp-warden preset test <name>`            | Validate a preset against the current keychain           |
| `mcp-warden preset test <name> GET /path`  | Policy simulator: would this call be allowed, and why? Sends nothing (`--command`, `--get`/`--put`, `--query` for other tools) |
| `mcp-warden preset grant <name> --for 1h`  | Time-limited access: calls are refused after the window (`--permanent` clears it) |
| `mcp-warden preset revoke <name>`          | End access to a preset now (next server start; `lock` for immediately) |
| `mcp-warden lock [--reason …]`             | Kill switch: every MCP server refuses every call from its next one on (or send `/lock` to the Telegram bot) |
| `mcp-warden approval telegram-test`        | Check the Telegram setup: token, chat, a test prompt you answer |
| `mcp-warden unlock`                        | Remove the lock after a human approves it in the dialog / Telegram |
| `mcp-warden scan`                          | Find plaintext keys in MCP client configs and `.env` files (never prints values) |
| `mcp-warden import`                        | Move the keys `scan` found into the keychain and point the client at `mcp-warden run` |
| `mcp-warden server add <name> --env VAR -- <cmd…>` | Wrap another MCP server; its key is read from stdin into the keychain |
| `mcp-warden run <name>`                    | Launch a wrapped MCP server with its keys injected (use as the client's command) |
| `mcp-warden preset scaffold <template>` *(v0.3.0)* | Generate a preset from a built-in template (`--list` to discover) |
| `mcp-warden preset from-openapi <src>` *(v0.3.0)* | Bootstrap a preset from an OpenAPI 3.x spec (URL or file) |
| `mcp-warden approval <preset> <policy> [--window N]` | Set approval policy; `--window N` (sec) enables time-boxed approvals for `prompt` |
| `mcp-warden audit [--last N \| --since T]` | Read-only view of the audit log (append-only by design), with what the agent asked for — including refused calls — and which MCP client and session made each call |
| `mcp-warden doctor [--deep]` *(v0.3.0 for `--deep`)* | Diagnostic summary; `--deep` runs safe read-only HTTP probes per preset |
| `mcp-warden web [--port N]` *(v0.3.0)*     | Local read-only web UI (binds 127.0.0.1 only)            |
| `mcp-warden mcp`                           | Run the MCP server over stdio (consumed by the AI agent) |

## MCP tools exposed

- **`list_presets`** — read-only catalogue of available actions.
- **`proxy_http`** — execute an HTTP request through a preset; allow-list validation runs before credential injection.
- **`ssh_exec`** *(v0.2.0)* — run a shell command on an SSH host; command must match preset's anchored regex allow-list; key-based auth + host-key verification.
- **`sftp_transfer`** *(v0.2.0)* — get/put a file over SFTP; remote path matches preset's `sftp_allowed_paths`, local path under `$HOME` or `/tmp`.
- **`db_query`** *(v0.2.0)* — run a NAMED QUERY against PostgreSQL / MySQL / Redis. SQL/command is fixed at preset definition; agent supplies only `query_name` + positional params.
- **`get_secret_for_env`** — last-resort tool when a child process must read a secret from `env`. Always prompts for approval, regardless of preset policy.

## Claude Code plugin

For [Claude Code](https://claude.com/claude-code) there is a plugin that bundles the MCP server config, a skill that teaches Claude to use mcp-warden correctly (discover presets first, never ask for tokens, respect approvals, treat `get_secret_for_env` as a last resort) and a guided `/mcp-warden:setup` command. Install the binary first, then in Claude Code:

```
/plugin marketplace add ermoluk/mcp-warden
/plugin install mcp-warden@mcp-warden
```

Restart Claude Code and run `/mcp-warden:setup`. If you previously added the server with `claude mcp add`, remove that entry so it isn't registered twice. Details: [`plugins/mcp-warden/`](plugins/mcp-warden/).

Other MCP clients: see [`docs/claude-code-setup.md`](docs/claude-code-setup.md) and [`docs/cursor-setup.md`](docs/cursor-setup.md) for manual setup.

## What's new in v0.5.0

- **Approvals work on every desktop.** `prompt` presets now ask in a native dialog on macOS and Windows: Deny by default, Return / Esc deny, and it auto-denies after 60 s. In 0.4.x a `prompt` preset on macOS could not be approved at all under an MCP client unless Telegram was set up. A prompt that can't be shown is refused and audited as `failed`.
- **Kill switch.** `mcp-warden lock` makes every running MCP server refuse every call from its next one on. A server that has seen the lock stays locked until it restarts. `mcp-warden unlock` needs your approval in the dialog or Telegram. With Telegram configured, `/lock` from your phone does the same.
- **Find and fix plaintext keys.** `mcp-warden scan` finds API keys pasted into MCP client configs and `.env` files; it never prints a value. `mcp-warden import` moves them into the keychain, and `mcp-warden run <name>` launches the server with its key injected (see [Find and fix plaintext keys](#find-and-fix-plaintext-keys)).
- **Time-limited access and a policy simulator.** `preset grant <name> --for 1h` and `preset revoke <name>` limit how long a preset works. `preset test <name> GET /path` tells you whether a call would be allowed, and why, without sending anything.
- **Tighter responses.** A credential the upstream echoes back is scrubbed before the agent sees it. Per preset, `max_response_bytes` caps a response body and `response_fields` returns only the fields you list.
- **Better audit trail.** Every event names the MCP client and session that made it.
- **Telegram for several sessions.** Several Claude sessions share one bot: they take turns polling it, so button presses no longer get lost. `mcp-warden approval telegram-test` checks the setup end to end.
- **Five more templates:** `gitlab-read`, `linear`, `jira-read`, `slack-read`, `vercel-read`.
- **Behaviour changes:**
  - the MCP server reads `config.toml` once at startup, so restart it after editing presets;
  - the minimum Rust version is now 1.89.

Full list: [CHANGELOG.md](CHANGELOG.md#050).

## What's new in v0.4.0

- **Workspace split.** The project is now two crates: `mcp-warden-core` (library — trait surfaces + shared types) and `mcp-warden` (binary — CLI, MCP server, executor, web UI, concrete approval transports). Alternate implementations of `KeychainStore`, `ApprovalTransport`, `AuditSink`, or `PresetSource` now depend only on `mcp-warden-core` and don't drag the binary's GUI/runtime stack.
- **Telegram approval transport wired in.** The impl already existed in v0.3.0; v0.4.0 makes it actually selectable. Add to your config file (`mcp-warden doctor` prints its path: `~/.config/mcp-warden/` on Linux, `~/Library/Application Support/io.mcp-warden.mcp-warden/` on macOS):
  ```toml
  [approval.telegram]
  bot_token_secret = "tg_bot_token"   # name of the keychain entry, not the token value
  chat_id = 123456789                  # your numeric Telegram chat id
  timeout_seconds = 120                # optional
  ```
  then `mcp-warden secret add tg_bot_token` (pastes the bot token into the keychain). `prompt`-policy presets now send Approve / Deny inline-button messages to that chat; if the Telegram prompt times out, macOS asks again in the native dialog (see [`docs/approval-transports.md`](docs/approval-transports.md)). Override at runtime with `MCP_WARDEN_APPROVAL_TRANSPORT={telegram|desktop|tui}`.

## What's new in v0.3.0

- **`preset scaffold`** — 8 built-in templates for the most common APIs (`github-read`, `github-write`, `notion-read`, `stripe-read`, `openai-chat`, `anthropic-messages`, `gitea-read`, `cloudflare-dns`). Generate a working preset in one command instead of copy-pasting from the cookbook.
- **`preset from-openapi <url-or-file>`** — point it at an OpenAPI 3.0/3.1 JSON or YAML spec and it derives `base_url`, `allowed_paths`, `allowed_methods`, and the auth scheme (Bearer or APIKey-Header). Filter by HTTP method or tag.
- **`doctor --deep`** — for each HTTP preset, runs a safe read-only probe (GET against base URL or first literal allowed path), reports ok / auth_failed / auth_ok_404 / network_error / tls_error / skipped, with elapsed time and a redacted body snippet. Skips `prompt`-policy presets unless `--include-prompt` is passed.
- **`web`** — a small local-only web UI (binds `127.0.0.1`, hardcoded) for browsing presets and the audit log without spawning a TUI. Read-only in this release; approval over WebSocket is on the roadmap.
- **Telegram approval transport** — new `ApprovalTransport` impl that sends approval prompts to a Telegram chat with inline Approve / Deny / Approve-for-window buttons. Bot token lives in the OS keychain. Foreign-chat callbacks are rejected. Message uses `protect_content: true`. Selected automatically when `[approval.telegram]` is configured.

See `docs/web-ui.md` for the web UI design notes.

## Security model

`mcp-warden`'s threat model and security invariants live in [`docs/threat-model.md`](docs/threat-model.md). At a glance:

- Secrets in the OS keychain only — never on disk in plaintext, never in logs.
- A credential the upstream echoes back in a `proxy_http` response (an echo endpoint, an error that quotes the token) is replaced with `[redacted by mcp-warden]` before the agent sees it. The rest of the response is untrusted upstream data and is passed through as is.
- Allow-list validation runs **before** credential injection.
- Default approval policy is `prompt`; `auto` requires `--confirm-auto` at preset creation.
- The MCP server loads and validates `config.toml` once at startup and never re-reads it: restart the server after editing presets.
- Audit log is append-only — the trait surface itself contains no `delete` / `clear` method.
- `mcp-warden lock` stops every running server at its next call; a server that has seen the lock stays locked until it restarts, and `unlock` needs a human to approve it.
- Presets can cap and trim what `proxy_http` hands the agent (`max_response_bytes`, `response_fields`); a credential the upstream echoes back is always scrubbed.
- Wrapped servers (`mcp-warden run`) only get keys stored for them (`server/<name>/<VAR>`), never a preset's secret, and their command is fixed in the config. The key is still visible to the process it is handed to.
- Stdout is the MCP protocol channel; all logs go to stderr.

## Links

- crates.io: [`mcp-warden`](https://crates.io/crates/mcp-warden)
- MCP Registry name: `mcp-name: io.github.ermoluk/mcp-warden`

## License

Apache-2.0 — permanent commitment for the OSS core. See [LICENSE](LICENSE).

mcp-warden stays fully functional for free, forever — see our [open-core commitment](docs/open-core.md).
