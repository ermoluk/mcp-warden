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

## How it compares

Other MCP credential brokers make different trade-offs:

| | mcp-warden | [Keyward](https://github.com/arturayupov/keyward) | [Wundervault](https://github.com/wundervault/wundervault-mcp) | [Janee](https://github.com/rsdouglas/janee) |
|---|---|---|---|---|
| Secret stays out of the agent's context | Yes, except `get_secret_for_env`, which always asks first | Not returned to the agent; written into a project file such as `.env` | Yes, no tool returns a value | Yes |
| What the agent can do | HTTP, SSH commands, SFTP, named SQL / Redis queries | Have a key written into a project file | HTTP, SSH commands / rsync, x402 payments, signing | HTTP (incl. AWS SigV4 / OAuth 1.0a signing), CLI tools with injected env vars |
| Per-call allow-lists | HTTP method + path, SSH command regex, SFTP paths, named DB queries | Not yet (per-key policy is on its roadmap) | Allowed SSH hosts per key; an approval is bound to the HTTP destination, method and path | HTTP method + path rules, allowed executables |
| Human approval | Native dialog (macOS, Windows), notification (Linux) or Telegram; on by default | Native OS dialog per request, once or for the session | Passkey, for secrets marked "ask me first" | ? |
| Where secrets live | OS keychain | `age`-encrypted file, master key in the OS keystore | End-to-end encrypted hosted vault, used by a local broker | Encrypted file in `~/.janee/`, master key in the OS keychain or a file |
| No cloud account or background service | Yes | Yes | No: needs a wundervault.com vault and a broker installed with admin rights | Yes (stdio; HTTP mode for containers) |
| Audit log | Local SQLite, append-only, includes refused calls | Local JSONL of decisions | On your computer, tamper-evident | Local JSONL of requests |
| Kill switch | `mcp-warden lock`, or `/lock` in Telegram | ? | Revoke an agent in the vault | Revoke a session (`janee revoke`) |
| Works with any MCP client | Yes | Yes | Yes | Yes |
| License | Apache-2.0 | MIT | AGPL-3.0 (the hosted vault is not open source) | MIT |
| Install | `cargo install`, or binaries for macOS / Linux | Homebrew, Scoop, `go install`, binaries | npm plus a broker installer, free account | npm or Docker |

Compared with Keyward 0.1.1, Wundervault MCP server 2.0.1 and Janee 0.16.0, from each project's README and docs as of October 2026. `?` means not documented there. If something here is wrong or out of date, please open an issue.

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
- Release notes: [CHANGELOG.md](CHANGELOG.md)
- MCP Registry name: `mcp-name: io.github.ermoluk/mcp-warden`

## License

Apache-2.0 — permanent commitment for the OSS core. See [LICENSE](LICENSE).

mcp-warden stays fully functional for free, forever — see our [open-core commitment](docs/open-core.md).
