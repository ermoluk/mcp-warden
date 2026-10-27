# Changelog

All notable changes to this project will be documented in this file. The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **`cargo install mcp-warden` could not build 0.5.0.** It failed with `cannot find function use_native_store in crate keyring`: without `--locked`, cargo resolves the newest `keyring`, and keyring 4.2 moved that function behind a feature in a minor release. `mcp-warden-core` no longer depends on `keyring`. It links the OS credential stores directly through `keyring-core`: the macOS keychain, Windows Credential Manager and Linux keyutils. These are the same stores with the same settings, so secrets saved by earlier versions stay readable (verified on macOS). This also drops about 1,500 lines of unused dependencies from `Cargo.lock`. On other platforms mcp-warden now reports that no OS keychain is available, where `keyring` fell back to its plaintext sample store.

### Changed

- Install instructions use `cargo install --locked`, so a future semver break upstream can't break the install again.

## [0.5.0]

### Security

- **`proxy_http` returned a credential the upstream echoed back.** The response body reached the agent unchanged, so an upstream that reflects the request — httpbin-style `/headers` or `/anything`, a debug endpoint, an error such as `{"error": "invalid token …"}` — handed the agent the credential it is never meant to see, and from there it could reach transcripts, logs and anything the agent forwards. A prompt injection could steer the agent to such an endpoint whenever `allowed_paths` permitted one. Every key, string and number of the JSON body is now searched for each form the credential was sent in — raw, `<prefix><value>` for header auth, `base64(username:value)` for Basic auth, and percent-encoded — and each occurrence is replaced with `[redacted by mcp-warden]` before the body is returned; one stderr warning names the preset and the number of replacements, never the value (invariants 1–2). A body without the credential is returned unchanged. A credential the upstream returns truncated, split across fields, hashed or otherwise transformed cannot be detected; `ssh_exec` output and `db_query` rows are not scrubbed.
- **`mcp-warden mcp` re-read `config.toml` on every tool call.** Only the startup secret check used the config loaded at startup; `list_presets` and every action looked presets up in the file again. A preset added after startup was therefore served without that check, and an edit to `approval = "auto"` or a wider `allowed_paths` / `allowed_methods` took effect live — skipping `--confirm-auto`, and possible from any process, including the agent's own file-edit tool. The server now serves exactly the presets it validated at startup and never re-reads the file (invariant 10). **Behaviour change:** edits to `config.toml` take effect only after the MCP server restarts (in Claude Code: restart it, or reconnect the server from `/mcp`).

### Fixed

- **A config written by `mcp-warden` without presets started with `preset = []`**, after which any `[[preset]]` table added by hand was a TOML error and the MCP server refused to start. The empty list is no longer written.
- **`prompt` presets could not be approved on macOS.** macOS notifications have no buttons, so approval fell through to the TUI prompt — which cannot run when an MCP client launches the server. With no terminal (Claude Desktop) it failed with `io: Device not configured`, in a terminal (Claude Code CLI) with `io: Failed to initialize input reader`, both within a fraction of a second, so every `prompt` call was refused unless Telegram was configured. The call failed closed: nothing ran and no credential was read.
- **Approval transport errors left an unfinished audit event** with no decision or outcome. Such calls are now recorded with the new `failed` decision and the error as the outcome, and the agent is told the prompt could not be shown and the action did not run.

### Added

- **`/lock` from Telegram.** With `[approval.telegram]`, sending `/lock [reason]` to the bot from the configured chat locks mcp-warden like `mcp-warden lock`, and the bot confirms; unlocking still needs `mcp-warden unlock` on the computer. Every MCP server now listens in the background, and servers take turns polling through a file lock with a shared offset, so several Claude sessions no longer steal each other's updates; a press for another server's prompt is handed over through `telegram/inbox/`. Each button now carries its own random 128-bit token, which is the answer — so a local process can't forge or flip an answer through the inbox.
- **`mcp-warden approval telegram-test`** checks the Telegram setup end to end: the token works, a test prompt reaches the chat, and it reports which button you pressed (or what to fix).
- **Native approval dialog on Windows** — a Windows Forms window shown by the system Windows PowerShell, with the same buttons and rules as the macOS dialog (Deny on Enter / Esc / close, give-up timeout, request text passed as environment variables, never as script). Windows notifications have no buttons, so before this `prompt` presets on Windows needed Telegram. New and so far tested only in CI and with a stand-in helper.
- **The demo** shows the refused call landing in the audit log, and a new scene in which the agent runs `mcp-warden scan` (seeing only `ghp_…, 40 chars`) and `import` moves the key into the keychain.
- **Response limits for `proxy_http`** (per preset, opt-in). `max_response_bytes` reads no more than N bytes of the decoded body; a larger one is not returned — the agent gets the status, `body: null` and a `notice`. `response_fields = ["id", "owner.login", "items[].title"]` returns only those fields, keeping the body's shape; picked after the credential echo is scrubbed. `preset add --max-response-bytes / --response-fields`. The `proxy_http` description now tells the agent the body is untrusted data, never instructions, and its output gains an optional `notice`.
- **The audit log names the MCP client and session.** Every event records the client's `name version` (from `initialize`, sanitised) and a random per-process session id, shown by `mcp-warden audit` and the web UI. Existing `audit.db` files are migrated in place; old rows are kept.
- **Five more `preset scaffold` templates:** `gitlab-read`, `linear`, `jira-read`, `slack-read`, `vercel-read` — all `prompt`, with allow-lists that keep secret-bearing endpoints (GitLab CI variables, Vercel project env) out of reach.
- **`mcp-warden scan`** finds plaintext keys where MCP clients keep server definitions — `~/.claude.json` (only `mcpServers` and `projects.*.mcpServers`), Claude Desktop, Cursor, Windsurf, VS Code, Codex — and in `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` and `.env*` files of the current directory (`--path DIR` for more). It checks a server's `env`, `headers`, `args` and URL query: known token formats (GitHub, GitLab, Anthropic, OpenAI, Stripe, Slack, AWS, Google, Linear, Notion, npm, Hugging Face, DigitalOcean) with high confidence, long values under secret-sounding names with medium confidence, and never placeholders or references. Read-only, and the output never carries secret material — at most a token type's public prefix and the length — so an agent can run it safely. `--format json`, `--fail-on-findings` for CI.
- **`mcp-warden import`** moves the keys `scan` marks importable (`env` of stdio servers in JSON configs) into the keychain and rewrites each client entry to `mcp-warden run <name>`, keeping its other keys and order. Keys are stored and verified before anything is rewritten, no plaintext backup is kept, the plan is shown redacted and needs a y/N (or `--yes`), and `--dry-run` only shows it.
- **`mcp-warden run <name>`** launches another MCP server from a new `[[server]]` config entry with its keys injected from the keychain, so the client config holds `mcp-warden run <name>` instead of the key. A wrapped server only gets keys stored for it (`server/<name>/<VAR>`): the config lists variable names, never keychain entries, so no config edit can hand a preset's secret to a command. `mcp-warden server add <name> --env VAR -- <cmd…>` reads each value from stdin (never from argv); `server list` / `server remove` manage them. The key is still visible to the process it is handed to — see threat model R12.
- **`mcp-warden preset grant <name> --for 1h`** gives time-limited access (durations up to 30d; `--permanent` clears it), **`preset revoke <name>`** ends it. Calls after the window are refused and audited, and `list_presets` leaves the preset out and shows `expires_at` for the others. Expiry is checked on every call; new grants and revokes apply at the next server start.
- **`mcp-warden lock` / `unlock`** — a kill switch. Every MCP server refuses every call (`list_presets` included) from its next one on, drops its approval windows, and stays locked until it restarts even if the lock file is deleted. `unlock` removes the lock only after a human approves it in the dialog / notification / Telegram. Both are audited.
- **Policy simulator:** `mcp-warden preset test <name> GET /path` (or `--command`, `--get`/`--put`, `--query … --params N`) says whether that call would be allowed and why — the same checks the server runs, with lock and expiry — without sending anything or reading a secret. Exits 1 when refused; `--format json`.
- `mcp-warden doctor` shows the lock state, presets whose access has expired, and wrapped servers with missing keys.
- **Native approval dialog on macOS.** `prompt` presets ask in a dialog (via `osascript`) with Deny / Approve once / Approve for N min — the last only when the preset has an approval window. Deny is the default, so Return and Esc deny and approving takes a click; an unanswered dialog closes itself after 60 s and the call is refused as `timeout`. Request text is passed to a fixed AppleScript as arguments, never as script source. No extra macOS permissions are needed.
- **`failed` audit decision** — the approval prompt could not be shown; nobody approved and the action did not run. Shown by `mcp-warden audit` and `mcp-warden web`.

### Changed

- **Minimum Rust version is now 1.89** (for `File::try_lock`). CI also builds and tests on `windows-latest`.
- **The TUI is a fallback only where it can be seen.** On macOS the dialog has no fallback, and it is itself the fallback when a Telegram prompt times out. On Linux and Windows the TUI is asked after a timeout only when the server's stderr is a terminal — under an MCP client it was invisible. `MCP_WARDEN_APPROVAL_TRANSPORT=tui` still selects it explicitly.
- Docs, the `proxy_http` tool description and the plugin skill no longer say the approval prompt appears as a TUI in the MCP client's output panel.

## [0.4.3]

### Security

- **HTTP path allow-list bypass via encoded slashes and empty segments.** `allowed_paths` were matched against the raw path, where `%2F` is part of a segment, but upstreams that decode it before routing (nginx does by default) see a separator: `/repos/OWNER/[^/]+` let `/repos/OWNER/x%2Fcollaborators` reach `/repos/OWNER/x/collaborators`. Likewise `//` was accepted although upstreams that merge slashes route a different path. Patterns (exact strings and regexes) are now matched against the percent-decoded path, while the raw path is still what is sent, and paths are rejected if they contain an empty segment (raw or decoded) or decode to invalid UTF-8, control characters (`%00`, `%0a`, …), `\` or `.` / `..` segments (invariants 3 and 6). **Behaviour change** for presets that relied on encoded slashes: a GitLab-style id like `/projects/group%2Fproject` no longer matches `/projects/[^/]+` — use `/projects/[^/]+/[^/]+`; exact entries and regexes that spell out `%2F` (or any other percent-escape) must be written in decoded form.

### Changed

- **`github-read` and `gitea-read` templates now default to `approval = "prompt"`.** They ship without `allowed_paths`, and pairing an open allow-list with `auto` let an agent read every private repo a classic PAT can see without a single prompt — contrary to invariant 4. `preset scaffold` output explains how to narrow `allowed_paths` and switch to `auto` afterwards. A test now fails if any template combines empty `allowed_paths` with `auto`. Existing configs are unchanged.
- README, `docs/claude-code-setup.md`, the presets cookbook and the `init` config template now show `github-read` with `allowed_paths` set, so the quickstart no longer creates an open auto-approved preset.

### Added

- **Warnings for HTTP presets without `allowed_paths`.** An empty `allowed_paths` allows every path under `base_url`, and the built-in `github-read` template ships that way with `approval = "auto"`: with a classic PAT the agent can read every private repo the token can see. Behaviour is unchanged so existing configs keep working, but it is now visible: `mcp-warden doctor` prints a warning per such preset (and adds a `warnings` field to each `--deep --format json` probe result), `preset add --type http` without `--allowed-paths` warns on stderr, and `preset scaffold` explains it in `--dry-run` output for `github-read`, `stripe-read` and `gitea-read` (with an example allow-list and token advice) and warns when it writes the config. README and the presets cookbook now say that patterns match the whole path (exact strings or regexes anchored as `^(?:…)$`, never prefixes) and that `[^/]+` is safer than `.*` for one segment.
- **Refused requests are audited.** Calls turned away before authorisation — unknown preset, method / path / command / SFTP path / named query outside the allow-list, `allow_sftp` off, bad SFTP `direction` — used to return an error without leaving a trace. They are now recorded with the new `refused` decision, the preset name the agent sent (even one that doesn't exist), the raw request summary (`GET /raw/path`, `ssh host -- command`, …) and the validation error as the outcome. Nobody is prompted and no credential is read for them; the agent-supplied text of each refused event is capped at 1024 characters. The audit log stays append-only.
- **`mcp-warden audit` prints each event's summary** — what the agent asked for, not only the preset that matched. Long summaries are truncated with `…`, and control characters are stripped from agent-supplied text before it reaches the terminal.

## [0.4.2]

### Fixed

- **`proxy_http` broke MCP clients built on the TypeScript SDK.** Its output schema described `body` as the boolean schema `true`; the TS SDK rejects that, so `tools/list` failed in those clients (and in Glama's checks). `body` is now an object schema. A test checks every tool schema for this.

### Added

- **Claude Code plugin** (`plugins/mcp-warden/`), installable from this repo as a marketplace: `/plugin marketplace add ermoluk/mcp-warden`, then `/plugin install mcp-warden@mcp-warden`. Bundles the MCP server config (finds the binary on `PATH` or in `~/.cargo/bin`), the `using-mcp-warden` skill, a guided `/mcp-warden:setup` command that never routes secrets through the chat, and a `SessionStart` hook that flags a missing binary.

### Changed

- The `using-mcp-warden` skill moved from `skills/` into the plugin.

### Fixed

- Docs gave `~/.config/mcp-warden/` as the config location on every platform; on macOS it is `~/Library/Application Support/io.mcp-warden.mcp-warden/`. Docs now point to `mcp-warden doctor`, which prints the real path.

## [0.4.1]

### Security

- **SSH command / HTTP path allow-list bypass via alternation.** Patterns were anchored as `^{pattern}$`, so an entry like `uptime|df -h` compiled to `^uptime|df -h$` and matched `rm -rf / ; df -h`. All allow-list patterns are now anchored as `^(?:{pattern})$` through one shared helper (`config::anchored_regex`). Review any `allowed_commands` / `allowed_paths` entries that contain `|`.
- **SFTP local-path traversal.** The local path was checked with a string prefix, so `$HOME/../../etc/passwd` and `$HOME-other/…` passed. Now `..` is rejected, the parent directory is resolved through symlinks, roots are compared by whole components, and the target may not be a symlink. The local path is re-validated after approval and opened with `O_NOFOLLOW` (new files `0600`), closing the check-to-use window during the approval prompt. Remote `sftp_allowed_paths` prefixes are also compared by whole components (`/srv/app` no longer allows `/srv/app-secrets`).
- **HTTP path allow-list bypass via percent-encoded dots.** URL parsers treat `%2e` as `.`, so `/repos/%2e%2e/%2e%2e/admin` passed an allow-list like `/repos/.*` and was then normalised to `/admin`; with an empty `allowed_paths` it could also climb out of `base_url`'s path. `%2e`, `%5c`, `\` and `.` segments are now rejected, and the URL is refused if normalisation would change the validated path in any way. The URL is built before the approval prompt and credential lookup.
- **Telegram bot token in error messages.** reqwest errors include the request URL, and every Bot API URL embeds the token. Transport errors are now rendered without the URL before they reach logs or the agent (invariants 1 and 2).
- **Database passwords sent in plaintext.** Remote PostgreSQL, MySQL and Redis connections now require TLS with certificate and hostname verification. Plaintext is allowed only for `localhost`, loopback IPs and Unix sockets. **Breaking** for remote servers without TLS — use an SSH tunnel to `localhost` (threat model R10). The rustls crypto provider is pinned to `ring` at startup, since several dependencies compile in more than one.
- **Credentials could follow HTTP redirects.** `proxy_http` and `doctor --deep` followed redirects; reqwest strips `Authorization` on cross-origin hops but not custom auth headers (`Auth::Header`, e.g. `X-Api-Key`), so a 302 from the API could carry the key to another host — or reach a path outside the allow-list. Redirects are no longer followed; the 3xx is returned to the agent (threat model R11).

### Fixed

- **Telegram `timeout_seconds` was ignored.** Prompts always timed out after 60 s regardless of `[approval.telegram] timeout_seconds`. The setting is now honoured; the default is 120 s, as documented.
- **Telegram callbacks are pinned to the prompt message.** In addition to the chat-id check and per-request callback data, a button press is accepted only from the message sent for the current request (defence in depth).
- README: the TUI fallback is used when the Telegram prompt *times out*, not on every Telegram error — errors fail closed.

### Added

- `docs/approval-transports.md` — transport selection, Telegram setup and security properties, and how to write a custom `ApprovalTransport`.
- `SECURITY.md` — how to report a vulnerability.

### Changed

- CI now runs clippy and tests for the whole workspace (`--workspace`), so `mcp-warden-core`'s tests run too.
- Updated four yanked transitive dependencies (`aes`, `chacha20`, `der`, `spin`).
- `cargo fmt` applied across the codebase; clippy is clean under `-D warnings`.
- Removed the stale duplicate skill copy under `docs/agent-skill/`; `skills/using-mcp-warden/` is canonical.

### Roadmap

- `mcp-warden approval telegram-test` CLI helper (moved from 0.4.1).

## [0.4.0]

### Added

- **Workspace split.** New `mcp-warden-core` library crate ships the open-core trait surfaces (`KeychainStore`, `ApprovalTransport`, `AuditSink`, `PresetSource`) and shared types (`WardenError`, `Secret`, `Config`). The binary now depends on it; alternate implementations can attach to core without pulling the binary's full dep stack.
- **Telegram approval transport wired into the runtime.** Add `[approval.telegram]` to `config.toml` (or set `MCP_WARDEN_APPROVAL_TRANSPORT=telegram`) and `mcp-warden mcp` selects Telegram as the active transport with TUI as fallback. Validates the bot-token keychain entry at startup.

### Changed

- Versions bumped from 0.3.0 to 0.4.0 across both crates.
- `Config` gains an optional `approval: Option<ApprovalConfig>` field; existing configs without it parse unchanged.

### Known caveats / roadmap

- `russh` is still a dependency of `mcp-warden-core` (only because russh's `Handler::Error` requires `From<russh::Error>`). A binary-local newtype to drop this dep is on the roadmap.
- `docs/approval-transports.md` and `mcp-warden approval telegram-test` CLI helper are not in this release.

## [0.3.0]

### Added

- **`preset scaffold <template>`** — 8 built-in templates for common APIs (`github-read`, `github-write`, `notion-read`, `stripe-read`, `openai-chat`, `anthropic-messages`, `gitea-read`, `cloudflare-dns`). `--list` discovers, `--dry-run` previews, `--force` overwrites.
- **`preset from-openapi <source>`** — bootstrap a preset from an OpenAPI 3.0/3.1 JSON/YAML spec (URL or file). Derives `base_url`, `allowed_paths`, `allowed_methods`, and the auth scheme. `--method-filter` and `--tag-filter` narrow the surface. 50 MB spec size cap; file paths must resolve under `$HOME` or `/tmp/`.
- **`doctor --deep`** — for each HTTP preset, runs a safe read-only probe (GET) and reports per-preset status. Redacts body snippets matching common credential patterns (Bearer, token, password, api_key, …). Skips `prompt`-policy presets unless `--include-prompt`. `--format json` for machine output.
- **`web [--port N]`** — local-only read-only web UI (binds `127.0.0.1` hardcoded). Routes: dashboard, presets table, preset detail, audit log. CSP / X-Frame-Options / X-Content-Type-Options set on every response. All dynamic values HTML-escaped. Default port 7077.
- **Telegram approval transport** (`approval/telegram.rs`) — new `ApprovalTransport` impl that sends prompts to a Telegram chat with inline Approve / Deny / Approve-for-window buttons. Bot token lives in the OS keychain; foreign-chat callbacks are rejected; `protect_content: true` prevents message forwarding. Wiring into `cli/mcp.rs` (selecting Telegram over Desktop / TUI) is intentionally a small follow-up.

### Changed

- `cli::Command::Doctor` now carries `DoctorArgs` (breaking the bare-enum form). Default behaviour without flags is unchanged.
- `cli::preset::run()` is now `async` (because the OpenAPI bootstrap fetches the spec over HTTP).

### Dependencies

- Added `openapiv3 = "2.2"` and `serde_yaml = "0.9"` for OpenAPI parsing.
- Added `axum = "0.7"` for the local web UI.

## [0.2.0]

- Added `ssh_exec`, `sftp_transfer`, and `db_query` MCP tools.

## [0.1.0]

- Initial release.
