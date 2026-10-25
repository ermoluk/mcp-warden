# Changelog

All notable changes to this project will be documented in this file. The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
