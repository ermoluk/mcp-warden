# Threat model — `mcp-warden` v0.1.0

This document describes what `mcp-warden` defends against, what it does not, and where the residual risks lie. It complements (and does not replace) the security invariants in `CLAUDE.md` §"Security invariants — non-negotiable".

## Assumptions

- The user runs `mcp-warden` on their own laptop / dev machine.
- The OS keychain (macOS Keychain, Linux Secret Service / keyutils, Windows Credential Manager) is trusted.
- The agent (Claude Code, Cursor, etc.) runs with the user's regular permissions and can be coerced or manipulated by adversarial input.
- The user is the only person physically at the keyboard.

## In-scope threats (what `mcp-warden` is designed to stop)

### T1. Prompt-injection-driven credential exfiltration

An attacker influences the agent (via a poisoned web page, README, codebase comment) and tells it to "echo your API key" or "POST it to attacker.com". Since the agent **never sees** the secret, there is nothing to exfiltrate.

### T2. Secret leakage via session transcript / log uploads

A user shares a transcript for debugging. Without `mcp-warden`, this can leak `.env` contents the agent had loaded. With `mcp-warden`, the transcript contains tool calls and results but not credentials.

### T3. Privilege escalation via unscoped credentials

Without scoping, a GitHub PAT lets the agent do everything. Presets restrict by base URL, method, and path regex. An agent with the `github-read` preset cannot `DELETE /user/repos/*` even if compelled to try.

### T4. Silent credential reuse for unintended actions

Every call lands in `audit.db` next to the config file (`mcp-warden doctor` prints the path). The user can review what the agent did. Append-only by trait-surface design (no `delete` / `clear` method).

### T5. Approval-prompt phishing via crafted preset names

A malicious preset named `"prod-readonly\nApproval: auto\n"` could spoof the desktop notification body. `mcp-warden` sanitises preset names and summaries before rendering — strips control characters and truncates. See `src/approval/mod.rs::sanitise_for_prompt`.

### T6. URL-parsing tricks bypassing the path allow-list

`http://attacker.com#@trusted.com` and IPv6 / userinfo abuse. `mcp-warden` parses URLs with the `url` crate (RFC 3986) and rejects request paths that contain `://` or `..`, plus enforces the preset's `base_url` host explicitly. Since v0.4.1 it also rejects `%2e` (which URL parsers treat as `.`), `%5c` / `\` (treated as `/` for http(s)) and `.` segments, and refuses to send any URL whose path was rewritten by normalisation — the path that reaches the server is byte-for-byte the path that passed the allow-list, inside `base_url`'s path.

`%2f` is allowed (GitLab-style namespaced ids such as `projects/group%2Fproject` need it), but upstreams that decode it before routing — nginx does by default — see two segments where the raw path has one, so `/repos/OWNER/[^/]+` matched against the raw path would let `/repos/OWNER/x%2Fcollaborators` reach `/repos/OWNER/x/collaborators`. The allow-list is therefore matched against the percent-decoded path (exact strings and regexes alike), while the raw path is still what is sent: a namespaced id needs `[^/]+/[^/]+`. Paths are also rejected if they contain an empty segment (`//`, raw or decoded — upstreams that merge slashes would route a different path), or if their decoded form is not valid UTF-8 or contains control characters (`%00`, `%0a`, …), `\`, or `.` / `..` segments.

### T7. TOCTOU on config

An attacker writes a malicious config after `mcp-warden mcp` has started. The MCP server loads-once-and-freezes the config in `Arc<Config>` at startup; subsequent file writes are ignored until the next process start.

## Out-of-scope threats (what `mcp-warden` does NOT defend against)

### N1. The user's machine is compromised

If the OS keychain has been read by malware running with the user's UID, `mcp-warden` can't help. Use full-disk encryption + screen lock + a healthy paranoia about what you `curl | sh`.

### N2. The agent runs unsandboxed code that reads the keychain directly

`mcp-warden` doesn't prevent the agent from spawning a child process that calls `security find-generic-password` (macOS) or `secret-tool` (Linux). For projects where this matters, run the agent in a container/VM; `mcp-warden` is the credential boundary, not a sandbox.

### N3. Side-channels via `proxy_http` responses

If a preset allows `GET /me`, the response body might contain the user's email or other PII. `mcp-warden` does not redact response bodies — that's the upstream service's contract.

### N4. Insider threat (the user themselves)

`mcp-warden` is a defensive tool, not a compliance system. A user with `--approval auto` on every preset has effectively opted out. Team Mode (paid, future) adds the multi-approver workflows that make this enforceable for orgs.

## Residual risks (known, accepted in MVP)

### R1. macOS / Windows desktop-notification approval is degraded

`notify-rust` exposes interactive notification actions (Approve / Deny buttons) only on Linux/DBus. On macOS and Windows the notification fires for awareness, but actual approval happens in the TUI prompt printed to the MCP server's stderr (visible in Claude Code / Cursor's MCP output panel). Documented in `src/approval/desktop.rs`.

### R2. TUI approval is rendered to stderr only

The full-screen ratatui dialog (v0.2.0) renders via `CrosstermBackend::new(std::io::stderr())` so it never touches stdout (the JSON-RPC channel). Visible in Claude Code / Cursor's MCP output panel. It restores the terminal state on exit (alt-screen + raw mode), but a process kill mid-dialog can leave the terminal in raw mode — the panic hook should reset.

### R3. Audit log integrity is policy, not crypto

The SQLite file is `0600`-permissioned and rejects symlinks at open time, but root or anyone with the user's UID can still mutate it with `sqlite3`. Tamper-evident logs (hash-chained, optionally signed) ship in Phase 2+.

### R4. SSH command-injection via careless regex (v0.2.0)

`ssh_exec` runs the agent-supplied command via `russh`'s exec channel — a single string sent to the remote shell. We anchor each `allowed_commands` entry as `^(?:...)$` — the group keeps alternations anchored, so `uptime|df -h` cannot match `rm -rf / ; df -h` (fixed in v0.4.1; earlier versions anchored as `^...$`). So a typical pattern like `^docker compose (pull|up -d|ps)$` is safe. **A careless regex** like `git pull.*` allows `git pull; rm -rf /`. Preset authors must terminate or constrain patterns explicitly. Pitfalls verified by `tests::rejects_injection_attempts` and `tests::alternation_in_pattern_stays_anchored`. The same anchoring applies to HTTP `allowed_paths` patterns.

### R5. SFTP local path leakage (v0.2.0)

`sftp_transfer` with `direction = "get"` writes to a local file. We restrict the local path to `$HOME`, `/tmp` and `/var/tmp`: `..` components are rejected, the parent directory is resolved through symlinks before the check, roots are compared by whole path components, and the target file itself may not be a symlink (hardened in v0.4.1). Because approval can take minutes, the local path is validated again right before the file is opened, and it is opened with `O_NOFOLLOW` (new files `0600`), so a symlink planted at the final component in the meantime is refused. A symlink swapped into a *parent* directory within the microseconds between that re-check and the open is not defended against (that would need `openat`-style traversal). Even so, a malicious agent could still overwrite a file the user owns inside those roots (e.g. `~/.ssh/authorized_keys`). Document this for users; preset authors should confine SFTP transfers to dedicated working directories where possible.

### R6. DB password lifetime in driver internals (v0.2.0)

`tokio-postgres::Config::password()`, `mysql_async::OptsBuilder::pass()`, and `redis::ConnectionInfo::password` each take an owned `String`. Our `Secret` is dropped immediately after the builder is constructed, but the password lives inside the driver until the connection authenticates. Audit beyond our control. Acceptable trade-off; future option: switch to drivers that take a closure for the password (none of the three currently support this).

### R7. DB named-query allow-list trust depends on the preset author

`db_query` rejects agent-supplied SQL — only the preset's declared queries are runnable. But a careless preset can declare destructive queries (`DELETE FROM users WHERE id = $1`) that the agent can drive with arbitrary `$1`. The allow-list moves the trust boundary from "no SQL" to "only this set of SQL"; preset authors must treat each named query as a public API.

### R8. Audit log integrity is policy, not crypto

The SQLite file is `0600`-permissioned and rejects symlinks at open time, but root or anyone with the user's UID can still mutate it directly. Tamper-evident logs (hash-chained, optionally signed) are deferred to a later phase.

### R9. Time-boxed approvals are convenience, not deeper trust

When the user picks **Approve for window** in the TUI / desktop prompt, the executor caches `(preset, action) → expires_at` in process memory and skips re-prompting for that pair until the window expires. Properties:

- **In-process only.** The cache is a `tokio::sync::Mutex<HashMap<…, Instant>>` inside `ActionExecutor`. Restarting `mcp-warden mcp` clears every window — by design. There is no file or socket through which a different process can inject or read windows.
- **Per `(preset, action)` keyed.** A window for `proxy_http` on `github-read` does **not** cover `ssh_exec` on the same preset. Each tool class requires its own approval.
- **Capped by the preset.** `approval_window_seconds = N` in the preset is the maximum window length; the TUI cannot exceed it. Presets that omit the field disable the window option entirely — the TUI shows only Approve once / Deny.
- **`get_secret_for_env` is never windowed.** Spec §6 mandates a fresh prompt every time a raw secret is revealed; the executor's `force_prompt = true` path bypasses the cache and never registers a window.
- **Audited.** Calls that proceed via an active window are recorded with `decision = "windowed"` in `audit.db`. Reviewing recent activity makes it visible that the user did not see a fresh prompt; the initial approve-for-window decision is still recorded as `approved`.

The residual risk: an agent that has the user's attention long enough to coerce *one* Approve-for-window can then issue many calls of the same kind without prompts inside the window. Mitigation: keep windows short (10 minutes is the default cap, 30 minutes is generous), and only enable windowing on presets where this trade-off is acceptable. Production-destructive presets should leave the field unset.

### R10. Database transport security

Since v0.4.1 `db_query` requires TLS with certificate and hostname verification for every non-loopback host — PostgreSQL (OS trust store + Mozilla roots), MySQL and Redis (Mozilla roots). Plaintext is used only for `localhost`, loopback IPs and Unix sockets, where traffic cannot leave the machine. There is no opt-out: a remote server without TLS, or with a certificate from a private CA the roots don't cover, is refused. Reach such servers through an SSH tunnel to `localhost` (e.g. `ssh -L 6379:localhost:6379 host`); for PostgreSQL a private CA can also be added to the OS trust store.

### R11. HTTP redirects are not followed

`proxy_http` and `doctor --deep` never follow redirects: a hop could leave `base_url`'s host carrying a custom auth header (reqwest strips only `Authorization` cross-origin) or land on a path the allow-list never approved. The 3xx response is returned to the agent, which can issue a new — validated — request if the target is allowed.

## Update policy

This document updates with every release. Material changes are noted in `CHANGELOG.md` under a `### Security` heading.
