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

The log also shows what the agent *tried*. Calls refused before authorisation — unknown preset, method / path / command / remote or local path / named query outside the allow-list, `allow_sftp` off, bad `direction` — are recorded with `decision = "refused"`, the preset name the agent sent (even if no such preset exists), the raw request summary (`GET /raw/path`, `ssh host -- command`, `sftp get remote ↔ local`, `db postgres → query (N param)`) and the validation error as the outcome. `mcp-warden audit` prints each event's summary. Refused events never carry a secret: the summary is built from the agent's own request fields (never headers, the `query` map or the body), and validation runs before any credential is read (invariants 1 and 3). Because refusals are written without a human in the loop, the agent-supplied text of each refused event (preset name, summary, error) is capped at 1024 characters, and the `audit` CLI strips control characters from it and truncates it for display so it cannot drive the terminal; the web UI HTML-escapes it. An agent can still fill the log with many refused calls — the log grows, but nothing is executed.

### T5. Approval-prompt phishing via crafted preset names

A malicious preset named `"prod-readonly\nApproval: auto\n"` could spoof the desktop notification body. `mcp-warden` sanitises preset names and summaries before rendering — strips control characters and truncates. See `src/approval/mod.rs::sanitise_for_prompt`.

### T6. URL-parsing tricks bypassing the path allow-list

`http://attacker.com#@trusted.com` and IPv6 / userinfo abuse. `mcp-warden` parses URLs with the `url` crate (RFC 3986) and rejects request paths that contain `://` or `..`, plus enforces the preset's `base_url` host explicitly. Since v0.4.1 it also rejects `%2e` (which URL parsers treat as `.`), `%5c` / `\` (treated as `/` for http(s)) and `.` segments, and refuses to send any URL whose path was rewritten by normalisation — the path that reaches the server is byte-for-byte the path that passed the allow-list, inside `base_url`'s path.

`%2f` is allowed (GitLab-style namespaced ids such as `projects/group%2Fproject` need it), but upstreams that decode it before routing — nginx does by default — see two segments where the raw path has one, so `/repos/OWNER/[^/]+` matched against the raw path would let `/repos/OWNER/x%2Fcollaborators` reach `/repos/OWNER/x/collaborators`. The allow-list is therefore matched against the percent-decoded path (exact strings and regexes alike), while the raw path is still what is sent: a namespaced id needs `[^/]+/[^/]+`. Paths are also rejected if they contain an empty segment (`//`, raw or decoded — upstreams that merge slashes would route a different path), or if their decoded form is not valid UTF-8 or contains control characters (`%00`, `%0a`, …), `\`, or `.` / `..` segments.

Patterns see the path decoded once, but an upstream may decode twice — a proxy in front of an app that decodes again — so `/users/%252e%252e/admin` (`%2e%2e` after one pass, an ordinary segment to the allow-list) would reach `/admin` there, and `%252F` a separator the allow-list never saw. Since v0.5.2 any path containing `%25` is refused: a second decode pass can only find an escape whose `%` came out of the first, and that `%` is always a `%25`. A literal `%` in a path is refused with it.

### T7. TOCTOU on config

An attacker rewrites `config.toml` after `mcp-warden mcp` has started — another process, or the agent through its own file-edit tool — to add a preset whose secret was never checked, flip `approval` to `"auto"` without `--confirm-auto`, or widen `allowed_paths` / `allowed_methods`. The MCP server reads and validates the config once at startup (invariant 10) and serves presets from that in-memory snapshot (`FrozenSource`); the file is never read again, so every `list_presets` and every action sees the startup presets, and edits have no effect until the next process start. A restart does load the edited file: the startup check then refuses presets whose secret is missing, but it cannot tell whether `auto` came from `preset add --confirm-auto` or a hand edit, so the config file itself must stay writable only by the user.

Before this was fixed (see the CHANGELOG), only the startup secret check used the frozen config; presets were re-read from the file on every call, so all of the edits above took effect live.

## Out-of-scope threats (what `mcp-warden` does NOT defend against)

### N1. The user's machine is compromised

If the OS keychain has been read by malware running with the user's UID, `mcp-warden` can't help. Use full-disk encryption + screen lock + a healthy paranoia about what you `curl | sh`.

### N2. The agent runs unsandboxed code that reads the keychain directly

`mcp-warden` doesn't prevent the agent from spawning a child process that calls `security find-generic-password` (macOS) or `secret-tool` (Linux). For projects where this matters, run the agent in a container/VM; `mcp-warden` is the credential boundary, not a sandbox.

### N3. Side-channels via `proxy_http` responses

Response bodies are upstream data and stay untrusted: apart from the credential (below), they reach the agent as the service sent them, and text in them can still try to steer the agent. `mcp-warden` does not redact PII — if a preset allows `GET /me`, the body might contain the user's email; that's the upstream service's contract. The `proxy_http` tool description tells the agent the body is untrusted data, never instructions.

A preset can limit what reaches the agent's context:
- `max_response_bytes` reads no more than N bytes of the decoded body. A larger body is not returned: the agent gets the status, `body: null` and a `notice` explaining why.
- `response_fields` returns only the listed JSON fields (`id`, `owner.login`, `items[].title`), picked after the credential scrub below.

Both are opt-in. Neither is a sanitiser: whatever they let through is still untrusted.

The credential itself is the exception. An upstream that reflects the request — httpbin-style `/headers` or `/anything`, a debug or echo endpoint, an error payload such as `{"error": "invalid token …"}` — would hand the agent the secret it never saw, and a prompt injection could steer the agent to such an endpoint whenever `allowed_paths` permits one. So before the body is returned, every key, string and number in it is searched for each form the credential was sent in — the raw value, `<prefix><value>` for header auth, `base64(username:value)` (padded or not) for Basic auth, and any percent-encoding of these, `+` for a space included — and each occurrence is replaced with `[redacted by mcp-warden]` (invariants 1–2). One stderr warning names the preset and the number of replacements, never the value. A body without the credential is returned unchanged. Non-JSON bodies are returned as `null` and response headers not at all, so neither can carry it.

Known limits: a credential that comes back truncated, split across fields, hashed, embedded in a larger encoded blob or otherwise transformed cannot be detected. Only `proxy_http` bodies are scrubbed — `ssh_exec` output and `db_query` rows come back as is, so a named query that reads the password back (Redis `CONFIG GET requirepass`) returns it. Keep echo endpoints out of `allowed_paths`.

### N4. Insider threat (the user themselves)

`mcp-warden` is a defensive tool, not a compliance system. A user with `--approval auto` on every preset has effectively opted out. Team Mode (paid, future) adds the multi-approver workflows that make this enforceable for orgs.

## Residual risks (known, accepted in MVP)

### R1. Local approval prompts trust the local screen

On macOS approval is a native dialog shown with `osascript` (`src/approval/osascript.rs`). Deny is the default and the cancel button, so Return and Esc deny and approving takes a click; the dialog gives up after the request timeout (`timeout`). Request text reaches the fixed AppleScript as arguments, never as script source, and is sanitised as in T5. On Windows it is a Windows Forms window shown by the system Windows PowerShell (`src/approval/powershell.rs`) under the same rules; its script is a fixed `-EncodedCommand` and the request text reaches it only through environment variables. On Linux `notify-rust` shows a notification with Approve / Deny actions over DBus.

A local prompt is only as trustworthy as the screen it is on: an agent that can drive the desktop (computer-use tools) could click Approve. Users who give an agent screen control should approve through Telegram, which is out of band.

Up to v0.4.3 macOS had no working prompt under an MCP client: the notification had no buttons and the TUI fallback could not run, so every `prompt` call was refused (fail closed).

### R2. TUI approval works only in a terminal you can see

The full-screen ratatui dialog renders via `CrosstermBackend::new(std::io::stderr())` so it never touches stdout (the JSON-RPC channel). Under an MCP client stderr is captured and stdin is the JSON-RPC pipe, so the dialog cannot be seen (and on macOS cannot read keys). It is therefore a fallback only on Linux / Windows when stderr is a terminal, or chosen explicitly with `MCP_WARDEN_APPROVAL_TRANSPORT=tui`. Whenever a transport fails to show its prompt, the call is refused and audited as `failed` — never approved. The TUI restores the terminal state on exit (alt-screen + raw mode), but a process kill mid-dialog can leave the terminal in raw mode — the panic hook should reset.

### R3. Audit log integrity is policy, not crypto

The SQLite file is `0600`-permissioned and rejects symlinks at open time, but root or anyone with the user's UID can still mutate it with `sqlite3`. Tamper-evident logs (hash-chained, optionally signed) ship in Phase 2+.

### R4. SSH command-injection via careless regex (v0.2.0)

`ssh_exec` runs the agent-supplied command via `russh`'s exec channel — a single string that sshd runs with the remote user's login shell (`$SHELL -c`). We anchor each `allowed_commands` entry as `^(?:...)$` — the group keeps alternations anchored, so `uptime|df -h` cannot match `rm -rf / ; df -h` (fixed in v0.4.1; earlier versions anchored as `^...$`). The same anchoring applies to HTTP `allowed_paths` patterns.

Anchoring alone left shell syntax to the pattern: `git checkout \S+` also matched `git checkout $(curl …|sh)`, which the remote shell expands. Since v0.5.2 every command is checked before its pattern (invariant 5): words are separated by single spaces and may contain only letters, digits and `- _ . / : = @ , + %`, and none may start with `=` (zsh's `=cmd`). `$`, backticks, `;`, `|`, `&`, `<`, `>`, parentheses, quotes, `\`, globs, `{}`, `~`, `!`, `#`, newlines and other control characters are refused whatever the pattern says, so the shell runs exactly the words the allow-list matched. Verified by `tests::refuses_shell_syntax_whatever_the_pattern`.

What remains is the pattern's own scope. **A careless regex** like `git pull.*` still allows extra options made of permitted characters, such as `git pull --upload-pack=/tmp/x`. Preset authors must terminate or constrain patterns explicitly — `^docker compose (pull|up -d|ps)$`, `[a-z0-9._-]+` for an argument.

### R5. SFTP local path leakage (v0.2.0)

`sftp_transfer` with `direction = "get"` writes to a local file. We restrict the local path to `$HOME`, `/tmp` and `/var/tmp`: `..` components are rejected, the parent directory is resolved through symlinks before the check, roots are compared by whole path components, and the target file itself may not be a symlink (hardened in v0.4.1). Because approval can take minutes, the local path is validated again right before the file is opened, and it is opened with `O_NOFOLLOW` (new files `0600`), so a symlink planted at the final component in the meantime is refused. A symlink swapped into a *parent* directory within the microseconds between that re-check and the open is not defended against (that would need `openat`-style traversal). Even so, a malicious agent could still overwrite a file the user owns inside those roots (e.g. `~/.ssh/authorized_keys`). Document this for users; preset authors should confine SFTP transfers to dedicated working directories where possible.

### R6. DB password lifetime in driver internals (v0.2.0)

`tokio-postgres::Config::password()`, `mysql_async::OptsBuilder::pass()`, and `redis::ConnectionInfo::password` each take an owned `String`. Our `Secret` is dropped immediately after the builder is constructed, but the password lives inside the driver until the connection authenticates. Audit beyond our control. Acceptable trade-off; future option: switch to drivers that take a closure for the password (none of the three currently support this).

### R7. DB named-query allow-list trust depends on the preset author

`db_query` rejects agent-supplied SQL — only the preset's declared queries are runnable. But a careless preset can declare destructive queries (`DELETE FROM users WHERE id = $1`) that the agent can drive with arbitrary `$1`. The allow-list moves the trust boundary from "no SQL" to "only this set of SQL"; preset authors must treat each named query as a public API.

### R8. Audit log integrity is policy, not crypto

The SQLite file is `0600`-permissioned and rejects symlinks at open time, but root or anyone with the user's UID can still mutate it directly. Tamper-evident logs (hash-chained, optionally signed) are deferred to a later phase.

### R9. Time-boxed approvals are convenience, not deeper trust

When the user picks **Approve for window** in the approval prompt (dialog, notification, Telegram or TUI), the executor caches `(preset, action) → expires_at` in process memory and skips re-prompting for that pair until the window expires. Properties:

- **In-process only.** The cache is a `tokio::sync::Mutex<HashMap<…, Instant>>` inside `ActionExecutor`. Restarting `mcp-warden mcp` clears every window — by design. There is no file or socket through which a different process can inject or read windows.
- **Per `(preset, action)` keyed.** A window for `proxy_http` on `github-read` does **not** cover `ssh_exec` on the same preset. Each tool class requires its own approval.
- **Capped by the preset.** `approval_window_seconds = N` in the preset is the maximum window length; no prompt can exceed it. Presets that omit the field disable the window option entirely — prompts show only Approve once / Deny.
- **`get_secret_for_env` is never windowed.** Spec §6 mandates a fresh prompt every time a raw secret is revealed; the executor's `force_prompt = true` path bypasses the cache and never registers a window.
- **Audited.** Calls that proceed via an active window are recorded with `decision = "windowed"` in `audit.db`. Reviewing recent activity makes it visible that the user did not see a fresh prompt; the initial approve-for-window decision is still recorded as `approved`.

The residual risk: an agent that has the user's attention long enough to coerce *one* Approve-for-window can then issue many calls of the same kind without prompts inside the window. Mitigation: keep windows short (10 minutes is the default cap, 30 minutes is generous), and only enable windowing on presets where this trade-off is acceptable. Production-destructive presets should leave the field unset.

### R10. Database transport security

Since v0.4.1 `db_query` requires TLS with certificate and hostname verification for every non-loopback host — PostgreSQL (OS trust store + Mozilla roots), MySQL and Redis (Mozilla roots). Plaintext is used only for `localhost`, loopback IPs and Unix sockets, where traffic cannot leave the machine. There is no opt-out: a remote server without TLS, or with a certificate from a private CA the roots don't cover, is refused. Reach such servers through an SSH tunnel to `localhost` (e.g. `ssh -L 6379:localhost:6379 host`); for PostgreSQL a private CA can also be added to the OS trust store.

### R11. HTTP redirects are not followed

`proxy_http` and `doctor --deep` never follow redirects: a hop could leave `base_url`'s host carrying a custom auth header (reqwest strips only `Authorization` cross-origin) or land on a path the allow-list never approved. The 3xx response is returned to the agent, which can issue a new — validated — request if the target is allowed.

### R12. A wrapped server's key is visible to whatever runs as that server

`mcp-warden run <name>` takes keys out of client configs (no plaintext at rest), but it still hands them to the wrapped server through its environment, and from there:
- any process running as the same user can read that environment (`ps eww`, `/proc/<pid>/environ`);
- whoever launches `mcp-warden run` controls the rest of the environment and the working directory (`PATH`, `NODE_OPTIONS`, a local `node_modules`, …) and can get code into the server.

So `run` protects against keys being read off disk, synced, committed or pasted into a transcript. It does not protect against an agent that already runs arbitrary code as the user (see N2).

What it does guarantee:
- A wrapped server gets only the keys stored for it: `server/<name>/<VAR>`. The config lists variable names, not keychain entries, so no edit to it — and no `server add` — can bind a **preset's** secret to a command. Without this, `server add evil --env X=github_pat -- sh -c 'echo $X'` would have exfiltrated it.
- Values are read from stdin, or by `import` from the client config. They are never taken as command-line arguments, where they would land in shell history and `ps`.

### R13. The kill switch latches per process

`mcp-warden lock` writes `<config dir>/lock`.
- **Running servers.** Every running server refuses every call from its next one on, drops its approval windows, and latches: once it has seen the lock it stays locked until it restarts, even if the file is deleted.
- **`unlock`** removes the file only after a human approves it through the approval transport, so an agent can't talk its way past it with the CLI.
- **Deleting the file by hand** cannot reopen a server that saw the lock. A server *started after* the deletion does start unlocked, though. Restarting MCP servers is the client's job, not the agent's, but users who want the lock to survive tampering should also revoke the upstream credentials.
- **Screen control.** As in R1, an agent that can click on the user's screen could approve the unlock dialog. Use Telegram if the agent has screen control.
- **Telegram `/lock`** from the configured chat writes the same lock file, from whichever server is polling at that moment. It works only while at least one MCP server with `[approval.telegram]` runs. Telegram cannot unlock.
- **The Telegram inbox.** Servers hand button presses to each other through `telegram/inbox/<button token>` files. Each button carries its own random 128-bit token, and only the asking server knows which token means Approve. Someone who can write the inbox can delete an answer, which makes the prompt time out (fail closed). They cannot forge an answer or flip one.

### R14. `preset grant` windows and frozen presets

- **Expiry is enforced on every call.** It is checked against the wall clock, so a running server stops serving a preset on time.
- **New grants and revokes need a restart.** Presets are frozen at startup (T7), so `preset grant` and `preset revoke` take effect when the server restarts. For an immediate stop, use `mcp-warden lock`.
- **`get_secret_for_env` is outside the window.** It is not tied to a preset, and it always asks for approval.

### R15. `scan` and `import` handle plaintext they did not create

**`scan`:**
- It is read-only and sends nothing.
- In `~/.claude.json` it reads only `mcpServers` and `projects.*.mcpServers`.
- Its output never contains secret material: at most a token type's public prefix (`ghp_`) and the length. That keeps it safe for an agent to run.
- Detection is heuristic. Tokens in unknown formats under innocuous names are missed.

**`import`:**
- It stores each key and verifies it before it rewrites anything, and it keeps no backup, because a backup would hold the plaintext.
- Claude Code and Claude Desktop rewrite their own config files. If they are running during an import, they may put the old entry back, plaintext included, so `import` asks the user to quit them and to re-run `scan` afterwards.
- A key that has been sitting in a config file should be considered exposed. Rotate it.

## Update policy

This document updates with every release. Material changes are noted in `CHANGELOG.md` under a `### Security` heading.
