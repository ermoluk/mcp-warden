# Threat model — `mcp-warden`

Current as of v0.5.4 (unreleased). This document describes what `mcp-warden` defends against, what it does not, and where the residual risks lie. It complements (and does not replace) the security invariants in `CLAUDE.md` §"Security invariants — non-negotiable".

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

A malicious preset named `"prod-readonly\nApproval: auto\n"` could spoof the desktop notification body. `mcp-warden` sanitises preset names and summaries before rendering — strips control characters and truncates. See `core/src/approval/mod.rs::sanitise_for_prompt`.

Stripping control characters (Unicode category Cc) is not enough: up to v0.5.3 the bidi overrides, embeddings and isolates (U+202A–202E, U+2066–2069), zero-width characters, the line and paragraph separators U+2028 / U+2029 and long runs of combining marks passed through. The agent controls text that reaches a prompt — the `remote` and `local` paths of `sftp_transfer`, the secret name of `get_secret_for_env` — and text that reaches the audit views — the preset name, summary and error of every refused call, the client name. With U+202E a path such as `/srv/app/\u{202E}gol.cod` is displayed reversed, and U+2028 starts a new line in many dialogs. Since v0.5.4 every format character (Cf), U+2028 / U+2029 and the Hangul fillers are shown as a visible `\u{XXXX}` escape, and a character keeps at most two combining marks. The same function feeds every transport (the macOS and Windows dialogs, the Linux notification, Telegram, the TUI), `mcp-warden audit`, and — newly — the web UI, which escaped HTML but not these characters.

### T6. URL-parsing tricks bypassing the path allow-list

`http://attacker.com#@trusted.com` and IPv6 / userinfo abuse. `mcp-warden` parses URLs with the `url` crate (RFC 3986) and rejects request paths that contain `://` or `..`, plus enforces the preset's `base_url` host explicitly. Since v0.4.1 it also rejects `%2e` (which URL parsers treat as `.`), `%5c` / `\` (treated as `/` for http(s)) and `.` segments, and refuses to send any URL whose path was rewritten by normalisation — the path that reaches the server is byte-for-byte the path that passed the allow-list, inside `base_url`'s path.

`%2f` is allowed (GitLab-style namespaced ids such as `projects/group%2Fproject` need it), but upstreams that decode it before routing — nginx does by default — see two segments where the raw path has one, so `/repos/OWNER/[^/]+` matched against the raw path would let `/repos/OWNER/x%2Fcollaborators` reach `/repos/OWNER/x/collaborators`. The allow-list is therefore matched against the percent-decoded path (exact strings and regexes alike), while the raw path is still what is sent: a namespaced id needs `[^/]+/[^/]+`. Paths are also rejected if they contain an empty segment (`//`, raw or decoded — upstreams that merge slashes would route a different path), or if their decoded form is not valid UTF-8 or contains control characters (`%00`, `%0a`, …), `\`, or `.` / `..` segments.

Patterns see the path decoded once, but an upstream may decode twice — a proxy in front of an app that decodes again — so `/users/%252e%252e/admin` (`%2e%2e` after one pass, an ordinary segment to the allow-list) would reach `/admin` there, and `%252F` a separator the allow-list never saw. Since v0.5.2 any path containing `%25` is refused: a second decode pass can only find an escape whose `%` came out of the first, and that `%` is always a `%25`. A literal `%` in a path is refused with it.

Since v0.5.3 two more classes of path are refused before the allow-list sees them:

- **Malformed escapes.** `percent_decode_str` decodes only `%` followed by two hex digits and leaves anything else as text. IIS and ASP.NET also decode the non-standard `%uXXXX` form, so `/users/%u005cadmin` — an ordinary segment to the allow-list — is `/users/\admin` to them, and `%u002e%u002e` is `..`. Every `%` must now start an escape of exactly two hex digits; `%u…`, `%zz` and a trailing `%` are refused.
- **Unicode compatibility forms.** An upstream that applies NFKC normalisation after decoding turns `／` (U+FF0F) into `/`, `．．` (U+FF0E) into `..`, `＼` (U+FF3C) into `\`, and ligatures, superscripts or the Kelvin sign into plain letters and digits. A path is refused if NFKC would change its decoded form, so every upstream routes the characters the allow-list matched. Raw (unencoded) forms were already refused before sending — the URL parser re-encodes non-ASCII, and `build_url` refuses any path it rewrites — but the check now runs in the allow-list for both. Text NFKC leaves unchanged (Cyrillic, CJK, Hangul, accented letters in composed form) still passes; a decomposed accent (`й` written as `и` + U+0306) is refused and must be sent composed.

Together with the earlier checks this gives three properties, tested with generated paths (`proptest`) in `src/executor/http.rs`: an accepted path decodes to the same string on a second pass, its decoded form is NFKC-stable, and neither pass yields a `.`/`..` segment, `\`, a control character or an empty segment. Every input that has bypassed the allow-list so far is kept in `tests/corpus/paths.txt`, and CI fails if any of them is allowed by a preset with `allowed_paths = [".*"]`.

**Method override.** The allow-list checks the method the request is sent with, but some frameworks run a request as another method on the client's say-so: Laravel and Symfony (with method parameter override on, Laravel's default) treat `POST /x?_method=DELETE` as a DELETE, Laravel also reads `_method` from a JSON body, and Express `method-override` can be configured to read the query string. Up to v0.5.3 neither the `query` map nor the body was checked, so a preset allowing `POST` also allowed `DELETE` on such an upstream. Since v0.5.4, query parameters and top-level body keys named `_method`, `X-HTTP-Method-Override`, `X-HTTP-Method` or `X-Method-Override` are refused before the credential is read — compared case-insensitively and after PHP's own renaming (leading spaces dropped, `.`, ` ` and `[` read as `_`, an array suffix like `_method[]` ignored) — as are query parameter names with control characters. The agent cannot set request headers at all, so the header forms of these overrides never reach the upstream. Every refused key is in `tests/corpus/queries.txt`.

### T7. TOCTOU on config

An attacker rewrites `config.toml` after `mcp-warden mcp` has started — another process, or the agent through its own file-edit tool — to add a preset whose secret was never checked, flip `approval` to `"auto"` without `--confirm-auto`, or widen `allowed_paths` / `allowed_methods`. The MCP server reads and validates the config once at startup (invariant 10) and serves presets from that in-memory snapshot (`FrozenSource`); the file is never read again, so every `list_presets` and every action sees the startup presets, and edits have no effect until the next process start. A restart does load the edited file: the startup check then refuses presets whose secret is missing. Up to v0.5.3 it could not tell whether `auto` came from `preset add --confirm-auto` or a hand edit — and `--confirm-auto` is a flag an agent with a shell can pass as well.

Before this was fixed (see the CHANGELOG), only the startup secret check used the frozen config; presets were re-read from the file on every call, so all of the edits above took effect live.

**Edits that take effect at the next start.** MCP clients start a fresh server for every session, so "the next process start" comes soon, and an agent that can write files can make it read a config of its choosing: edit `config.toml`, or point `MCP_WARDEN_CONFIG_DIR` in a project's `.mcp.json` at a directory it controls. Such a config can bind any existing keychain entry to any `base_url`. Up to v0.5.3 the approval prompt for `proxy_http` showed only the method and path, so a `prompt` preset re-pointed at `attacker.example` looked exactly like before. Since v0.5.4 the prompt and the audit summary name the destination — `GET https://api.github.com/user/repos`, `db postgres db.internal → user_by_id (1 param)` — as `ssh_exec` already did (`ssh host -- …`).

**Confirmations bound to the config they confirm.** Since v0.5.4 the decisions that let a credential be used without a prompt count only in the exact form a human confirmed through the approval transport — the dialog or Telegram, which the agent cannot answer (R1 aside):

- An `auto` preset runs without asking only if the keychain entry `stamp/preset/<name>` holds the SHA-256 of the preset's canonical form (every field: destination, credential, allow-lists, policy, `expires_at`). `preset add --approval auto --confirm-auto`, `approval <name> auto --confirm-auto`, `preset grant` on an `auto` preset and the new `mcp-warden preset confirm [NAME]…` write the stamp, each after an approval prompt that spells out the policy, the secret, the destination and the allow-lists. Any edit voids it: the server then serves the preset as `prompt` and says so on stderr, and `doctor` lists it.
- A `[[server]]` gets its keys from `mcp-warden run` only as the command a human confirmed (`stamp/server/<name>`: name, command, arguments, variables). The first launch, and the first after any edit — `command = "sh"`, `args = ["-c", "env > /tmp/x"]` — asks first, naming the command and the keys; denied, nothing starts.

A stamp is not the fingerprint itself — anyone can hash a config — but its HMAC-SHA256 under a random key that lives only in the keychain (`stamp/key`) and is never shown. `mcp-warden secret add` and `secret remove` refuse every `stamp/` name, and no preset may use one as its secret, so neither the CLI (which an agent with a shell can run) nor `get_secret_for_env` can write a stamp or read the key.

What this defends against: an agent that can write files (the config, or a client config that sets `MCP_WARDEN_CONFIG_DIR`), and run the CLI, but cannot write the OS keychain directly or answer the approval prompt. What it does not: N2 (an agent that runs code writing the keychain directly) and R1 (an agent that clicks the dialog). A `prompt` preset needs no stamp: the human sees its destination in every prompt. Stamps are keychain entries holding a hash, not a secret; `secret list` hides them. **Behaviour change:** after upgrading, every `auto` preset asks until `mcp-warden preset confirm` is run once, and every wrapped server asks on its first launch.

### T8. Oversized agent input

Up to v0.5.2 nothing capped what an agent could send: a megabyte-long path or command went through the allow-list regexes, into the approval prompt (truncated for display only), into the audit log for approved calls and on to the upstream. Since v0.5.3 every call is checked against fixed limits first — in `policy::check_request`, before the preset kind, the patterns, percent-decoding or any credential (invariant 3). `mcp-warden preset test` applies the same limits. The constants are in `src/executor/limits.rs`:

| Input | Limit | Why this size |
|---|---|---|
| `proxy_http` path | 2048 bytes | Common upstream URL limits are 2–8 KB, and real API paths are a few hundred bytes at most. |
| `proxy_http` query | 64 parameters, 4096 bytes of keys and values | Room for filters and pagination, but not for a payload smuggled into the URL. |
| `proxy_http` JSON body | 1 MiB, serialised | Enough for API writes such as issues, comments or file contents; measured with a writer that stops at the limit, so a larger body is never serialised in full. |
| `ssh_exec` command | 1024 bytes | Allow-listed commands are short; longer ones are a sign of an injection attempt. |
| `sftp_transfer` remote / local path | 1024 bytes each | macOS `PATH_MAX` is 1024. |
| `db_query` parameters | 32 parameters, 16 KiB each | Named queries take a handful of values; 16 KiB leaves room for a text field. |

A refused call returns an error naming the field and the limit, never the input, and is audited as `refused` like any other validation failure. Its agent-supplied text is still capped at 1024 characters in the audit log (T4).

**The MCP channel itself.** Up to v0.5.3 the server read stdin with rmcp's line codec, which has no length limit and treats any undecodable line as the end of input: one line of broken JSON made the server exit (and the client restart it — with whatever config it then finds, T7), and a single huge line was buffered whole. Since v0.5.4 a line longer than 16 MiB, or one that is not a JSON-RPC message, is logged to stderr and skipped; the session goes on. Tested in `tests/mcp_integration.rs` with broken JSON, a JSON array, a 32 MiB line and wrongly typed arguments.

### T10. Oversized or stalling upstream responses

The upstream can be hostile too — or simply broken — and up to v0.5.3 several of its answers had no bound:

- **HTTP bodies.** Without `max_response_bytes` the body was read in full, and reqwest decompresses gzip on the way: an 11 KiB response decoded to 11 MiB of memory, all of it handed to the agent's context.
- **SSH output.** `ssh_exec` kept stdout and stderr for as long as the host wrote them; only the command timeout ended the call.
- **SSH and SFTP set-up.** The timeout covered only reading the command's output, so a host that accepted the key and then never opened a channel held the call forever. `sftp_transfer` had no timeout at all.
- **Databases.** `db_query` had no timeout, and its rows had no size limit.

Since v0.5.4 (constants in `src/executor/limits.rs`):

| Upstream | Bound |
|---|---|
| `proxy_http` body | 10 MiB decoded, whatever the preset says; `max_response_bytes` can only lower it. A larger body is not returned: `body: null` and a `notice`. |
| `ssh_exec` output | 1 MiB of stdout and 1 MiB of stderr; past that the channel is closed and `notice` says the output was cut. |
| `ssh_exec` call | `timeout_seconds` (default 120 s) for the whole call: connecting, key exchange, authentication and the command. |
| `sftp_transfer` call | `timeout_seconds` (default 600 s) for the whole transfer. |
| `db_query` call | `timeout_seconds` (default 30 s) for connecting, authenticating and the query. |
| `db_query` rows | 10 MiB serialised; larger results are not returned: no rows and a `notice`. |

Deeply nested JSON never reaches the recursive scrub and field selection: serde_json refuses more than 128 levels, and such a body comes back as `null`. Known limit: the database drivers read the whole result into memory before its size is checked, so a hostile database can still make the process allocate a large result once; HTTP bodies and SSH output are cut while they are read.

### T9. DNS rebinding against `mcp-warden web`

The web UI binds 127.0.0.1 only and has no login, so any local process can read it — and, up to v0.5.3, so could any web page the user opened. A hostile page re-points its own domain at 127.0.0.1 (DNS rebinding); the browser then treats `http://evil.example:7077/audit` as same-origin and lets the page read the presets (hosts, paths, secret names) and the audit log. Since v0.5.4 the UI answers only requests whose `Host` header names it — `127.0.0.1:<port>`, `localhost:<port>` or `[::1]:<port>` — and refuses the rest with 421 before any handler runs; a rebinding page cannot make the browser send another `Host`. Requests other than GET / HEAD (none exist yet) must in addition carry an `Origin` naming the UI and no cross-site `Sec-Fetch-Site`, so a form on another site cannot post to future state-changing routes. Tested in `src/web/server.rs`.

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

The credential itself is the exception. An upstream that reflects the request — httpbin-style `/headers` or `/anything`, a debug or echo endpoint, an error payload such as `{"error": "invalid token …"}` — would hand the agent the secret it never saw, and a prompt injection could steer the agent to such an endpoint whenever `allowed_paths` permits one. So before the body is returned, every key, string and number in it is searched for each form the credential was sent in — the raw value, `<prefix><value>` for header auth, `base64(username:value)` (padded or not, standard or URL-safe) for Basic auth, and any percent-encoding of these, `+` for a space included — and, since v0.5.4, for the forms an echo endpoint commonly re-encodes it in: base64 and base64url of the bare value (padded or not) and its hex. Matching ignores ASCII case, so an upper-cased token or upper-case hex is found too. Each occurrence is replaced with `[redacted by mcp-warden]` (invariants 1–2). Transport error text (reqwest's) is scrubbed the same way before it reaches the agent or the audit log. One stderr warning names the preset and the number of replacements, never the value. A body without the credential is returned unchanged. Non-JSON bodies are returned as `null` and response headers not at all, so neither can carry it.

Known limits: a credential that comes back truncated, split across fields, hashed, embedded in a larger encoded blob or otherwise transformed cannot be detected. Keep echo endpoints out of `allowed_paths`.

Up to v0.5.3 only `proxy_http` bodies were scrubbed, so a named query that reads the password back (Redis `CONFIG GET requirepass`) returned it to the agent. Since v0.5.4 `db_query` rows and error messages are scrubbed of the database password in the same forms, and an `[redacted by mcp-warden]` count is logged to stderr. `ssh_exec` output is not scrubbed and needs no scrub: public-key authentication sends the host a signature, never the private key, so the host cannot echo it. A test (`src/mcp/leak_tests.rs`) drives every tool against failing upstreams — connection refused, a TLS failure, a 401 that quotes the token, Redis and PostgreSQL servers that quote the password in their errors or return it as data — and checks the agent's view, stderr and every column of `audit.db` for the secret in raw, re-cased, base64, base64url, hex and percent-encoded form. The PostgreSQL and Redis drivers turned out not to pass the server's error text on (`db error`, `AuthenticationFailed`); the MySQL driver does, and its errors are now scrubbed too (not exercised by a fake MySQL server).

### N4. Insider threat (the user themselves)

`mcp-warden` is a defensive tool, not a compliance system. A user with `--approval auto` on every preset has effectively opted out. Team Mode (paid, future) adds the multi-approver workflows that make this enforceable for orgs.

## Residual risks (known, accepted in MVP)

### R1. Local approval prompts trust the local screen

On macOS approval is a native dialog shown with `osascript` (`src/approval/osascript.rs`). Deny is the default and the cancel button, so Return and Esc deny and approving takes a click; the dialog gives up after the request timeout (`timeout`). Request text reaches the fixed AppleScript as arguments, never as script source, and is sanitised as in T5. On Windows it is a Windows Forms window shown by the system Windows PowerShell (`src/approval/powershell.rs`) under the same rules; its script is a fixed `-EncodedCommand` and the request text reaches it only through environment variables. On Linux `notify-rust` shows a notification with Approve / Deny actions over DBus.

A local prompt is only as trustworthy as the screen it is on: an agent that can drive the desktop (computer-use tools) could click Approve. Users who give an agent screen control should approve through Telegram, which is out of band. Up to v0.5.3 that advice did not hold: a Telegram prompt that timed out was asked again in the local dialog (macOS, Windows) or the TUI, and `MCP_WARDEN_APPROVAL_TRANSPORT=desktop` — set in the MCP client's config, which an agent may edit — replaced Telegram entirely, so the agent could wait out the Telegram prompt or switch it off and click Approve itself. Since v0.5.4 a configured Telegram transport is the only one: a local fallback needs `desktop_fallback = true` in `[approval.telegram]`, and any other `MCP_WARDEN_APPROVAL_TRANSPORT` value stops the server from starting.

Up to v0.4.3 macOS had no working prompt under an MCP client: the notification had no buttons and the TUI fallback could not run, so every `prompt` call was refused (fail closed).

### R2. TUI approval works only in a terminal you can see

The full-screen ratatui dialog renders via `CrosstermBackend::new(std::io::stderr())` so it never touches stdout (the JSON-RPC channel). Under an MCP client stderr is captured and stdin is the JSON-RPC pipe, so the dialog cannot be seen (and on macOS cannot read keys). It is therefore a fallback only on Linux / Windows when stderr is a terminal, or chosen explicitly with `MCP_WARDEN_APPROVAL_TRANSPORT=tui`. Whenever a transport fails to show its prompt, the call is refused and audited as `failed` — never approved. The TUI restores the terminal state on exit (alt-screen + raw mode), but a process kill mid-dialog can leave the terminal in raw mode — the panic hook should reset.

### R3. Audit log integrity is policy, not crypto

The SQLite file is `0600`-permissioned and rejects symlinks at open time — since v0.5.4 also at `audit.db-journal`, `-wal` and `-shm`, which SQLite would otherwise follow and write journal pages into, and the database is opened with `SQLITE_OPEN_NOFOLLOW` — but root or anyone with the user's UID can still mutate it with `sqlite3`. Tamper-evident logs (hash-chained, optionally signed) ship in Phase 2+.

### R4. SSH command-injection via careless regex (v0.2.0)

`ssh_exec` runs the agent-supplied command via `russh`'s exec channel — a single string that sshd runs with the remote user's login shell (`$SHELL -c`). We anchor each `allowed_commands` entry as `^(?:...)$` — the group keeps alternations anchored, so `uptime|df -h` cannot match `rm -rf / ; df -h` (fixed in v0.4.1; earlier versions anchored as `^...$`). The same anchoring applies to HTTP `allowed_paths` patterns.

Anchoring alone left shell syntax to the pattern: `git checkout \S+` also matched `git checkout $(curl …|sh)`, which the remote shell expands. Since v0.5.2 every command is checked before its pattern (invariant 5): words are separated by single spaces and may contain only letters, digits and `- _ . / : = @ , + %`, and none may start with `=` (zsh's `=cmd`). `$`, backticks, `;`, `|`, `&`, `<`, `>`, parentheses, quotes, `\`, globs, `{}`, `~`, `!`, `#`, newlines and other control characters are refused whatever the pattern says, so the shell runs exactly the words the allow-list matched. Verified by `tests/corpus/commands.txt`, every line of which CI runs against a preset with `allowed_commands = [".*"]`.

Two uses of those characters still mean something to a shell, which a differential test found by running generated commands through sh, bash, zsh, dash, ksh, tcsh, csh and fish (`shells_split_permitted_words_as_written` in `src/executor/ssh.rs`, run with `--ignored`): a leading `NAME=value` word sets an environment variable for the command in every one of them (`LD_PRELOAD=/tmp/x.so git pull`, `GIT_SSH_COMMAND=…`, `PATH=…`), and fish expands a word `%self` to its PID. Since v0.5.4 a command that starts with `NAME=value` and any word that starts with `%` are refused too; otherwise every shell tested passed each generated word to the program exactly as written. This matters only where a pattern leaves the first word free (`\S+ status`), which already lets the agent pick the program.

What remains is the pattern's own scope. **A careless regex** like `git pull.*` still allows extra options made of permitted characters, such as `git pull --upload-pack=/tmp/x` — and so does a tight-looking class that may start with `-`: the cookbook itself recommended `^systemctl status [a-z0-9_-]+$` up to v0.5.3, which admits `systemctl status -Hother-host`. The cookbook now uses `[a-z0-9][a-z0-9_-]*`, a test checks that no pattern in the docs lets an argument start with `-`, and `mcp-warden doctor` warns about every `allowed_commands` pattern that does (a heuristic: it checks the class, `.`, `\S` or `\W` right after each space). Preset authors must terminate or constrain patterns explicitly — `^docker compose (pull|up -d|ps)$`, `[a-z0-9._-]+` for an argument. A second allow-list on the server — a dedicated account whose key is pinned to a gate script with `command=` / `ForceCommand` — holds even when a pattern is too broad or the key leaks: [`docs/ssh-hardening.md`](ssh-hardening.md).

### R5. SFTP local path leakage (v0.2.0)

`sftp_transfer` with `direction = "get"` writes to a local file. We restrict the local path to `$HOME`, `/tmp` and `/var/tmp`: `..` components are rejected, the parent directory is resolved through symlinks before the check, roots are compared by whole path components, and the target file itself may not be a symlink (hardened in v0.4.1). Because approval can take minutes, the local path is validated again right before the file is opened, and it is opened with `O_NOFOLLOW` (new files `0600`), so a symlink planted at the final component in the meantime is refused. A symlink swapped into a *parent* directory within the microseconds between that re-check and the open is not defended against (that would need `openat`-style traversal). Up to v0.5.3 that was all: anywhere in `$HOME` was fair game, so `put` could upload `~/.ssh/id_*`, `~/.aws/credentials` or mcp-warden's own config, and `get` could overwrite `~/.zshrc`, `~/.ssh/authorized_keys` or `~/.claude/settings.json` (whose hooks run commands) — which matters most when the agent's own file tools are confined to a project directory and mcp-warden would be the deputy that reaches further. The prompt also showed the path as given, so `/tmp/backup/id_ed25519` could stand for a symlinked `~/.ssh`. Since v0.5.4:

- Locations that hold credentials or run code later are refused, checked on the resolved path, by whole components and ignoring case on macOS and Windows: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`, cloud CLI and package-registry credentials, `~/.netrc`, `~/.git-credentials`, the macOS keychains, shell startup files, git config, login items (LaunchAgents, autostart, systemd user units), Claude Code, Claude Desktop and Cursor configuration, and mcp-warden's config dir. The list is in `src/executor/sftp.rs`; every entry is in `tests/corpus/local-paths.txt`.
- A file with more than one name (a hard link) is refused, since no path check can see that `/tmp/x` is `~/.ssh/id_ed25519`; `get` checks before it truncates.
- `allowed_local_paths` in the preset narrows the roots to the directories listed.
- The prompt and the audit summary show the resolved path, and the path as given when it differs.

A deny-list cannot be complete: a preset that transfers files should set `allowed_local_paths` to a dedicated working directory.

### R6. DB password lifetime in driver internals (v0.2.0)

`tokio-postgres::Config::password()`, `mysql_async::OptsBuilder::pass()`, and `redis::ConnectionInfo::password` each take an owned `String`. Our `Secret` is dropped immediately after the builder is constructed, but the password lives inside the driver until the connection authenticates. Audit beyond our control. Acceptable trade-off; future option: switch to drivers that take a closure for the password (none of the three currently support this).

### R7. DB named-query allow-list trust depends on the preset author

`db_query` rejects agent-supplied SQL — only the preset's declared queries are runnable. But a careless preset can declare destructive queries (`DELETE FROM users WHERE id = $1`) that the agent can drive with arbitrary `$1`. The allow-list moves the trust boundary from "no SQL" to "only this set of SQL"; preset authors must treat each named query as a public API. Checked by reading the drivers rather than with a hostile server: parameters are bound, never spliced into the text — PostgreSQL and MySQL use prepared statements, which hold one statement, and Redis sends each parameter as its own RESP argument; mysql_async 0.34 answers a server's `LOCAL INFILE` request with an error when no handler is set, and mcp-warden sets none, so a hostile MySQL server cannot read local files. Since v0.5.4 `mcp-warden doctor` warns about named Redis queries whose command can run code, rewrite the server's configuration or reach every key (`EVAL`, `SCRIPT`, `FUNCTION`, `CONFIG`, `MODULE`, `DEBUG`, `ACL`, `FLUSHALL`, `KEYS`, `MIGRATE`, `REPLICAOF`, …).

### R8. Audit log integrity is policy, not crypto

The SQLite file is `0600`-permissioned and rejects symlinks at open time, but root or anyone with the user's UID can still mutate it directly. Tamper-evident logs (hash-chained, optionally signed) are deferred to a later phase.

### R9. Time-boxed approvals are convenience, not deeper trust

When the user picks the approve-for-window choice in the approval prompt (dialog, notification, Telegram or TUI), the executor caches `(preset, action) → expires_at` in process memory and skips re-prompting for that pair until the window expires. Properties:

- **The button says what it allows.** Since v0.5.3 every transport words it the same way — `Approve for 10 min: every proxy_http call github-read allows runs without asking until 14:32` — so a click can't be mistaken for "approve this one call". Preset and tool names in it are sanitised like the rest of the prompt (T5).
- **One prompt at a time.** Since v0.5.4 a server shows one prompt at a time: calls that need one wait their turn, so a second dialog cannot pop up under the cursor of a human about to click the first (up to v0.5.3 parallel calls stacked one dialog per call). A call that waited behind an approve-for-window answer goes through as `windowed` without a prompt. Several MCP servers (one per client session) can still each show one.
- **A late Approve does not outrun a lock or an expiry.** A prompt stays open for up to its timeout. Up to v0.5.3 `mcp-warden lock`, or the end of a `preset grant` window, while it was open did not stop the call once the human clicked Approve on the dialog still in front of them. The lock and the expiry are now checked again after the answer; the event is recorded with the answer and the outcome `not run: …`.
- **It ends at the time shown.** The deadline is fixed when the prompt appears — `now + N`, rounded down to the minute for windows of 10 min or more and to the second otherwise — and the window is registered with exactly that deadline. A late click gets a slightly shorter window, never one that outlasts the button. A fallback prompt shown after the first one timed out gets its own deadline.

- **In-process only.** The cache is a `tokio::sync::Mutex<HashMap<…, Instant>>` inside `ActionExecutor`. Restarting `mcp-warden mcp` clears every window — by design. There is no file or socket through which a different process can inject or read windows.
- **Per `(preset, action)` keyed.** A window for `proxy_http` on `github-read` does **not** cover `ssh_exec` on the same preset. Each tool class requires its own approval.
- **Capped by the preset.** `approval_window_seconds = N` in the preset is the maximum window length; no prompt can exceed it. Presets that omit the field disable the window option entirely — prompts show only Approve once / Deny.
- **`get_secret_for_env` is never windowed.** Spec §6 mandates a fresh prompt every time a raw secret is revealed; the executor's `force_prompt = true` path bypasses the cache and never registers a window.
- **Audited.** Calls that proceed via an active window are recorded with `decision = "windowed"` in `audit.db`. Reviewing recent activity makes it visible that the user did not see a fresh prompt; the initial approve-for-window decision is still recorded as `approved`. Since v0.5.3 each windowed event also stores the id of that approval (`via_event`): `mcp-warden audit` prints `via approval #N`, and `mcp-warden audit --window N` shows the approval and every call it let through.

The residual risk: an agent that has the user's attention long enough to coerce *one* Approve-for-window can then issue many calls of the same kind without prompts inside the window. Mitigation: keep windows short (10 minutes is the default cap, 30 minutes is generous), and only enable windowing on presets where this trade-off is acceptable. Production-destructive presets should leave the field unset.

### R10. Database transport security

Since v0.4.1 `db_query` requires TLS with certificate and hostname verification for every non-loopback host — PostgreSQL (OS trust store + Mozilla roots), MySQL and Redis (Mozilla roots). Plaintext is used only for `localhost`, loopback IPs and Unix sockets, where traffic cannot leave the machine. There is no opt-out: a remote server without TLS, or with a certificate from a private CA the roots don't cover, is refused. Reach such servers through an SSH tunnel to `localhost` (e.g. `ssh -L 6379:localhost:6379 host`); for PostgreSQL a private CA can also be added to the OS trust store.

HTTP presets follow the same rule since v0.5.4. Up to v0.5.3 a `base_url` with `http://` to any host only logged a warning, and the credential crossed the network in clear text; now the server refuses to start unless such a host is `localhost`, 127.0.0.0/8 or `::1`. There is no opt-out: use https, or an SSH tunnel to localhost.

### R11. HTTP redirects are not followed

`doctor --deep` uses real credentials too, so since v0.5.4 each of its probes goes through the preset's approval policy and the audit log (`doctor_probe`), `--include-prompt` asks before probing a `prompt` preset, and the printed snippet is scrubbed like a `proxy_http` body. Up to v0.5.3 it probed `prompt` presets without asking and printed 80 characters of each response, redacted only by keyword.

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
- **Latching does not wait for a call.** Up to v0.5.3 a server saw the lock only when the agent next called it, so an agent that deleted the file right after `mcp-warden lock` — before its next call — was never locked out. Since v0.5.4 every server also checks the file once a second and latches on its own.
- **Deleting the file by hand** cannot reopen a server that saw the lock. A server *started after* the deletion does start unlocked, though. Restarting MCP servers is the client's job, not the agent's, but users who want the lock to survive tampering should also revoke the upstream credentials.
- **Screen control.** As in R1, an agent that can click on the user's screen could approve the unlock dialog. Use Telegram if the agent has screen control.
- **Telegram `/lock`** from the configured chat writes the same lock file, from whichever server is polling at that moment. It works only while at least one MCP server with `[approval.telegram]` runs. Telegram cannot unlock.
- **State files are read defensively.** The server reads `lock`, `telegram/offset` and the inbox files it polls for, and opens `telegram/poll.lock`. Up to v0.5.3 each of these followed a symlink and read to the end, so an agent that replaced one with a link to `/dev/zero` (or a FIFO) made the server read forever or block. Since v0.5.4 they are opened with `O_NOFOLLOW | O_NONBLOCK` and read only if they are small regular files; a lock file that cannot be read still locks. The config dir is created `0700` (`config.toml` `0600`), and `mcp-warden mcp` and `run` refuse to start when it is writable by other users or not owned by the user.
- **Telegram chat members.** A button press counts if it comes from the configured chat. In a group chat that is anyone in the group; use a private chat with the bot.
- **The Telegram inbox.** Servers hand button presses to each other through `telegram/inbox/<button token>` files. Each button carries its own random 128-bit token, and only the asking server knows which token means Approve. Someone who can write the inbox can delete an answer, which makes the prompt time out (fail closed). They cannot forge an answer or flip one.

### R14. `preset grant` windows and frozen presets

- **Expiry is enforced on every call.** It is checked against the wall clock, so a running server stops serving a preset on time.
- **New grants and revokes need a restart.** Presets are frozen at startup (T7), so `preset grant` and `preset revoke` take effect when the server restarts. For an immediate stop, use `mcp-warden lock`.
- **`get_secret_for_env` is outside the window.** It is not tied to a preset, and it always asks for approval.

### R16. `get_secret_for_env` hands the agent a raw secret

It is the escape hatch for tools that read a secret from their environment, so it always asks for approval and is never covered by an approval window. Up to v0.5.3 it showed a prompt for any name of any length — including the keychain entry of the Telegram bot token, so one careless click handed the agent the out-of-band approval channel itself (with the token it can read and edit the bot's messages). Since v0.5.4 it reveals only a name that a frozen preset or `[[server]]` entry uses, never the Telegram bot token, and refuses anything else — or a name over 256 bytes — before any prompt, audited as `refused`.

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
