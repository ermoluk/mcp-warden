# Changelog

All notable changes to this project will be documented in this file. The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Named commands for SSH presets** (`[[preset.commands]]`, the new `ssh_run` tool). The preset fixes each command line; the agent names a command and supplies typed values: `int` (a range), `enum` (a list), `string` (one word matching a pattern) or `path` (an absolute path matching a pattern, no `//`, `.` or `..`). Values are checked before any credential is read, may not start with `-`, contain a space or shell syntax, and the filled-in command passes the shell-syntax check again (invariants 3 and 5). Templates are checked at startup: one bad command stops the server, naming the preset and the command (invariant 10). Each command may set its own `approval` (`mcp-warden approval PRESET POLICY --command NAME`); a command's `auto` counts only once the preset is confirmed (`preset confirm`), and the approval window is per command. `list_presets` shows each command and what its parameters accept; `expose_as_tools = true` also offers each command as its own tool, `ssh_<preset>_<command>` (at most 32). `mcp-warden preset test NAME --run CMD --param k=v` shows the verdict and the exact command it would send. `preset scaffold ssh-deploy --host H --user U` writes a preset with named commands only. See the cookbook and threat model R4.
- **`max_output_bytes` for SSH presets**: lowers how much stdout and stderr `ssh_exec` and `ssh_run` read (default and ceiling 1 MiB per stream); a named command can lower it further.
- **`doctor` warns** about catch-alls (`.*`, `.+`, `\S+`, `[^ ]+`) anywhere in `allowed_commands`, such as `git pull.*`, and about named commands that run `rm`, `shred`, `dd`, `mkfs*` or a recursive `chmod` / `chown`.

### Security

- **Seven of the eight accepted dependency advisories are gone.** russh 0.65 (RUSTSEC-2026-0387, `crypto-bigint`), notify-rust 4.18 (RUSTSEC-2026-0194 and -0195, `quick-xml`, Windows only) and mysql_async 0.37 (RUSTSEC-2026-0391, -0398, -0403 and -0410, `zstd`). The one left is `rsa` (RUSTSEC-2023-0071, the Marvin attack): no `rsa` release fixes it, and mcp-warden only signs with RSA keys, never decrypts. A host certificate offered by an SSH server is checked by the key it certifies, which `known_hosts` must pin like any other host key; `@cert-authority` lines are still not supported.

### Fixed

- **SSH logins with an RSA key failed against current OpenSSH.** `ssh_exec` and `sftp_transfer` signed with `ssh-rsa` (SHA-1), which OpenSSH 8.8 and later refuse by default. An RSA key now signs with `rsa-sha2-512` or `rsa-sha2-256`, whichever the server announces (`rsa-sha2-256` if it announces none). Ed25519 and ECDSA keys were not affected.

## [0.5.4]

### Security

- **An edited config was trusted on the next start (High).** MCP clients start a new server for every session, and the server accepted whatever `config.toml` said — or the config in any directory `MCP_WARDEN_CONFIG_DIR` pointed to, which a project's `.mcp.json` can set. An agent that could write files could flip a preset to `approval = "auto"`, widen its allow-lists or point its `base_url` at another host, bound to an existing keychain secret, and use it without a prompt; `--confirm-auto` is only a CLI flag, which an agent with a shell can pass too. Likewise, editing a `[[server]]` entry's `command` made `mcp-warden run` hand that server's keys to a command of the agent's choosing. Now an `auto` preset is honoured only in the exact form a human confirmed through the approval prompt — a SHA-256 stamp in the keychain (`stamp/preset/<name>`) written by `preset add --confirm-auto`, `approval … auto --confirm-auto`, `preset grant` and the new `mcp-warden preset confirm` after an approval prompt; any other `auto` preset is served as `prompt`, with a warning on stderr and in `doctor`. `mcp-warden run` asks before the first launch of a wrapped server and after any edit to its entry (`stamp/server/<name>`). See the threat model, T7. **Behaviour change:** after upgrading, `auto` presets ask until `mcp-warden preset confirm` is run once, and each wrapped server asks on its first launch; `secret list` hides the stamps. Stamps are HMAC-SHA256 under a random key kept only in the keychain, and `secret add` / `secret remove` refuse `stamp/` names (as does config validation for preset secrets), so a stamp cannot be forged by hashing the config and storing the hash through the CLI.
- **`allowed_methods` bypass through method-override parameters (High).** The query string and body were not checked at all, so on Laravel or Symfony (method parameter override, Laravel's default) a preset that allows `POST` also allowed `POST /x?_method=DELETE` — run as DELETE — and Laravel reads `_method` from a JSON body too. Query parameters and top-level body keys `_method`, `X-HTTP-Method-Override`, `X-HTTP-Method` and `X-Method-Override` are now refused before the credential is read, compared case-insensitively and after PHP's renaming of `.`, ` ` and `[` to `_`, and so are query parameter names with control characters (invariant 3, T6). New hostile-input corpus `tests/corpus/queries.txt`, run in CI. **Behaviour change:** such parameters are refused.
- **The approval prompt did not say where a request goes.** `proxy_http` prompts and audit summaries read `GET /user/repos`, so a preset whose `base_url` had been changed — by an agent editing `config.toml`, or pointing `MCP_WARDEN_CONFIG_DIR` at a config of its own — looked the same in the prompt. Prompts and summaries now name the destination: `GET https://api.github.com/user/repos`, `db postgres db.internal → user_by_id (1 param)` (threat model, T7). **Behaviour change** in prompt and audit text.
- **An agent with screen control could approve its own calls despite Telegram.** With `[approval.telegram]` configured, a Telegram prompt that timed out was asked again in the local dialog (macOS, Windows) or TUI, and `MCP_WARDEN_APPROVAL_TRANSPORT=desktop` in the MCP client's config replaced Telegram altogether. Telegram is what the threat model recommends exactly when the agent can drive the screen (R1). A configured Telegram transport is now the only one: a local fallback needs `desktop_fallback = true` in `[approval.telegram]`, and any other `MCP_WARDEN_APPROVAL_TRANSPORT` value refuses to start. **Behaviour change:** no local prompt after a Telegram timeout unless opted in; `MCP_WARDEN_APPROVAL_TRANSPORT=desktop|tui` with Telegram configured stops the server from starting.
- **`get_secret_for_env` could reveal any keychain entry, including the Telegram bot token.** It showed an approval prompt for any name, of any length (no input limit applied), so one click could hand the agent the token of the out-of-band approval channel. It now reveals only a secret that a preset or a `[[server]]` entry uses, never `[approval.telegram] bot_token_secret`, and refuses other names and names over 256 bytes before any prompt, audited as `refused` (invariant 3, R16). The tool description says so. **Behaviour change.**
- **DNS rebinding against `mcp-warden web`.** The web UI binds 127.0.0.1 but did not check the `Host` header, so a web page that re-pointed its own domain at 127.0.0.1 could read `/presets`, `/presets/:name` and `/audit` — hosts, paths, secret names and the audit log — as same-origin. Requests whose `Host` is not `127.0.0.1:<port>`, `localhost:<port>` or `[::1]:<port>` now get `421 Misdirected Request`; requests other than GET / HEAD also need an `Origin` naming the UI and no cross-site `Sec-Fetch-Site` (403 otherwise). See the threat model, T9. **Behaviour change:** the UI must be opened as `127.0.0.1`, `localhost` or `[::1]` with its port, not through another name.
- **Invisible and reordering characters in approval prompts and audit views.** `sanitise_for_prompt` removed only control characters (Cc), so bidi overrides, embeddings and isolates, zero-width characters, U+2028 / U+2029 and long combining-mark runs reached the macOS and Windows dialogs, the Linux notification, Telegram, the TUI, `mcp-warden audit` and the web UI. Agent-controlled text gets there: `sftp_transfer` paths, the `get_secret_for_env` name, and the preset name, summary and error of refused calls. A path like `/srv/app/\u{202E}gol.cod` was displayed reversed. Format characters (Cf), U+2028 / U+2029 and the Hangul fillers are now shown as a visible `\u{XXXX}` escape, and a character keeps at most two combining marks (threat model, T5). **Behaviour change:** such characters appear escaped in prompts and in both audit views.
- **`sftp_transfer` could read and write credentials and startup files under `$HOME`.** Any path under `$HOME`, `/tmp` or `/var/tmp` was allowed, so `put` could upload `~/.ssh/id_*`, `~/.aws/credentials` or mcp-warden's config, and `get` could overwrite `~/.zshrc`, `~/.ssh/authorized_keys` or an agent's settings with hooks; a hard link (`/tmp/x` → `~/.ssh/id_ed25519`) slipped past any path check; and the prompt showed the path as given rather than where its symlinked parent led. Now locations that hold credentials or run code (SSH, cloud, registry and git credentials, keychains, shell startup files, git config, login items, Claude Code / Claude Desktop / Cursor config, mcp-warden's config dir) are refused on the resolved path, files with more than one name are refused (`get` checks before truncating), the new preset option `allowed_local_paths` limits the local side to listed directories, and the prompt and audit show the resolved path (threat model, R5). New corpus `tests/corpus/local-paths.txt`. **Behaviour change:** transfers to or from those locations, or of hard-linked files, are refused.
- **Upstream responses without bounds.** A hostile or broken upstream could exhaust memory or hold a call open: without `max_response_bytes` a `proxy_http` body was read in full — and decompressed, so a small gzip response became gigabytes; `ssh_exec` buffered output without end; a host that accepted the key and then stalled hung `ssh_exec` (the timeout covered only the command's output) and `sftp_transfer` (no timeout at all); `db_query` had no timeout and no size limit. Now: `proxy_http` reads at most 10 MiB of decoded body whatever the preset says (`max_response_bytes` can only lower it); `ssh_exec` keeps 1 MiB of stdout and of stderr and then closes the channel, with a `notice`; `timeout_seconds` bounds the whole call — default 120 s for `ssh_exec`, 600 s for `sftp_transfer`, 30 s for `db_query`; `db_query` results over 10 MiB are not returned (threat model, T10). **Behaviour change:** larger bodies, outputs and results are withheld or cut; `ssh_exec` and `db_query` responses gain an optional `notice`.
- **The credential scrub missed common re-encodings.** An upstream that reflected the token as base64 or base64url of the bare value, as hex, or in another letter case (`GHP_…`) handed it to the agent: only the forms it was sent in were searched. Those forms are now found too, matching ignores ASCII case, and `proxy_http` transport errors are scrubbed as well (invariants 1–2, N3). A token split across fields, hashed or inside a larger base64 blob at another alignment is still not detected.
- **`db_query` returned the database password when the query read it back.** Rows were not scrubbed, so a named query such as Redis `CONFIG GET requirepass` handed the agent the password. Rows and error messages of `db_query` are now scrubbed of the password like a `proxy_http` body (invariants 1–2, N3). A new test drives every tool against failing upstreams — refused connection, TLS failure, a 401 quoting the token, databases quoting or returning the password — and checks the agent's view, stderr and `audit.db` for every form of the secret.
- **`mcp-warden doctor --deep` used credentials without approval and printed what came back.** With `--include-prompt` it probed `prompt` presets with the real credential without asking anyone, none of its probes reached the audit log, and the 80-character body snippet was redacted only if it contained a word like `token` — so an upstream that reflected the credential had it printed, to an agent too if it ran `doctor --format json`. Every probe now goes through the preset's approval policy and the audit log (action `doctor_probe`), `--include-prompt` asks before each `prompt` preset, the lock is honoured, the snippet is scrubbed of every form of the credential before it is cut, and at most 64 KiB of body is read (invariants 1, 3, T4). **Behaviour change:** `--include-prompt` now shows an approval prompt per `prompt` preset.
- **Plain-http presets sent the credential unencrypted.** A `base_url` with `http://` to a host other than loopback only logged a warning. The MCP server (and `doctor`'s validation) now refuses such a preset, as it already did for databases without TLS (R10); `localhost`, 127.0.0.0/8 and `::1` still work, so an SSH tunnel to localhost is the way to reach an http-only service. **Behaviour change:** configs with a non-loopback `http://` `base_url` stop the server from starting.
- **A lock or an ended `preset grant` window did not stop a call whose prompt was already open, and parallel calls stacked dialogs.** The lock and the preset's expiry were checked before the prompt only, so an Approve clicked minutes later on the dialog still on screen ran the call anyway. Both are now checked again after the answer (`not run: …` in the audit log). A server also shows one prompt at a time now, so a second dialog cannot appear under the cursor of a human about to click the first, and calls queued behind an approve-for-window answer go through as `windowed` (R9). **Behaviour change:** prompts from one server are shown one after another.
- **Vulnerable dependencies updated.** `cargo audit` reported 27 advisories in `Cargo.lock`. Updated within semver: russh 0.60.3 (unbounded allocation from a hostile SSH server), rustls 0.23.46 and rustls-webpki 0.103.16 (handshake and certificate-verification fixes), webpki-roots 1.0.11 (distrusted roots), postgres-protocol 0.6.12 (SCRAM iteration DoS from a hostile server), h2, quinn-proto, crossbeam-epoch, ctutils, tokio, anyhow, event-listener. Eight remain, each needing a semver-breaking upgrade or without a fix; they are listed with reasons in `deny.toml` (threat model, R17).
- **The kill switch latched only on the next call.** An agent that deleted `<config dir>/lock` right after `mcp-warden lock`, before its next call, escaped it. Servers now also check the file once a second and latch on their own (R13).
- **One malformed line on stdin stopped the MCP server, and lines had no length limit.** rmcp's stdio codec ends the session at the first line it cannot decode and buffers a line of any length. The server now uses its own framing: a line over 16 MiB or one that is not a JSON-RPC message is skipped with a warning on stderr, and the session continues (T8).
- **Planted files in the config dir could hang the server or redirect audit writes.** `lock`, `telegram/offset` and the Telegram inbox were read through symlinks to the end (a link to `/dev/zero` never finished), `telegram/poll.lock` was opened through a symlink or a FIFO (which blocks), and SQLite followed a symlink at `audit.db-journal`. State files are now opened with `O_NOFOLLOW | O_NONBLOCK` and read only as small regular files, the audit log refuses symlinks at the database and its `-journal`, `-wal` and `-shm` files and opens the database with `SQLITE_OPEN_NOFOLLOW`, the config dir is created `0700` and `config.toml` `0600`, and the MCP server and `run` refuse a config dir that other users can write to or that the user does not own (R3, R13). **Behaviour change:** a group- or world-writable config dir stops the server from starting.
- **`ssh_exec`: environment assignments and fish `%self`.** A differential test ran generated allow-listed commands through sh, bash, zsh, dash, ksh, tcsh, csh and fish. Every shell passed the permitted words through unchanged, with two exceptions: a leading `NAME=value` word is an environment assignment for the command in all of them (`LD_PRELOAD=/tmp/x.so git pull`), and fish expands `%self` to its PID. Commands starting with `NAME=value` and words starting with `%` are now refused whatever the pattern (invariant 5, R4); new entries in `tests/corpus/commands.txt`. Exploitable only through a pattern that leaves the first word free. **Behaviour change.**
- **Option injection through a recommended `ssh_exec` pattern.** The presets cookbook suggested `^systemctl status [a-z0-9_-]+$`, whose argument may start with `-`, so `systemctl status -Hother-host` matched. The cookbook now uses `[a-z0-9][a-z0-9_-]*` and explains why; a test checks every `allowed_commands` pattern in the docs, and `mcp-warden doctor` warns about any pattern that lets an argument start with `-` (`[a-z0-9_-]+`, `\S+`, `.*`, `[^ ]+` after a space) (R4).
- **Two presets could share a name.** Calls used the first, while `list_presets`, the web UI and approval windows (keyed by name) saw both, so a second `gh` with `approval = "auto"` and other methods sat behind the first. Duplicate preset names now stop the server from starting (invariant 10). **Behaviour change.**
- **Supply-chain checks.** CI gains a job that runs `cargo deny check` (advisories, licenses, sources) and `cargo audit`; every GitHub Action is pinned to a commit SHA, `ci.yml` gets `permissions: contents: read`, and checkouts keep no token. `install.sh` and `install.ps1` verify the archive's build-provenance attestation with `gh attestation verify` when `MCP_WARDEN_VERIFY_ATTESTATION=1` is set (R17).

### Added

- **Fuzzing and an end-to-end property test.** `fuzz/` (cargo-fuzz, nightly only; the build stays on stable) has targets for `policy::check_request`, the `ssh_exec` word check, `config.toml` parsing and validation, the credential scrub (with the oracle that no form of the secret survives), `response_fields` selection, known_hosts parsing, Telegram updates and `sanitise_for_prompt`. A property test drives generated paths and query maps through `proxy_http` to a wiremock upstream and checks that what arrives is what the allow-list checked. To reach the internals, `mcp-warden` now also builds as a library (`src/lib.rs`, not a stable API).
- **`mcp-warden doctor` warns about risky named Redis queries** — `EVAL`, `SCRIPT`, `FUNCTION`, `CONFIG`, `MODULE`, `DEBUG`, `ACL`, `FLUSHALL`, `KEYS`, `MIGRATE`, `REPLICAOF` and others whose arguments the agent chooses (R7) — and about `allowed_commands` patterns that admit options.
- **`mcp-warden preset confirm [NAME]…`** confirms `auto` presets through the approval prompt (all unconfirmed ones without names). `mcp-warden-core` gains the `stamp` module.
- A test that the tool descriptions pinned by snapshots are the ones the server serves; it found the pinned `sftp_transfer` text had drifted (`'get'` vs `"get"`).

## [0.5.3]

### Security

- **HTTP path allow-list bypass via non-standard `%uXXXX` escapes.** `percent_decode_str` decodes only `%` followed by two hex digits and leaves anything else as text, so `/users/%u005cadmin` reached the allow-list as an ordinary segment, which `/users/.*` matched — but IIS and ASP.NET decode `%u005c` to `\` (a separator to them) and `%u002e` to `.`. Every `%` in a path must now start an escape of exactly two hex digits; `%u…`, `%zz` and a trailing `%` are refused before the credential is read (invariants 3 and 6). Reported by atp_studio_coll on r/mcp. **Behaviour change:** a path with any other `%` is refused.
- **HTTP path allow-list bypass via Unicode compatibility forms.** `/users/a%EF%BC%8Fadmin` decodes to `/users/a／admin` — FULLWIDTH SOLIDUS, an ordinary character to the allow-list — but an upstream that applies NFKC normalisation after decoding sees `/`; `．．` (U+FF0E) likewise becomes `..` and `＼` (U+FF3C) `\`. A path is now refused if NFKC would change its decoded form (invariants 3 and 6). The raw characters were already refused before the request was sent, because the URL would have been re-encoded; the check now catches both forms in the allow-list itself. Cyrillic, CJK and other text that NFKC leaves as it is still passes. Reported by atp_studio_coll on r/mcp. **Behaviour change:** fullwidth forms, ligatures (`ﬁ`), superscripts, the Kelvin sign and other compatibility characters are refused in paths, as are decomposed accents (`й` written as `и` + U+0306) — send the composed form.
- **Hard limits on agent input.** Nothing capped how much an agent could send, so an oversized path, command or parameter reached the allow-list regexes, the approval prompt, the audit log and the upstream in full. Every call is now checked against fixed limits before anything else — before the preset's patterns, percent-decoding or any credential (invariant 3): `proxy_http` path 2048 bytes, query 64 parameters and 4096 bytes of keys and values, JSON body 1 MiB; `ssh_exec` command 1024 bytes; `sftp_transfer` remote and local paths 1024 bytes each; `db_query` 32 parameters of at most 16 KiB each. The error names the field and the limit, never the input. Refused calls are audited as `refused`, and `preset test` applies the same limits. The constants live in `src/executor/limits.rs`; see the threat model, T8. **Behaviour change:** calls over a limit are refused.

### Added

- **Hostile-input corpus in CI.** `tests/corpus/paths.txt` and `tests/corpus/commands.txt` list every path and command an allow-list bypass has used — the encodings from 0.4.1, 0.4.3 and 0.5.2, this release's `%uXXXX` and compatibility forms, shell syntax and over-limit inputs — one per line with what it tests and the release that first refused it. A test runs each one through the policy check the server and `preset test` share, with presets that allow every path and every command, and fails if any is allowed. New bypasses go there.
- **`mcp-warden audit --decision <approved|denied|auto|timeout|windowed|refused|failed>`**, repeatable, shows only events with those decisions — `--decision refused --decision failed` for what was turned away. `mcp-warden web` has the same filter as checkboxes on the audit page (`/audit?decision=refused&decision=failed`). Both filter in SQL. `mcp-warden-core` gains `AuditFilter`, `AuditSink::query` (read-only; its default implementation returns an error rather than filtering in memory) and `AuditDecision::{ALL, as_str, from_name}`.
- **Windowed calls name the approval that opened their window.** A `windowed` event said only that no prompt was shown. It now stores the id of the `approved` event whose approve-for-window choice let it through: `mcp-warden audit` prints `via approval #N` (the web UI `windowed via #N`), and `mcp-warden audit --window N` prints that approval and every call it let through, oldest first. Existing `audit.db` files gain a `via_event` column in place; old rows are kept. `mcp-warden-core` gains `AuditEvent::via_event`, `AuditFilter::window` and `AuditSink::record_windowed`, which only fills in the row the call created, like `record_decision`; its default implementation records the decision without the link.
- **Install without Rust.** Releases carry binaries for macOS (arm64, x86_64), Linux (x86_64 and aarch64, static musl builds, plus the x86_64 glibc build as before) and Windows (x86_64), a combined `SHA256SUMS`, and a GitHub build-provenance attestation for every archive (`gh attestation verify <archive> --repo ermoluk/mcp-warden`). Built on them:
  - Homebrew: `brew install ermoluk/tap/mcp-warden`;
  - Scoop (`ermoluk/scoop-bucket`) and winget (`ermoluk.mcp-warden`);
  - AUR: `mcp-warden-bin`;
  - Nix: `nix run github:ermoluk/mcp-warden`, built from source;
  - npm: `npx -y @mcp-warden/cli mcp`, with the binary in per-platform optional dependencies, no install script and no download at run time;
  - `cargo binstall mcp-warden`;
  - a Claude Desktop bundle (`.mcpb`) per platform;
  - `install.sh` / `install.ps1`, which check the release checksum and install into a user directory without sudo.

  None of them updates itself (invariant 9). `server.json` lists the npm and MCPB packages next to cargo. There is no Docker image: the OS keychain isn't reachable from a container. The release workflow builds and checks all of it, and `workflow_dispatch` runs it as a dry run; the manual publishing steps are in `docs/releasing.md`.
- **`docs/ssh-hardening.md`** — how to give `ssh_exec` a second allow-list on the server: a dedicated account with minimal rights and no interactive login, its key pinned with `restrict,command=` in `authorized_keys` or `ForceCommand` in `sshd_config`, a gate script that matches `$SSH_ORIGINAL_COMMAND` against fixed strings and never evaluates it, and a separate chrooted account for SFTP. It explains why the remote login shell is involved at all. Linked from the README and the presets cookbook.

### Changed

- **The approval-window button says what it allows.** It read `Approve for 10 min` (Telegram: `⏱ Approve for window`), which can pass for approving one call. Every transport — the macOS and Windows dialogs, the Linux notification, Telegram and the TUI — now uses one wording from one function: `Approve for 10 min: every proxy_http call github-read allows runs without asking until 14:32`, with preset and tool names sanitised like the rest of the prompt. Telegram puts that button on a row of its own and repeats the text in the message, since it cuts long buttons short. **Behaviour change:** the time on the button is fixed when the prompt appears (to the minute for windows of 10 min or more, to the second for shorter ones), and the window now ends exactly then instead of N minutes after the click — a late click gets a slightly shorter window, never one that outlasts the button.
- **The Claude Code plugin finds binaries installed without cargo.** It looked on `PATH` and in `~/.cargo/bin` only, but Claude Desktop and other GUI apps on macOS don't get Homebrew's or `~/.local/bin` on their `PATH`. The MCP server entry, the `SessionStart` check and `/mcp-warden:setup` now also look in `~/.local/bin`, `/opt/homebrew/bin`, `/usr/local/bin` and `~/.nix-profile/bin`, and point at the new install options.
- **`mcp-warden-core` API.** `ApprovalRequest` gains `window_until`, `AuditEvent` gains `via_event`, and `AuditSink` gains `query` (with the new `AuditFilter`) and `record_windowed`. The new trait methods have default implementations, but code that builds `ApprovalRequest` or `AuditEvent` with a struct literal needs the new fields. **Behaviour change** for alternate implementations of the core traits.
- `policy::Request` (the shared check behind the tools and `preset test`) now carries the `proxy_http` query and body and the `db_query` parameter values, so the input limits are checked in one place.
- The README keeps only "What's new in v0.5.3"; release notes for earlier versions are in this changelog.

### Fixed

- **`mcp-warden secret remove` failed on Linux for the last secret.** Removing it wrote an empty list of names to the index entry, which the Linux kernel keyring (keyutils) can't store, so the command failed with `Value of 'secret' is invalid: cannot be empty`. The secret itself was deleted, but its name stayed listed. An empty index now deletes the index entry. Broken since 0.5.1; found by the new keyring check in the release workflow.

Thanks to claudio-rootedlogic on r/mcp for the ideas behind the approval-window wording and the audit decision filter.

## [0.5.2]

### Security

- **HTTP path allow-list bypass via double percent-encoding.** `allowed_paths` are matched against the path decoded once, so `/users/%252e%252e/admin` became `/users/%2e%2e/admin` — an ordinary segment to the allow-list, which `/users/.*` or `[^/]+` matched — and was sent as `%252e%252e`. An upstream that decodes twice (a proxy in front of an app that decodes again) sees `..` and routes outside the allow-list; `%252F` likewise becomes a separator the allow-list never saw. Any path containing `%25` is now refused before the credential is read: a second decode pass can only find an escape whose `%` came out of the first, and that `%` is always a `%25` (invariants 3 and 6). **Behaviour change:** a literal `%` in a request path is refused with it. Reported by atp_studio_coll on r/mcp.
- **`ssh_exec` passed shell syntax that a broad pattern allowed.** sshd runs the command with the remote user's login shell, and `allowed_commands` regexes were the only check, so `git checkout \S+` also matched `git checkout $(curl …|sh)`, which that shell expands. Every command is now checked before its pattern with a per-word character allow-list (invariant 5): words are separated by single spaces and may contain only letters, digits and `- _ . / : = @ , + %`, and none may start with `=`. `$`, backticks, `;`, `|`, `&`, `<`, `>`, parentheses, quotes, `\`, globs, `{}`, `~`, `!`, `#`, newlines and other control characters are refused whatever the pattern says. The `ssh_exec` description tells the agent the rule, and `preset test --command` applies it too. **Behaviour change:** patterns that relied on quotes, globs or other shell syntax no longer match anything. Reported by atp_studio_coll on r/mcp.

## [0.5.1]

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

- **Workspace split.** New `mcp-warden-core` library crate ships the open-core trait surfaces (`KeychainStore`, `ApprovalTransport`, `AuditSink`, `PresetSource`) and shared types (`WardenError`, `Secret`, `Config`). The binary keeps the CLI, MCP server, executor, web UI and concrete approval transports, and now depends on core; alternate implementations can attach to core without pulling the binary's full dep stack.
- **Telegram approval transport wired into the runtime.** The transport shipped in 0.3.0; this release makes it selectable. Add `[approval.telegram]` to `config.toml` (or set `MCP_WARDEN_APPROVAL_TRANSPORT=telegram`) and `mcp-warden mcp` selects Telegram as the active transport with TUI as fallback: `prompt`-policy presets send Approve / Deny inline-button messages to that chat. `MCP_WARDEN_APPROVAL_TRANSPORT` also accepts `desktop` and `tui`. Validates the bot-token keychain entry at startup. Setup:
  ```toml
  [approval.telegram]
  bot_token_secret = "tg_bot_token"   # name of the keychain entry, not the token value
  chat_id = 123456789                  # your numeric Telegram chat id
  timeout_seconds = 120                # optional
  ```
  then `mcp-warden secret add tg_bot_token` stores the bot token in the keychain.

### Changed

- Versions bumped from 0.3.0 to 0.4.0 across both crates.
- `Config` gains an optional `approval: Option<ApprovalConfig>` field; existing configs without it parse unchanged.

### Known caveats / roadmap

- `russh` is still a dependency of `mcp-warden-core` (only because russh's `Handler::Error` requires `From<russh::Error>`). A binary-local newtype to drop this dep is on the roadmap.
- `docs/approval-transports.md` and `mcp-warden approval telegram-test` CLI helper are not in this release.

## [0.3.0]

### Added

- **`preset scaffold <template>`** — 8 built-in templates for common APIs (`github-read`, `github-write`, `notion-read`, `stripe-read`, `openai-chat`, `anthropic-messages`, `gitea-read`, `cloudflare-dns`). `--list` discovers, `--dry-run` previews, `--force` overwrites.
- **`preset from-openapi <source>`** — bootstrap a preset from an OpenAPI 3.0/3.1 JSON/YAML spec (URL or file). Derives `base_url`, `allowed_paths`, `allowed_methods`, and the auth scheme (Bearer or API-key header). `--method-filter` and `--tag-filter` narrow the surface. 50 MB spec size cap; file paths must resolve under `$HOME` or `/tmp/`.
- **`doctor --deep`** — for each HTTP preset, runs a safe read-only probe (GET against the base URL or the first literal allowed path) and reports per-preset status — `ok`, `auth_failed`, `auth_ok_404`, `network_error`, `tls_error` or `skipped` — with elapsed time and a body snippet. Redacts body snippets matching common credential patterns (Bearer, token, password, api_key, …). Skips `prompt`-policy presets unless `--include-prompt`. `--format json` for machine output.
- **`web [--port N]`** — local-only read-only web UI (binds `127.0.0.1` hardcoded) for browsing presets and the audit log without a TUI. Routes: dashboard, presets table, preset detail, audit log. CSP / X-Frame-Options / X-Content-Type-Options set on every response. All dynamic values HTML-escaped. Default port 7077. Approval over WebSocket is on the roadmap; design notes in `docs/web-ui.md`.
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
