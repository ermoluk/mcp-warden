# mcp-warden security audit — November 2026

Scope: `main` at v0.5.3 (83bc998). The fixes were made on branch `security/audit-2026-11` and shipped in **0.5.4** (ermoluk/mcp-warden#2, merge commit ca49491).
This report was kept out of git until that release; `file:line` references point at the branch head before the merge.

## Method

1. **Inventory.** Every input an attacker can influence, the checks applied to it (`file:line` on the branch head) and where it ends up (below).
2. **Attacker model** (from the brief):
   - the agent is fully prompt-injected — any tool, any arguments, any order, in parallel — and can read and write the user's files and run the CLI;
   - upstreams may be hostile or reflect the request;
   - a web page in the user's browser may be hostile.

   Direct keychain access by the agent (N2) is out of scope.
3. **Exploit tests.** Every hypothesis got a test that drives the real code path: unit tests, the MCP tool methods, `assert_cmd` CLI tests, raw stdio for the MCP server. Fakes and mocks used:
   - fake upstreams: wiremock, an in-process russh SSH server, fake Redis and PostgreSQL servers, silent and counting TCP listeners;
   - a counting in-memory keychain and a counting approval transport.

   For a confirmed finding the test was run before the fix and failed. The failure is recorded below.
4. **Differential testing.** Generated `ssh_exec` commands were run through sh, bash, zsh, dash, ksh, tcsh, csh and fish (installed with Homebrew).
5. **Fuzzing.** 8 cargo-fuzz targets were run for 10 minutes each (results below). One property test checks what an allowed request looks like at the upstream.
6. **Dependencies.** `cargo audit` and `cargo deny` were run locally and added to CI.

Not done, and why:
- Windows (PowerShell dialog) and a live Telegram bot were not exercised. Both are the owner's own checks per the brief.
- MySQL-specific claims (LOCAL INFILE, error text) rest on reading the mysql_async source, not on a fake MySQL server.
- shellcheck was not available locally. The `install.sh` changes were checked with `sh -n` and a local `file://` fake release.

## Input inventory

| Input | Checks (branch head) | Reaches |
|---|---|---|
| `proxy_http.preset_name` | `find_preset` `src/mcp/server.rs:417`: lock, lookup, expiry | audit (refused, clipped 1024), prompt (via preset name from config) |
| `proxy_http.method` | `limits::check` `src/executor/limits.rs:49`; `validate_request` `src/executor/http.rs:36` (allow-list, ASCII-case) | prompt / audit summary, upstream |
| `proxy_http.path` | limits; `validate_request` + `decode_path` + `build_url` `src/executor/http.rs:36-237` (escapes, `%25`, NFKC, dot/empty segments, rewrite check, allow-list on decoded path) | prompt / audit summary (raw, now with `base_url`), upstream |
| `proxy_http.query` | limits (64 pairs, 4 KiB); **new** `check_query_and_body_keys` `src/executor/http.rs:121` (override keys, control chars); url-encoded by `append_pair` | upstream only (never summary/audit) |
| `proxy_http.body` | limits (1 MiB serialised); **new** top-level override keys; re-serialised as JSON | upstream only |
| `ssh_exec.command` | limits (1 KiB); `check_words` `src/executor/ssh.rs:59` (alphabet, single spaces, no leading `=`, **new** no leading `%`/`NAME=value`); anchored regex | prompt / audit, remote login shell |
| `sftp_transfer.direction/remote/local` | direction enum; limits; `validate_remote_path` `src/executor/sftp.rs:25`; `validate_local_path` `src/executor/sftp.rs:113` (absolute, no `..`, not a symlink, resolved parent under roots, **new** deny-list, `allowed_local_paths`); `open_local_nofollow` (O_NOFOLLOW, **new** nlink=1) | prompt / audit (**new**: resolved path), remote SFTP, local file |
| `db_query.query_name/params` | limits (32 × 16 KiB); `find_query` (declared name, count); per-driver type conversion; bound parameters | prompt / audit (name, count, **new** host), DB server |
| `get_secret_for_env.name` | **new** length ≤ 256, must be a preset or `[[server]]` secret, never the Telegram token — before the prompt | prompt, audit, keychain read, agent (value) |
| MCP `initialize` client info | `client_label` → `sanitise_for_prompt` (64/32 chars) | audit `client` column |
| JSON-RPC framing on stdin | **new** `stdio_transport` `src/cli/mcp.rs:123` (16 MiB line limit, bad lines skipped) | rmcp |
| Upstream HTTP response | **new** 10 MiB decoded ceiling `src/executor/response.rs:9`; scrub `src/executor/credential_echo.rs:112`; serde depth 128; `response_fields` | agent; stderr (count only) |
| Upstream SSH output / handshake | known_hosts `src/executor/known_hosts.rs:20`; **new** 1 MiB/stream, whole-call timeout | agent |
| Upstream DB rows / errors | **new** timeout, 10 MiB ceiling, password scrub `src/executor/db/mod.rs:34-144` | agent, audit |
| Telegram updates | chat id, 32-hex token, message id, `/lock` parse `src/approval/telegram.rs:221` | decision, lock file |
| `config.toml` (agent may write it, or point `MCP_WARDEN_CONFIG_DIR` at its own) | `Config::validate` `core/src/config.rs:256` (secrets present, **new** loopback-only http, duplicate names, reserved `stamp/` names); **new** stamps `core/src/stamp.rs:75,129` | everything above |
| `MCP_WARDEN_APPROVAL_TRANSPORT` | **new** cannot override `[approval.telegram]` | transport choice |
| CLI args (agent may run the CLI) | `--confirm-auto` (flag only); **new** approval-prompt confirmation + stamps; `secret add/remove` refuse `stamp/` | config, keychain |
| HTTP to `mcp-warden web` | **new** `only_this_ui` `src/web/server.rs:70` (Host, Origin/Sec-Fetch-Site for non-GET); HTML escaping; **new** sanitiser | browser |
| `<config dir>/lock` | `is_present` (symlink counts); **new** `read_small_nofollow` `src/fsutil.rs:93`; **new** 1 s watcher | lock latch |
| `telegram/offset`, `inbox/*`, `poll.lock` | **new** O_NOFOLLOW + O_NONBLOCK, small regular files only | poller |
| `audit.db`, `-journal`, `-wal`, `-shm` | **new** symlink refusal for all four, `SQLITE_OPEN_NOFOLLOW` on the resolved path `core/src/audit/sqlite_sink.rs:20` | audit writes |
| config dir itself | **new** `ensure_private_dir` `src/fsutil.rs:61` (0700, refuse group/world-writable or foreign owner) | all of the above |

## Findings

Severity is for the v0.5.3 code. Each entry: hypothesis → result → evidence → fix commit.

| # | Finding | Sev | Status | Evidence (failed before, passes after) | Commit |
|---|---|---|---|---|---|
| A10 | Config edited between server starts (or `MCP_WARDEN_CONFIG_DIR` → agent's config) was trusted: `auto` + new `base_url`/allow-lists bound to an existing secret ran without a prompt; `[[server]]` command edits received keys; the prompt never named the destination | **High** | Confirmed, fixed | `stamp::tests::an_edited_auto_preset_runs_as_prompt`, `cli::mcp::tests::unconfirmed_auto_presets_are_served_as_prompt`, `cli::confirm::tests::*`, `mcp::refusal_tests::the_prompt_names_the_destination_host`, `run_without_confirmation_starts_nothing` | 5dfc84a, 4adb3fa |
| A10b | Stamp forgeable: bare SHA-256 written via `secret add stamp/…` (found by the automated review of 4adb3fa) | High (in unreleased code) | Confirmed, fixed | `stamp::tests::a_stamp_written_without_the_key_does_not_count`, `cli::secret::tests::stamps_cannot_be_written_or_removed_from_the_cli`, `config::tests::presets_cannot_use_a_reserved_keychain_name`. The CLI test hung on stdin before the fix (that run was killed), so its "before" state is reasoned rather than observed | 962f65f |
| A3 | `allowed_methods` bypass via `_method` / `X-HTTP-Method-Override` in query or JSON body (Laravel/Symfony), PHP renaming `.`/`[`/space | **High** | Confirmed, fixed | `policy::tests::hostile_corpus_query_keys_are_refused_whatever_the_allow_list` (failed on `_method`, `_METHOD` …), `method_override_in_the_json_body_is_refused`; corpus `tests/corpus/queries.txt` | 001bb88 |
| T-new | Telegram configured, but a timeout fell back to the local dialog, and env `MCP_WARDEN_APPROVAL_TRANSPORT=desktop` replaced Telegram — defeats R1 for a screen-controlling agent | Medium | Confirmed (code), fixed | `cli::mcp::tests::telegram_has_no_local_fallback_unless_opted_in`, `the_environment_cannot_replace_telegram_with_a_local_prompt` | 6f41272 |
| G-new | `get_secret_for_env` prompted for any name, any length (no T8 limit), could reveal the Telegram bot token | Medium | Confirmed, fixed | `mcp::refusal_tests::revealing_anything_but_a_preset_secret_is_refused_unasked` (shown failing with the check disabled) | 190b77c |
| A1 | DNS rebinding: web UI served any `Host` | Medium | Confirmed, fixed | `web::server::tests::requests_for_another_host_are_refused` (evil Host got 200), `state_changing_requests_need_this_origin` | 34f71e3 |
| A2 | Bidi/zero-width/U+2028/combining runs passed `sanitise_for_prompt` into every transport, audit CLI and web UI (sftp paths, secret name, refused-event text, client label) | Medium | Confirmed, fixed | `approval::tests::invisible_and_reordering_characters_are_made_visible` etc., `dialog::tests::message_escapes_…`, `telegram::tests::render_body_escapes_…`, `web::handlers::tests::agent_text_is_shown_with_reordering_characters_escaped` | 90f10a6 |
| A7 | No default HTTP body ceiling (gzip bomb: 11 KiB → 11 MiB to the agent); unbounded SSH output; SSH timeout covered only output, SFTP and DB had none; DB rows unbounded | Medium | Confirmed, fixed | `http::tests::a_gzip_bomb_is_withheld_without_max_response_bytes`, `ssh::tests::endless_output_is_cut_at_the_limit`, `…stalls_after_authentication_times_out` (ssh, sftp: hung >10 s with timeout 1 s), `db::tests::a_database_that_never_answers_times_out` (Postgres hung), `an_oversized_result_is_withheld` | 4d3f78e |
| A8 | Scrubber missed base64/base64url/hex/re-cased echoes; `db_query` rows not scrubbed (Redis `CONFIG GET requirepass` returned the password) | Medium | Confirmed, fixed | `credential_echo::tests::encoded_and_recased_echoes_are_redacted` (base64 not found), `mcp::leak_tests::failing_upstreams_never_leak_the_secret` (Redis password leaked) | ad86c2c, b40e463 |
| A9 | `doctor --deep`: keyword-only redaction printed a reflected credential; `--include-prompt` probed `prompt` presets with real credentials without asking; no audit | Medium | Confirmed, fixed | `doctor::tests::a_reflected_credential_is_not_printed` (shown failing without scrub), `probing_a_prompt_preset_asks_first` | b91778c |
| A11 | `sftp_transfer` local side: all of `$HOME` (keys, rc files, agent configs, mcp-warden config); hard links bypass any path check; prompt showed unresolved path | Medium | Confirmed, fixed | `sftp::tests::hostile_corpus_local_paths_are_refused_under_home`, `a_symlinked_parent_…`, `hard_linked_files_are_refused` (all three failing with the checks disabled), `the_prompt_shows_the_resolved_local_path`; corpus `tests/corpus/local-paths.txt` | 38430b5 |
| A12 | `http://` `base_url` to non-loopback only warned; credential in clear text | Medium | Confirmed, fixed | `config::tests::plain_http_is_refused_unless_the_host_is_loopback` | 28fe904 |
| A13 | Lock or `preset grant` expiry during an open prompt did not stop the call after Approve; parallel calls stacked dialogs | Medium | Confirmed, fixed | `executor::tests::a_lock_set_while_the_prompt_is_open_stops_the_call`, `access_that_ends_while_the_prompt_is_open_stops_the_call`, `prompts_are_shown_one_at_a_time` (4 dialogs open at once) | eeb853c |
| A13b | Lock latched only on the next call; agent deleting the file first escaped it | Low–Medium | Confirmed, fixed | `executor::tests::a_lock_deleted_before_the_next_call_still_holds` | eeb853c |
| A14 | One undecodable stdin line ended the server (rmcp treats decode errors as EOF); no line-length limit | Low | Confirmed, fixed | `tests/mcp_integration.rs::malformed_and_oversized_messages_do_not_stop_the_server` (broken pipe after `{not json`) | 14d6745 |
| A15 | `lock`, `telegram/offset`, inbox read through symlinks to EOF (`/dev/zero` → never ends); `poll.lock` opened through FIFO; SQLite followed `audit.db-shm`/`-journal` symlinks; config dir created with umask | Low | Confirmed, fixed | `lock::tests::a_hostile_lock_file_still_locks_and_reads_quickly` (timed out), `fsutil::tests::small_state_files_…`, `telegram::tests::planted_state_files_do_not_hang_the_poller`, `audit::tests::a_symlinked_journal_or_database_is_refused` (`-shm` followed), `fsutil::tests::the_config_dir_is_private_…` | 2346408 |
| A5 | Shell differences | Low | Partly confirmed, fixed | Differential proptest over 8 shells (400 × 8 runs): every permitted word reached argv unchanged. Exceptions: leading `NAME=value` (an env assignment in all 8 shells, fish included) and fish `%self` (expands to the PID). `ssh::tests::permitted_characters_that_are_not_plain_words_are_refused`, corpus `commands.txt` | 15ed9e1 |
| A6 | Option injection through recommended patterns: cookbook `systemctl status [a-z0-9_-]+` admits `-Hhost` | Low | Confirmed (docs), fixed | `doctor::tests::documented_command_patterns_admit_no_options` (failed on the cookbook pattern), `arguments_that_may_be_options_are_flagged` | 7890abd |
| D-new | Duplicate preset names accepted (first wins, others visible in list/UI/windows) | Low | Confirmed, fixed | `config::tests::duplicate_preset_names_are_refused` | a342fbc |
| A17 | 27 RustSec advisories in Cargo.lock (incl. russh allocation DoS, rustls, webpki, postgres-protocol SCRAM DoS); Actions pinned by tag; `ci.yml` had no `permissions` | Medium (deps) / Low (CI) | Confirmed, fixed (19 advisories by semver updates; 8 accepted with reasons) | `cargo audit` 27 → 8 (all in deny.toml); `cargo deny check` passes | da86894, 875e707, 42f8127 |
| P-new | Pinned tool-description snapshots were not compared with the served descriptions (sftp copy had drifted) | Info | Fixed | `mcp::server::tests::pinned_descriptions_are_the_ones_served` | 190b77c |
| A4 | Ordering of checks (invariant 3) | — | **Not confirmed** | `mcp::refusal_tests::*` drove all three corpus files and other refusals through the tools. Every refused call did 0 keychain reads, opened 0 prompts and made 0 upstream requests or TCP connections, and left exactly one `refused` event | 4295606 (harness) |
| A16 | `db_query` injection / LOCAL INFILE / multi-statements | — | **Not confirmed** (by source reading) | Parameters are bound: prepared statements for PG/MySQL, separate RESP arguments for Redis. mysql_async 0.34.2 answers LOCAL INFILE with `NoHandler` when no handler is set (`conn/routines/helpers.rs:93`), and none is set. MySQL was not exercised. `doctor` now flags risky Redis commands | dfdc0d5 (lint) |
| A9 (errors) | Secrets in error text: refused connections, TLS failures, 401s, DB server errors | — | **Not confirmed** for HTTP/PG/Redis | `leak_tests`: reqwest errors carry only the URL. tokio-postgres reports `db error` without the server text, redis-rs reports `AuthenticationFailed`. Error text is still scrubbed now as defence in depth | b40e463 |
| A18 | Fuzzing | — | see below: no crash in 8 targets | | 054a2b6, cc70e3d, 34b4ea7 |

## Fuzzing results

Each target ran for 10 minutes (`-max_total_time=600 -rss_limit_mb=2048 -timeout=10`, cargo-fuzz 0.13.2, nightly) on an Apple M-series machine, eight in parallel:

| Target | Executions | Result |
|---|---|---|
| `check_request` (wide-open presets; an allowed path must build to the same URL path) | 770 159 | no crash |
| `check_words` (accepted commands contain only permitted words) | 1 142 259 | no crash |
| `config` (parse, validate, stamp demotion) | 2 829 931 | no crash |
| `scrub` (oracle: no case-insensitive form of the secret survives) | 1 094 334 | no crash |
| `select_fields` | 1 910 190 (re-run) | first run stopped on fields `>` / body `4`: a scalar body returns `null`, longer than the body. Wrong oracle, not a bug; oracle fixed in 34b4ea7, re-run clean |
| `known_hosts` (russh's parser never verifies a key the file lacks) | 1 129 875 | no crash |
| `telegram_updates` | 1 125 160 | no crash |
| `sanitise_for_prompt` (no Cc/Cf/Zl/Zp output, at most `max` chars) | 3 379 412 | no crash |

Plus the property test `an_allowed_request_reaches_the_upstream_as_checked` (256 cases end to end through wiremock): no counterexample. The differential shell test (`shells_split_permitted_words_as_written`, 400 cases × 8 shells): no divergence after the fix.

## Residual risks and owner decisions still open

- **Upgrade majors** to clear the 8 accepted advisories: russh 0.65 (rsa / crypto-bigint), mysql_async (zstd) and notify-rust (quick-xml, Windows only). Each is semver-breaking and gets its own change.
- **Hostile DB result sets** are still read fully into memory before the size check (the drivers buffer).
- **R1 remains:** an agent with screen control can click a local dialog. Telegram is now enforced when configured.
- **Several MCP server processes**, one per client session, can each show one dialog at the same time.
- **The SFTP deny-list cannot be complete.** `allowed_local_paths` is the real control.
- **Stamps defend against file and CLI access, not N2.** An agent that writes the keychain directly is out of scope.
- **Behaviour changes in 0.5.4** — see CHANGELOG.
  - `auto` presets ask until `mcp-warden preset confirm` is run.
  - Each wrapped server asks once on first launch.
  - Plain-http non-loopback presets, group-writable config dirs and duplicate names stop the server.

---

# Re-audit for 0.6.0 (block E)

Scope: the code added for 0.6.0 on `release/0.6.0` — the dependency upgrades, named SSH commands (`ssh_run`, generated tools), the `query`, `oauth2` and `aws_sigv4` auth kinds, the hash-chained audit log with its keychain anchor and `audit verify` — and what changed around them. Severity is for the code as it stood when found; "unreleased" marks code that never shipped.

## Method

The method of block A:

1. **Inventory** of the new inputs (below).
2. **The same attacker model:** a fully prompt-injected agent that can write the user's files and run the CLI, hostile or reflecting upstreams (now including OAuth2 token endpoints), and anyone who can write `audit.db`. Direct keychain writes (N2) and root stay out of scope.
3. **Exploit tests** for every hypothesis, through the real code path: the MCP tool methods with the counting keychain, approval transport and listeners of `src/mcp/refusal_tests.rs`; the in-process SSH server; wiremock upstreams and token endpoints; raw `sqlite3`-style edits of `audit.db` with the triggers dropped. Confirmed findings had a failing test first.
4. **Leak tests** at TRACE log level for every new auth kind (`src/mcp/leak_tests.rs`).
5. **Fuzzing:** three new targets and two more request kinds in `check_request` (results below).

Not done, and why:
- **No AddressSanitizer.** The installed nightly (2026-10-31) cannot compile russh 0.65: rustc reports a query cycle while computing async-drop for ssh-key's `KeyData`. The targets were built with stable rustc (`RUSTC_BOOTSTRAP=1 cargo +stable fuzz run -s none`), so libFuzzer ran with debug assertions and overflow checks but without ASan. The code under test has no `unsafe`.
- **No real provider.** OAuth2 ran against wiremock token endpoints, not Google; SigV4 is checked against AWS's own `get-vanilla` test vector and wiremock, not AWS. Both live checks are on the owner's list.
- **Windows** ran only in CI (tests and clippy), as for block A.

## Input inventory

| Input | Checks | Reaches |
|---|---|---|
| `ssh_run.command` | limits (64 bytes); `commands::find` (declared name; an invalid name is never echoed) | audit (`ssh_run`, or `ssh_run:<command>` once found), prompt |
| `ssh_run.params` | limits (16 × 256 bytes) `src/executor/limits.rs`; `commands::render` `core/src/commands.rs`: exact key set, per type (int decimal in range; enum exact; string/path one word, pattern, no leading `-`; path absolute, no `//`, `.`, `..`), substitution, shell-syntax check and length again | prompt / audit (full command), remote login shell |
| generated tool arguments (`ssh_<preset>_<command>`) | the same `ssh_run` path | the same |
| `[[preset.commands]]` in the config | `commands::validate_preset` / `validate_tool_names` at startup: names, description, template words and placeholders, every enum value and int bound filled in through `check_words`, longest expansion ≤ 1024, ≤ 32 generated tools, no clash with static tools | tool list, `list_presets`, prompts |
| a command's `approval` | `stamp::demote_unconfirmed_auto`: `auto` only if the preset is confirmed in exactly this form; a `deny` preset refuses every command | policy |
| `query` auth `name` | config: 1–64 of `A-Za-z0-9_.-`, not already in `base_url`; per call `check_auth_query_name` (case, spaces, `.`/` `, `key[…]`) | upstream URL (never prompt, audit summary or error text) |
| OAuth2 `token_url`, `client_id`, `scopes`, entries | config: https or loopback http, client id 1–256 without control characters, RFC 6749 scope tokens, distinct entries, refresh-token entry used by nothing else | token endpoint |
| OAuth2 token endpoint answer | `oauth2::parse_answer`: 64 KiB, 15 s, no redirects, status 200, tokens printable ASCII ≤ 16 KiB, `token_type` bearer; errors give the status and `error` code only | `Authorization` header; keychain (rotated refresh token, under `fslock`) |
| `aws_sigv4` `region`, `service`, entries | config: 1–32 of `a-z0-9-`, distinct entries; signing after every check and the approval, with tracing silenced | upstream headers |
| `audit.db` (`events`, `chain`) | triggers; `chain::verify`; anchor `advance` / `check` | `audit verify`, doctor, web UI, the anchor |
| keychain `audit/anchor/…` | `Anchor::decode` (strict; malformed is an error); `audit/` reserved for CLI, presets, servers, Telegram | `audit verify`, `advance` |
| `<config dir>/locks/*` | `fslock`: 0700 directory, 0600 files, no symlink file or directory | OAuth2 rotation, anchor moves |

## Findings

| # | Finding | Sev | Status | Evidence | Commit |
|---|---|---|---|---|---|
| E1 | RSA keys signed with `ssh-rsa` (SHA-1), which OpenSSH ≥ 8.8 refuses: an RSA key could not log in to a current sshd (found while upgrading russh) | Medium (functional; in 0.5.4) | Confirmed, fixed | `ssh::tests::an_rsa_key_signs_with_sha2` failed with `["ssh-rsa"]` | c0461d5 |
| E2 | `proxy_http` errors quoted reqwest's error text, which names the full request URL with its query string, to the agent and the audit log | Low in 0.5.4 (only the agent's own values); High with `query` auth | Confirmed, fixed | `http::tests::upstream_errors_do_not_carry_the_url` failed with `error sending request for url (http://127.0.0.1:…/users/abc?page=url-marker)` | 6962202 |
| E3 | aws-sigv4 traces its signing parameters and canonical request at TRACE: with `RUST_LOG=trace` the access key id and any session token reached stderr (invariant 1) | High (unreleased) | Confirmed, fixed | `leak_tests::failing_upstreams_never_leak_query_oauth2_or_sigv4_secrets` failed: "stderr holds a form of the secret (AKID…)" | 2b84cac |
| E4 | The query credential's own name was refused only ignoring case and spaces; `key[]` and `key[x]`, which PHP and Rack read as `key`, got through, so the agent could send its own value for the upstream to pick | Low (unreleased) | Confirmed, fixed | `http::tests::the_caller_cannot_send_the_query_credentials_parameter` failed on `"key[]"` | ab02f50 |
| E5 | `approval.telegram.bot_token_secret` accepted reserved names (`stamp/…`), so a stamp could have been sent to Telegram as the bot token | Low (in 0.5.4) | Confirmed, fixed | `config::tests::presets_cannot_use_a_reserved_keychain_name` (Telegram case) | 84f9641 |
| E6 | Writers of the audit log can starve: SQLite does not queue processes waiting for the write lock, so with several busy writers on a slow disk one can wait past the busy timeout and its write fails (closed: the call or CLI command fails). Every open also took the write lock, to look for the genesis record | Low (unreleased) | Confirmed in Windows CI; mitigated: opening reads first, the timeout is 10 s, the tests' load is realistic (see residual risks) | `chain::tests::writers_in_parallel_make_one_chain` and `anchor::tests::racing_movers_never_move_it_back` (240 and 120 commits from four threads) failed on windows-latest with "database is locked" | 8dbc0de, this commit |

Refuted hypotheses, each pinned by a test:

- **Named-command values** — shell syntax, a leading `-`, `=` or `%`, `..`, `//`, NUL and control characters, non-ASCII look-alikes, a sign, leading zeros, hex, overflow, enum case variants: all refused (`tests/corpus/named-commands.txt`, 60 entries, at the policy and the MCP level with zero key reads, prompts and connections).
- **A repeated JSON key** in `params`: serde keeps the last, and that is the value checked and run.
- **Templates that could produce shell syntax** (an enum value or int bound that breaks a word, a literal `$(…)`) or more than 1024 bytes: the server refuses to start.
- **An unconfirmed command-level `auto`** (an agent edits one command of a `prompt` preset): served as `prompt` (written test-first, 5bfa680).
- **A window for one command covering another:** no; the key is `(preset, ssh_run:<command>)`.
- **Generated tools:** name collisions across presets (`a_b`+`c` vs `a`+`b_c`), a 33rd tool and names that are not valid MCP tool names all stop the server.
- **Hostile token endpoint:** a 400 quoting the refresh token and client secret, a non-`error` code, 70 KiB, non-JSON, `token_type=mac`, CR/LF in the token, a 302 (not followed), a 5 s stall (15 s cap, preset timeout 2 s): each fails the call, and none of the secrets reaches the agent, stderr or the audit log.
- **Rotation:** two concurrent calls through one refresh token both succeed and the newest token is stored; an empty, spaced or non-string rotated token fails the call and leaves the stored token; a failed write fails the call.
- **SigV4:** a refused call reads no key and signs nothing (path corpus through the refusal harness).
- **The audit chain:** an edited field, an edited or deleted chain record, a deleted event, an inserted unchained event, an unreadable record with a recomputed hash and an edited pre-0.6.0 row are each named; four writers in parallel keep one linear chain.
- **Laundering:** a log rewritten with its whole chain recomputed verifies on its own, but the anchor will not move onto it, and `audit verify` reports "rewritten"; a rollback to an older copy and a deleted database are reported too; four processes racing never move the anchor backwards; a malformed anchor is an error.
- **Lock files:** a symlink at a lock file or in place of the locks directory is refused.

## Fuzzing results

| Target | Time | Executions | Result |
|---|---|---|---|
| `named_command` (**new**; oracle: what renders passes the shell-syntax check, fits 1024 bytes and keeps the template's word count) | 10 min | 1 598 936 | no crash |
| `oauth_token_response` (**new**; oracle: an accepted token is printable ASCII without spaces, ≤ 16 KiB, only from a 200) | 10 min | 2 127 297 | no crash |
| `audit_verify` (**new**; arbitrary chain rows) | 10 min | 1 456 931 | no crash |
| `check_request` (**extended** with `ssh_run` and a query-auth preset; oracle: the credential's parameter name never gets through) | 10 min | 1 655 583 | no crash |
| `config`, `check_words`, `known_hosts` (russh 0.65), `sanitise_for_prompt`, `scrub`, `select_fields`, `telegram_updates` (regression runs) | 2 min each | 230 629 – 1 331 785 | no crash |

All built with stable rustc, without AddressSanitizer (see Method).

Plus the 60-entry named-command corpus and the hostile path corpus against a SigV4 preset, both through the refusal harness.

## Residual risks

- **The tail after the anchor.** Records written since the last anchor move (up to about a minute while a server runs, or since the last session ended) can be rewritten or cut without `audit verify` noticing. N2 (an agent that writes the keychain) and root remain out of scope. On Linux the anchor may not survive a reboot.
- **Unfair waiting for the audit log.** Each tool call makes three or four short audit writes. Many MCP sessions writing at once on a slow disk could keep one waiting past 10 s; that call then fails rather than run unaudited.
- **Cost of the chain.** Each audit write is one transaction with its chain record (about 0.5 ms here); the database roughly doubles. `audit verify` took 2.3 s for 100 000 events (300 001 records, 79 MB), and the web UI's audit page runs the chain check on every request.
- **Descriptions come from the config.** Command and generated-tool descriptions are shown to the agent as written (no control characters, at most 512 characters). An edited config can put instructions there, as it already can in preset descriptions (T7).
- **A key in the URL** (`query` auth) is visible to whatever logs URLs on the upstream's side. Prefer header auth where the API has it.
- **One token request per call** for OAuth2 (no cache, by decision): providers with tight token-endpoint rate limits may throttle.
- **Copies we do not control.** reqwest keeps the URL (with a `query` key) and the token request's form body in its own buffers until they are dropped; aws-credential-types keeps the SigV4 keys for the call.
- **Upgrade window.** A 0.5.x server still running after the upgrade writes rows without chain records; `audit verify` reports them as unchained. Restart MCP clients after upgrading.
- **RUSTSEC-2023-0071** (rsa, Marvin) stays accepted: no fixed release, signing only (owner decision 2026-11-03).
- **Fuzzing without ASan** (above), until a nightly compiles russh 0.65.
