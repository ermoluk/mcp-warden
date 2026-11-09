# mcp-warden security audit — 9 November 2026

Scope: `main` at fb77981 (v0.6.0), six days after the 0.6.0 re-audit (block E of `security-audit-2026-11.md`). No code changed in between, so this audit takes **new angles** instead of repeating blocks A and E: the process environment as attacker input, code the earlier inventories did not cover (`preset from-openapi`), new RustSec advisories, and ASan fuzzing now that a nightly builds russh 0.65.

Exploit tests and fixes were made on branch `security/audit-2026-11b` and shipped in **0.6.1** (ermoluk/mcp-warden#4). The exploit tests (2238e0e, c7394c5) were written first and failed on fb77981; each fix commit removes their `#[ignore]` and they now pass with the rest of the suite:

| Commit | Change |
|---|---|
| 96fa67e | rusqlite 0.41 (SQLite 3.54.1); RUSTSEC-2026-0462 accepted with its reason |
| 845e425 | H4: home from the account database (`src/osenv.rs`), also for `known_hosts` |
| 8d461e7 | H1: `run` resolves the command in the entry's `path`, clears the environment, starts in the account's home, pins the resolved program in the stamp |
| 1d5822d | H2: Windows PowerShell from the System known folder; the dialog's search paths from known folders; .NET profiler / runtime-hook variables removed |
| 6709cfd | H5: no proxy for plain-http requests (proxy_http, OAuth2 token, doctor --deep) |
| 54c13ec | O1–O4: OpenAPI paths as escaped one-segment patterns, review output, `--confirm-auto`, streamed cap, `/tmp` on macOS |
| bfef245 | `audit` prints words instead of Rust `Debug` |
| 0f38d61 | threat model T11, R1, R5, R10, R12; CHANGELOG; docs |

This report was kept out of git until the fixes were ready to ship with 0.6.1.

## Attacker model

As in block A: a fully prompt-injected agent that can write the user's files and **run the CLI**, hostile or reflecting upstreams, a hostile web page. N2 (an agent that writes the keychain directly) and root stay out of scope.

The new observation: such an agent also chooses the **environment** of every mcp-warden process it starts — `PATH=… mcp-warden run x`, `SystemRoot=… mcp-warden mcp`, or `"env"` in an MCP client config it edits. T7 already assumes this for `MCP_WARDEN_CONFIG_DIR`; no other variable was considered. Every process mcp-warden starts inherits that environment (`Command::new` without `env_clear`), and several values are read from it directly (`dirs::home_dir()` reads `$HOME`, reqwest reads `HTTP_PROXY` / `ALL_PROXY`, rustls-native-certs reads `SSL_CERT_FILE`).

## Findings

| # | Finding | Sev | Status | Evidence |
|---|---|---|---|---|
| H1 | (Listed as accepted residual risk R12 until now.) `mcp-warden run` hands a confirmed server's keys to a program the caller picks: the command (`npx`) is looked up on the caller's `PATH`, and the caller's `NODE_OPTIONS` / `BASH_ENV` / `PYTHONPATH` reach the server next to its keys. The stamp pins name, command, args and variable names, not the environment, so no prompt is shown. | **High** | Confirmed, **fixed** (8d461e7) | `cli::run::tests::audit_h1_the_callers_path_does_not_pick_the_program_that_gets_the_key` (the caller's fake `npx` received the key), `…_code_loading_variables_do_not_reach_the_server` (NODE_OPTIONS reached it) |
| H2 | Windows approval dialog: the program is `<SystemRoot>\System32\WindowsPowerShell\v1.0\powershell.exe`, or `powershell.exe` on `PATH` without `SystemRoot`. Whatever runs decides the approval (`replies_from_the_helper_become_decisions`), so a fake one approves every prompt, `get_secret_for_env` included. `PSModulePath` is inherited too (not analysed). | **High** (Windows) | Confirmed (path resolution), **fixed** (1d5822d); not exercised on Windows — the Windows CI job is the first real check | `approval::powershell::tests::audit_h2_the_callers_environment_does_not_pick_the_dialog_program` |
| H3 | Linux notification approval: `DBUS_SESSION_BUS_ADDRESS` names the bus; a notification server the agent runs there can answer "approve". | Medium | Plausible, not tested (no Linux desktop here); documented under R1, not changed | analysis of `notify-rust` / zbus |
| H4 | `sftp_transfer`: the `$HOME` root and the whole sensitive-location list come from `$HOME`. With `HOME` one level up the user's real `~/.zshenv` (or `~/.ssh/id_*`) is allowed: `get` can write a shell startup file, `put` can upload keys. The prompt still shows the resolved path. | Medium | Confirmed, **fixed** (845e425) | `executor::sftp::tests::audit_h4_the_callers_home_does_not_move_the_sensitive_locations`: `allowed /Users/…/.zshenv` with `HOME=/Users` |
| H5 | `proxy_http` (and the OAuth2 token request, `doctor --deep`, Telegram) honour `HTTP_PROXY` / `ALL_PROXY`. A loopback `http://` preset — the one plain-text kind the config allows — sends its credential to the caller's proxy. HTTPS stays protected (webpki roots only); the proxy learns hosts and can block Telegram approvals. | Low–Medium | Confirmed, **fixed** (6709cfd) | `executor::http::tests::audit_h5_a_proxy_from_the_callers_environment_never_sees_the_credential`: the proxy got `authorization: Bearer …` |
| H6 | Postgres (`rustls_native_certs::load_native_certs`) and Redis TLS trust `SSL_CERT_FILE` / `SSL_CERT_DIR`, so the caller can add a CA; a MITM still needs a network position. | Low | By analysis; documented under R10, not changed (private-CA databases rely on the OS store) | `src/executor/db/postgres.rs:81`, redis → rustls-native-certs 0.7 |
| H7 | RUSTSEC-2026-0459 (bundled SQLite < 3.54): a planted `audit.db` + `-wal` with different page sizes returns uninitialised page-cache memory. The agent can plant both (same user; symlinks are refused, regular files are not). The MCP server reads only the chain tip (`seq`, `hash`): the hash is hashed again, `seq + 1` is written back, so at most a few stale bytes per write. `audit`, `audit verify` and `web` print rows but hold no secret (no keychain read beyond the anchor). | Low | By analysis; **fixed** by rusqlite 0.41 (96fa67e) | `core/src/audit/chain.rs:110-130` |
| O1 | `preset from-openapi` copies spec paths into `allowed_paths` verbatim: `/pets/{id}` matches nothing but itself, so every templated operation is refused (functional). | Medium (functional) | Confirmed, **fixed** (54c13ec) | `cli::openapi::tests::audit_generated_presets_allow_the_specs_own_operations` |
| O2 | …and a spec path holding regex syntax (`/pets|/.*`) becomes a pattern allowing every path. The CLI prints only an operation count. | Low | Confirmed, **fixed** (54c13ec) | `cli::openapi::tests::audit_spec_paths_cannot_widen_the_allow_list` |
| O3 | `from-openapi` reads the whole response before the 50 MB cap (`resp.bytes()`); refuses spec files under `/tmp` on macOS (`/private/tmp`) despite its message. | Low | Confirmed (`/tmp`), by reading (cap); **fixed** (54c13ec) | CLI run: `path must be under $HOME or /tmp/` for `/tmp/x.json` |
| O4 | Invariant 4 at the CLI: `from-openapi --approval auto` and `scaffold` of an `auto` template take no `--confirm-auto`. The 0.5.4 stamps serve such presets as `prompt` until `preset confirm`, so there is no runtime effect. | Info | By reading; **fixed** (54c13ec): `--confirm-auto` required, `scaffold` explains | `src/cli/preset.rs:363`, `preset_templates.rs` |
| D1 | RUSTSEC-2026-0462 (rmcp < 3.9, Streamable HTTP client buffering): not compiled in — rmcp features are `server`, `macros`, `schemars`, `transport-io`. CI `supply-chain` fails on it anyway. | — (not affected) | Verified; accepted with its reason (96fa67e) | `cargo tree -i rmcp -e features` |

Refuted or unchanged:

- **macOS dialog:** `/usr/bin/osascript` by absolute path (SIP strips `DYLD_*`), fixed script with no `use` clauses — not affected by the environment.
- **`[[server]]` names and variables:** strictly validated (`[A-Za-z0-9_.-]`, POSIX variable names), so no aliasing of another server's keychain entry.
- **Supply chain:** every action pinned by SHA, top-level `contents: read`, the tap token only in the publish step, no `pull_request_target`. `shellcheck -o all` on `install.sh` and the plugin hook: 57 style (SC2250) and 2 info (SC2312) notes, no warning or error. `install.ps1` not analysed (no PSScriptAnalyzer).
- **Advisory warnings** (allowed): unmaintained `rustls-pemfile` (redis), `unsafe-libyaml` / `serde_yaml` (OpenAPI import), `zbus_names` / `zvariant*` (Linux notifications); unsound `lru` 0.16 (ratatui, TUI approval; `pop` panic safety).

## Fuzzing

**With AddressSanitizer for the first time since 0.6.0:** nightly 2026-11-08 compiles russh 0.65 (the 2026-10-31 nightly hit a rustc query cycle). `cargo +nightly fuzz build`; the binaries link `librustc-nightly_rt.asan.dylib`. All 11 targets ran in parallel, 10 minutes each (`-rss_limit_mb=2048 -timeout=10`), seeded from `fuzz/corpus/`, new inputs written to a scratch directory:

| Target | Executions | Result |
|---|---|---|
| `audit_verify` | 484 928 | no crash |
| `check_request` | 588 328 | no crash |
| `check_words` | 859 618 | no crash |
| `config` | 2 009 254 | no crash |
| `known_hosts` | — / 1 614 674 (re-run alone) | one 10 s timeout on `##\n` under full machine load (11 fuzzers plus two builds); the input runs in 0–2 ms on its own, and a 10-minute re-run alone was clean. The target writes a temporary file per input, so a stalled file system explains it. Not a finding. |
| `named_command` | 548 747 | no crash |
| `oauth_token_response` | 837 720 | no crash |
| `sanitise_for_prompt` | 2 516 671 | no crash |
| `scrub` | 826 843 | no crash |
| `select_fields` | 831 115 | no crash |
| `telegram_updates` | 852 662 | no crash |

## Functional check

- Gate on `main`: `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -D warnings`, `cargo test --workspace`: 469 passed, 1 ignored (the differential shell test). Same on the audit branch with the 11 new ignored tests.
- `cargo build --release --locked`: 11.7 MB (arm64).
- Smoke test of the debug build with the in-memory keychain and a throwaway config dir: `init`, `preset scaffold` / `list` / `test` (allowed, refused, traversal), `doctor`, `secret list`, `audit`, `audit verify`, `lock` / `unlock`, `run` while locked, `server add` / `list`, `scan` (fake token found, value never printed), `mcp` refusing to start on a missing secret, and an MCP session: `initialize`, `tools/list` (all seven tools), `list_presets`, refusals for unknown presets, stdout pure JSON, refusals in the audit log, chain intact.
- Found: `mcp-warden audit` prints `Some(Refused) Some(Err { message: … })` (Rust `Debug`) since v0.4.1 — cosmetic. `doctor` exits 0 even with `validation: FAIL`.
- rusqlite 0.41 tried in a copy: builds unchanged, all tests pass, RUSTSEC-2026-0459 gone.

## Fixes as made (owner chose "all fixes", 2026-11-10)

- **H1:** cleared environment (pass-through: `USER`, `LOGNAME`, `LANG`, `LANGUAGE`, `LC_*`, `TERM`, `COLORTERM`, `NO_COLOR`, `TZ`, `TMPDIR`; `HOME`/`PATH` set by mcp-warden), command resolved in the entry's new `path` or a fixed default, the resolved program in the stamp, cwd = the account's home (npx reads a project `.npmrc`). Residual (R12): the server's own code and config in the home directory (npm cache, `~/.npmrc`) — an agent that can write the whole home can still change them.
- **H2:** take the Windows directory from `GetSystemDirectoryW`, never from `SystemRoot`; start the dialog with a cleared environment.
- **H3:** documented under R1 (use Telegram where an agent can run its own processes or drive the screen).
- **H4:** home from the account database (`getpwuid_r`; the Profile known folder on Windows). `scan`/`import` keep `$HOME` (discovery only).
- **H5:** `.no_proxy()` for plain-http requests only; HTTPS keeps the system proxy (corporate networks need it; TLS keeps it out).
- **H6:** not changed: dropping the OS store would break private-CA databases; documented under R10.
- **H7 / D1:** rusqlite 0.41; RUSTSEC-2026-0462 accepted in `deny.toml` / `.cargo/audit.toml`; rmcp 3.x remains its own change.
- **O1/O2:** `{param}` → `[^/]+`, the rest `regex::escape`d; the generated allow-list is printed.
