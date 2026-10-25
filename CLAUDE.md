# CLAUDE.md — agent context for the mcp-warden codebase

This file is loaded automatically when an AI coding agent is working in this
repository. Read it first; it's the source of truth for what this project is,
how it's structured, and what the security invariants are.

## What this is

`mcp-warden` is a local-first credential broker for the Model Context
Protocol. It lets any MCP-compatible AI coding agent (Claude Code, Cursor,
Cline, Codex, Continue, Zed, …) take real, scoped actions against a user's
services — deploys, API calls, SSH commands — without ever seeing the
underlying credential. The agent calls high-level tools (`proxy_http`,
`ssh_exec`); `mcp-warden` injects the secret server-side, executes the
action, and returns only the result.

The agent's context window contains zero secrets. A leaked transcript leaks
nothing useful.

It is **not** "Claude Warden" or "Anthropic Warden". It works with any MCP
client. README and marketing position this as agent-agnostic.

## Tech stack

| Concern                    | Crate                          |
|----------------------------|--------------------------------|
| Cross-platform keychain    | `keyring` 4                    |
| CLI                        | `clap` 4 (derive)              |
| MCP server (stdio)         | `rmcp` 1.6 (official SDK)      |
| Async runtime              | `tokio` 1                      |
| HTTP client                | `reqwest` 0.12 (rustls)        |
| SSH client (Phase 2)       | `russh` 0.60                   |
| SQLite                     | `rusqlite` (bundled)           |
| Desktop notifications      | `notify-rust` 4                |
| TOML                       | `serde` + `toml`               |
| Logging                    | `tracing` (always to stderr)   |
| Secret zeroing             | `zeroize`                      |
| Snapshot tests             | `insta`                        |
| CLI integration tests      | `assert_cmd` + `predicates`    |

Single static binary. No daemon, no Docker, no Postgres, no external
services.

## Architecture

```
┌──────────────┐    stdio MCP    ┌─────────────────┐
│  AI Agent    │ <-------------> │   mcp-warden    │
│ (any client) │                 │  (single proc)  │
└──────────────┘                 │                 │
                                 │  ┌───────────┐  │
                                 │  │  keyring  │  │
                                 │  └───────────┘  │
                                 │  ┌───────────┐  │
                                 │  │  SQLite   │  │
                                 │  └───────────┘  │
                                 └────────┬────────┘
                                          │
                                          v
                                  desktop notification
                                  (approval flow)
```

Two roles in one binary:
- `mcp-warden <subcommand>` — interactive CLI for setup (init, secret, preset, audit, approval, doctor).
- `mcp-warden mcp` — MCP server over stdio, consumed by the AI agent.

## The four trait seams

These traits exist with **one implementation each in OSS** but **must remain
abstract**. They are the open-core seams; future paid features (Team Mode,
Cloud Approval Relay, Compliance) attach as alternate implementations.

| Trait                | OSS impl              | Future paid impl ideas                  |
|----------------------|-----------------------|-----------------------------------------|
| `KeychainStore`      | `SystemKeychain`      | HSM, 1Password Connect, Vault           |
| `ApprovalTransport`  | `DesktopApproval` + `TuiApproval` | Telegram, mobile push, web UI |
| `AuditSink`          | `LocalSqlite`         | Cloud audit log, SIEM forwarding        |
| `PresetSource`       | `TomlSource`          | Org-managed central preset registry     |

Do **not** delete or weaken these traits when you only have one impl. The
abstraction is the product.

## Security invariants — non-negotiable

1. **Secrets never appear in logs** — ever. The audit log records action,
   preset name, and result. It never records the secret value or response
   bodies that could echo it. Sanitise.
2. **Secrets never appear in tool descriptions or error messages** returned
   to the agent.
3. **Allow-lists are enforced before credential injection**, not after.
   Validation failure → return an error to the agent, never invoke the
   upstream service.
4. **Default approval policy is `prompt`**. `auto` must be set explicitly
   per preset, with a CLI confirmation flag (`--confirm-auto`).
5. **SSH commands** (Phase 2): validate against the preset's regex
   allow-list. Use `russh`'s exec channel with the matched command — never
   `sh -c`. Strict char-class allow-list per arg, not `shell_escape`.
6. **HTTP**: validate `path` against `allowed_paths`, `method` against
   `allowed_methods`. Body is JSON; refuse non-JSON bodies in MVP. Use the
   `url` crate for parsing — never substring-match.
7. **Audit log is append-only**. No `audit clear`, no `audit delete`,
   ever. The trait surface enforces this — no `fn delete` / `fn clear`.
8. **Keychain access prompts the OS unlock dialog**. Don't cache secrets
   in process memory beyond a single tool call's lifetime. `zeroize` after
   use via the `Secret` newtype.
9. **No telemetry**. No analytics. No "phone home" check-for-updates. The
   user updates via package manager.
10. **Refuse to start** if any preset references a secret name that does
    not exist in the keychain. Fail loudly, never silently. Load-once-and-
    freeze the config in the MCP server to defeat TOCTOU.
11. **The free OSS binary remains fully functional forever**. No artificial
    gating, no "premium feature flags" baked in. Trust is the moat.

## What NOT to do

- Do **not** implement your own crypto. Use the OS keychain.
- Do **not** add cloud sync, even as opt-in, in the OSS binary. Hosted
  services are a separate (closed-source) product.
- Do **not** add RBAC, multi-user, or team features in OSS.
- Do **not** auto-update.
- Do **not** depend on Docker, Postgres, Redis, or any external service.
- Do **not** make the binary larger than ~20 MB.
- Do **not** add a "store anything" mode. Only secrets that map to presets
  get stored.
- Do **not** cripple the OSS version to drive paid upgrades. Paid features
  must be additive (hosted infrastructure, team coordination), never gates
  on local single-user functionality.
- Do **not** print to **stdout** in the MCP server. stdout is the JSON-RPC
  protocol channel. Logs go to stderr only. There is an integration test
  (`tests/mcp_integration.rs::stdout_contains_only_json`) that pins this.

## How to navigate this repo

- `src/secret.rs` — `Secret` newtype, the zeroize boundary.
- `src/keychain/` — `KeychainStore` trait + impls.
- `src/config.rs` — TOML schema, validation, `load_and_validate`.
- `src/audit/` — append-only event log.
- `src/approval/` — approval transports + sanitisation helpers.
- `src/presets/` — preset source abstraction.
- `src/executor/` — composition root for action execution.
- `src/mcp/` — `rmcp` server wiring + tool definitions.
- `src/cli/` — `clap` subcommands.
- `tests/` — CLI integration (`assert_cmd`) + MCP integration (raw stdio
  framing).

## Conventions

- **Commit messages**: Conventional Commits (`feat:`, `fix:`, `test:`,
  `refactor:`, `docs:`, `chore:`). Reference spec or invariant numbers in
  the body when implementing security-critical code.
- **One logical change per commit**.
- **Per-step quality gate**: `cargo fmt --check && cargo clippy
  --all-targets -- -D warnings && cargo test`. Never `--no-verify`.
- **TDD for executable code**. Setup-only tasks (scaffold, docs, CI) skip
  TDD.
- **Tool descriptions are pinned with `insta` snapshots** — they're
  user-facing security copy.

## Release scope

The first release of `mcp-warden mcp` ships the following MCP tools:

- `list_presets` — enumerate scoped actions.
- `proxy_http` — credential-injected HTTP request against an allow-listed
  base URL / method / path.
- `get_secret_for_env` — reveal a single secret to the agent on explicit
  approval (escape hatch for legacy CLI tools that read from env).
- `ssh_exec` — run a regex-allow-listed command on a host whose key is
  pinned in `~/.ssh/known_hosts`.
- `sftp_transfer` — get/put a file along an allow-listed path.
- `db_query` — execute a named query (Postgres, MySQL, Redis) defined in
  the preset.

The `ssh_exec` / `sftp_transfer` / `db_query` tools were originally tagged
Phase 2 and gated on explicit human sign-off; that sign-off has been given
and they are part of the first release. Time-boxed approval windows, the
TUI approval transport, and host-key verification ship with them.

Future, still-gated work (NOT in this release without renewed sign-off):
Homebrew tap and packaging, multi-IDE deep setup guides, `doctor`
expansion (auto-fix), and any hosted/closed-source paid features
described in `docs/open-core.md`.
