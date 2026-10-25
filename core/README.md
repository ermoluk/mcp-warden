# mcp-warden-core

Core traits and shared types for [mcp-warden](https://github.com/ermoluk/mcp-warden) —
a local-first credential broker that lets MCP-compatible AI agents act on your
services without ever seeing your secrets.

**Most users want the [`mcp-warden`](https://crates.io/crates/mcp-warden) binary,
not this crate.** Depend on `mcp-warden-core` only to write an alternate backend
without pulling in the binary's CLI / MCP / GUI stack.

| Trait               | Purpose                              | Built-in implementation          |
|---------------------|--------------------------------------|----------------------------------|
| `KeychainStore`     | Where secrets live                   | OS keychain                      |
| `ApprovalTransport` | How a human approves an action       | Desktop, TUI, Telegram (binary)  |
| `AuditSink`         | Append-only record of every action   | Local SQLite                     |
| `PresetSource`      | Where scoped presets come from       | TOML config                      |

Also here: `Secret` (zeroized on drop), `Config` / `Preset` with validation,
`WardenError`, and `config::anchored_regex` for allow-list patterns.

Implementations must uphold the project's
[security invariants](https://github.com/ermoluk/mcp-warden/blob/main/CLAUDE.md#security-invariants--non-negotiable) —
see [`docs/approval-transports.md`](https://github.com/ermoluk/mcp-warden/blob/main/docs/approval-transports.md)
for a worked `ApprovalTransport` example.

License: Apache-2.0.
