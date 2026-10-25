# mcp-warden Web UI

A local-only, read-only web dashboard for browsing preset configuration and
audit log entries. Start it with:

```
mcp-warden web [--port N]   # default port 7077
```

The server binds exclusively to `127.0.0.1`. There is no flag to expose it on
any other address.

## Security model

- **Loopback-only bind.** `127.0.0.1` is hardcoded in `src/web/server.rs`.
  No authentication is needed precisely because only local processes can
  reach the socket.
- **No secrets exposed.** Preset detail pages show keychain entry *names*
  (e.g. `gh_pat`) but never the values. Audit summaries are redacted by the
  existing `audit::redact` path before they reach the database; the web UI
  applies no additional un-redaction.
- **Security headers on every response.**
  - `Content-Security-Policy: default-src 'self'`
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
- **HTML escaping.** All dynamic values from config or the database pass
  through `handlers::esc()` before interpolation into HTML. The helper escapes
  `&`, `<`, `>`, `"`, `'`.
- **No keychain access.** Config is loaded without secret validation so the
  OS keychain prompt is never triggered by browsing the web UI.

## Routes (MVP — all read-only)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Dashboard: preset count, audit events in last 24 h |
| `GET` | `/presets` | Table of all presets: name, kind, approval policy, description |
| `GET` | `/presets/:name` | Detail page for a single preset (no secret values) |
| `GET` | `/audit?limit=N` | Recent audit log entries (default 100, max 1000) |

## Next iterations

The following features are intentionally deferred from this MVP:

1. **Approval transport over WebSocket.** Allow the web UI to serve as an
   approval channel (`ApprovalTransport` impl) so users can approve/deny MCP
   tool calls from the browser. Requires a WebSocket endpoint, a CSRF or
   origin-check mechanism, and integration with the existing approval flow.

2. **Preset CRUD endpoints.** `POST /presets`, `PUT /presets/:name`,
   `DELETE /presets/:name` for managing presets from the UI. Requires TOML
   round-trip serialisation and careful handling of secret references (names
   only, never values).

3. **Audit log streaming.** Server-sent events (`GET /audit/stream`) so the
   audit table updates in real time without manual refresh.

4. **Dark theme.** A `prefers-color-scheme: dark` media query with a matching
   palette. Currently the UI is light-only.

5. **i18n.** Internationalisation support. Currently the UI is English-only.

6. **Authentication layer.** If the bind address were ever made configurable
   (e.g. for remote access over a VPN), a proper auth layer (token-based or
   mTLS) would need to precede all routes. This is a prerequisite for any
   non-loopback binding.
