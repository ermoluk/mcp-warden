# Wiring `mcp-warden` into Cursor

Cursor reads MCP server configuration from `~/.cursor/mcp.json` (path may vary by Cursor version — check `Settings → MCP`).

## 1. Install

```bash
cargo install --path .
which mcp-warden
```

## 2. Configure

Edit `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "mcp-warden": {
      "command": "/Users/<you>/.cargo/bin/mcp-warden",
      "args": ["mcp"]
    }
  }
}
```

## 3. First-run setup

(Same as Claude Code — see `docs/claude-code-setup.md` step 3.)

## 4. Restart Cursor

The MCP config is loaded at startup. Quit fully (`Cmd+Q` on macOS) and reopen.

## 5. Verify

In a Cursor chat, ask the agent to list mcp-warden presets. The MCP server output is visible in `Output → MCP` (View menu).

## Troubleshooting

The same caveats as Claude Code apply — see that guide's troubleshooting table. Approval prompts appear as a native dialog (macOS), a desktop notification (Linux) or a Telegram message — not in Cursor's MCP output panel.
