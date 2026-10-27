# Wiring `mcp-warden` into Claude Code

Claude Code reads MCP server config from `~/.claude/mcp_config.json` (or via the `/mcp` slash command in newer versions).

## 1. Build / install `mcp-warden`

```bash
cargo install --locked --path .               # from this repo, or:
cargo install --locked mcp-warden             # once published to crates.io
```

Verify:

```bash
which mcp-warden
mcp-warden version    # should print the version
```

## 2. Add to Claude Code's MCP config

Use the official CLI — it edits `~/.claude.json` safely and validates the entry:

```bash
claude mcp add --scope user mcp-warden "$(which mcp-warden)" -- mcp
```

`--scope user` makes it available from any directory. Drop the flag for project-local install. Verify:

```bash
claude mcp list
# expected:  mcp-warden: /Users/<you>/.cargo/bin/mcp-warden mcp - ✓ Connected
```

To remove: `claude mcp remove mcp-warden`.

## 3. First-run setup

```bash
mcp-warden init
mcp-warden secret add gh_pat                  # paste a GitHub Personal Access Token
mcp-warden preset add github-read \
  --type http \
  --base-url https://api.github.com \
  --auth-bearer gh_pat \
  --allowed-methods GET \
  --allowed-paths /user/repos \
  --approval auto --confirm-auto
```

## 4. Restart Claude Code

The MCP config is loaded at startup. Quit and reopen.

## 5. Verify

In Claude Code, ask:

> "List the mcp-warden presets you have access to."

You should see Claude call the `list_presets` tool and return `github-read`. If not:

- Check stderr by running `mcp-warden mcp` manually in a terminal — invalid configs surface there.
- Run `mcp-warden doctor` for a config sanity check.
- Confirm the binary path in `mcp_config.json` is absolute and executable.

## 6. Try a real call

Ask: "via mcp-warden, list my GitHub repositories — call proxy_http with the github-read preset and path /user/repos."

The agent should call `proxy_http`. Because the preset is `auto`, no prompt fires; the request goes straight through, and your PAT was never visible to the agent. Verify with:

```bash
mcp-warden audit --last 5
```

## Troubleshooting

| Symptom                                          | Likely cause                                                                    |
|--------------------------------------------------|---------------------------------------------------------------------------------|
| "tool not found"                                 | Server didn't start; check stderr with manual `mcp-warden mcp` in a terminal    |
| Garbled output / agent confusion                 | A library logged to stdout — set `RUST_LOG=warn` and report a bug               |
| "approval timeout"                               | Nobody answered within 60 s. On macOS and Windows the prompt is a dialog titled "mcp-warden — approval requested" (look behind other windows); on Linux a desktop notification; with `[approval.telegram]`, a message in your chat (`mcp-warden approval telegram-test` checks that setup). |
| "approval prompt could not be shown"             | The approval transport failed (e.g. no desktop session). The action did not run and `mcp-warden audit` shows it as `failed`. Use Telegram where there is no desktop. |
| "preset references missing secret"               | Run `mcp-warden secret add <name>` for the missing secret name                  |
