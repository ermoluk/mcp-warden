# mcp-warden plugin for Claude Code

Lets Claude Code call your APIs, run allow-listed SSH commands and query
databases with your credentials, without the credentials ever entering the
conversation. See the [main README](../../README.md) for how mcp-warden works.

## What's inside

| Part | What it does |
|------|--------------|
| MCP server (`.mcp.json`) | Starts `mcp-warden mcp` over stdio. Looks on `PATH`, then `~/.cargo/bin`. |
| Skill `using-mcp-warden` | Teaches Claude to discover presets first, call `proxy_http` / `ssh_exec` / `db_query` instead of asking for tokens, and respect approvals. |
| Command `/mcp-warden:setup` | Guided setup: install check, config, a first preset. The secret is stored by you in your own terminal, never through the chat. |
| `SessionStart` hook | If the `mcp-warden` binary is missing, tells Claude how to point you at the install. Silent otherwise. |

## Install

The plugin does not include the binary. Install it first:

```bash
cargo install --locked mcp-warden
```

or download a prebuilt binary from the [releases page](https://github.com/ermoluk/mcp-warden/releases). Then in Claude Code:

```
/plugin marketplace add ermoluk/mcp-warden
/plugin install mcp-warden@mcp-warden
```

Restart Claude Code and run `/mcp-warden:setup`.

If you added mcp-warden earlier with `claude mcp add`, remove that entry so the
server isn't registered twice:

```bash
claude mcp remove --scope user mcp-warden
```
