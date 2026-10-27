# Finding and fixing plaintext keys

MCP clients usually take an API key the simplest way: pasted into the server's `env` in a JSON config file. That file is plaintext on disk. Your agent can read it; so can dotfile sync, a backup, or a screenshot. Three commands move those keys into the OS keychain:

```bash
mcp-warden scan      # 1. where are they?
mcp-warden import    # 2. move them to the keychain, rewire the client entries
                     # 3. restart your MCP clients — they now launch `mcp-warden run <name>`
```

## `mcp-warden scan`

Read-only. Nothing is written and nothing is sent anywhere.

| Client | File | What is read |
|---|---|---|
| Claude Code | `~/.claude.json` | `mcpServers` and `projects.*.mcpServers` only |
| Claude Code (project) | `.mcp.json` | `mcpServers` |
| Claude Desktop | `claude_desktop_config.json` in the platform config dir | `mcpServers` |
| Cursor | `~/.cursor/mcp.json`, `.cursor/mcp.json` | `mcpServers` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | `mcpServers` |
| VS Code | user `mcp.json`, `.vscode/mcp.json` | `servers` |
| Codex | `~/.codex/config.toml` | `[mcp_servers.*]` |
| — | `.env`, `.env.*` (not `.example` / `.sample` / `.template` / `.dist`) | every entry |

Project files are read from the current directory and from every `--path DIR`. `--no-home` skips the user-level files.

Inside each server it looks at `env`, `headers`, `args` and URL query parameters.
- **Known token formats** are reported with high confidence: GitHub, GitLab, Anthropic, OpenAI, Stripe, Slack, AWS, Google, Linear, Notion, npm, Hugging Face and DigitalOcean.
- **Long values under secret-sounding names** (`…TOKEN`, `…KEY`, `password`, `Authorization`, …) are reported with medium confidence.
- **Never reported:** placeholders (`${VAR}`, `<your-token>`, `xxxx…`), `op://` references, paths and plain URLs.

```
~/.claude.json (Claude Code)
  mcpServers.github.env.GITHUB_PERSONAL_ACCESS_TOKEN   GitHub token   ghp_…, 40 chars   importable

Found 1 plaintext secret in 1 of 3 files checked; 1 can be moved with `mcp-warden import`.
```

The output never contains the value — at most a token type's public prefix and its length — so it is safe for an agent to run `scan`. `--format json` prints the same findings for scripts. `--fail-on-findings` exits 1 when anything is found, which suits CI and pre-commit hooks.

## `mcp-warden import`

Moves what `scan` marks **importable** — keys in the `env` of a stdio server (one with a `command`) in a JSON config. For each such server:

1. Each key is stored in the keychain as `server/<name>/<VAR>` and read back to verify.
2. A `[[server]]` entry is added to the mcp-warden config with the server's original command and arguments.
3. The client entry is rewritten:
   - its `command` becomes the absolute path of `mcp-warden`, with `args` `["run", "<name>"]`;
   - the imported variables are removed from its `env`;
   - other keys, other env variables and key order are kept.

   The file is replaced atomically and keeps its permissions.

A failure part-way leaves a key in two places, never in none. No backup is written, because a backup would contain the plaintext.

`import` shows the plan (redacted) and asks before it changes anything:
- `--dry-run` only shows the plan;
- without a terminal, it needs `--yes`.

**Quit Claude Code and Claude Desktop first.** They rewrite their config files and can put the old entry back. Run `scan` again after restarting the clients.

**Rotate the keys you imported.** They sat in plaintext before.

What `import` does not touch:

| Where the key is | What to do |
|---|---|
| a server's `args` | if the server can read the key from an environment variable, move it to `env` and run `import` again |
| a remote server's `headers` / URL | `run` can't wrap remote servers; use the client's own secret input, if it has one |
| Codex `config.toml` | `mcp-warden server add`, then point the entry at `mcp-warden run <name>` by hand |
| `.env` files | tools read them directly; keep them out of the agent's reach, or move the key into a preset |

## Wrapping a server by hand: `server add` and `run`

```bash
mcp-warden server add github --env GITHUB_PERSONAL_ACCESS_TOKEN -- \
  npx -y @modelcontextprotocol/server-github
# Value for 'server/github/GITHUB_PERSONAL_ACCESS_TOKEN': ****
```

Then, in the client config:

```json
{ "mcpServers": { "github": { "command": "/Users/you/.cargo/bin/mcp-warden", "args": ["run", "github"] } } }
```

`mcp-warden run github` reads the server's keys from the keychain, records the launch in the audit log (command line only), and execs the server with the keys in its environment. The server's stdio passes straight through, and nothing else goes to stdout.

`run` refuses to start when:
- a key is missing;
- the name is unknown;
- mcp-warden is locked.

Other server commands: `server list` shows the wrapped servers, and `server remove <name>` deletes a server together with its keys.

**What `run` protects.** Keys are no longer in client config files. A wrapped server gets only keys stored for it (`server/<name>/<VAR>`), never a preset's secret: the config lists variable names, not keychain entries. The command is fixed in the config.

**What it doesn't.** Once handed to the server, the key is in that process's environment. Other processes running as you can read it, and so can whoever launches `mcp-warden run`, by influencing the environment. See [threat model R12](threat-model.md).
