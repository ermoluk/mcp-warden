---
name: using-mcp-warden
description: Use when about to make any external HTTP API call, run a deploy command, or read a credential — invokes the `mcp-warden` MCP server (a local credential broker) so secrets never touch the conversation. Fires on requests like "call the GitHub API", "deploy via SSH", "use my Stripe key", "что в моём GitHub", "проверь репозитории", "make an API call", "fetch from {service}", or any task that would otherwise need a token/key. Skip only if mcp-warden is not in the connected MCP servers list.
---

# Using mcp-warden

`mcp-warden` is a local credential broker connected as an MCP server. The user has stored their secrets (GitHub PATs, API keys, SSH keys) in their OS keychain via `mcp-warden secret add`, and defined **presets** — named, scoped actions you may invoke. You call the high-level tool (`proxy_http`); `mcp-warden` injects the credential server-side, executes, and returns only the result. **You never see the credential.**

## The rule

When the user asks for anything that involves an external service:

1. **First call `list_presets`.** Don't guess preset names from memory. Don't ask the user to paste a token. Don't suggest editing `.env` files.
2. **If a relevant preset exists**, call `proxy_http` with that preset name. The preset selects base URL + auth.
3. **If no preset matches**, tell the user which preset to create — give them the exact `mcp-warden preset add` command. Do not fall back to asking for credentials.

## Discovery — always start here

```
tool: list_presets
```

Returns presets with `name`, `description`, `kind` (http/ssh), `approval` (auto/prompt/deny). If the list is empty, the user hasn't configured any preset yet — see "Setup" below.

## Calling proxy_http

```
tool: proxy_http
args:
  preset_name: "github-read"
  path: "/user/repos"
  method: "GET"
  query: { "per_page": "10" }
```

Constraints (server-validates BEFORE injecting the credential):

- `path` must be **relative** (start with `/`), no `..`, no `://`. The full URL is `<preset.base_url> + path`.
- `method` must be in the preset's `allowed_methods`.
- If the preset has `allowed_paths`, your path must match one of them (exact string or regex).
- `body` is optional, JSON-only.
- `query` is optional, string→string map.

Response: `{ status: u16, body: <json> }`.

## Approval expectations

Each preset has one of three policies:
- `auto` — proxy_http runs without prompting. Audit log records `auto`.
- `prompt` — asks the user: a native dialog on macOS, a desktop notification on Linux, or a Telegram message if configured. The user clicks Approve or Deny; an unanswered prompt times out after about a minute. **Wait for the result; do not retry.**
- `deny` — always returns an error. The user has explicitly disabled this preset.

If you receive **"approval denied"**, **"approval timeout"** or **"approval prompt could not be shown"** from `proxy_http`, **do not retry**. Tell the user the preset was denied and ask whether they want to change the policy (`mcp-warden approval <preset> prompt --confirm-auto` or similar) or pick a different preset.

## Other protocols (v0.2.0+)

`mcp-warden` also exposes three more tools beyond `proxy_http`:

### `ssh_exec` — run a shell command on a remote host

```
tool: ssh_exec
args: { preset_name: "deploy-prod", command: "docker compose ps" }
```

The command MUST match one of the preset's `allowed_commands` regex entries (anchored `^...$`). The server validates this BEFORE reading the SSH key. Returns `{stdout, stderr, exit_code}`. Auth is key-only; host key is verified against `~/.ssh/known_hosts`. **Do not** try to inject `;`, `&&`, `$()`, backticks — the validator rejects anything outside the allow-list. If the command you need isn't allowed, tell the user the exact `^pattern$` they'd need to add to the preset.

### `sftp_transfer` — get/put a file

```
tool: sftp_transfer
args: { preset_name: "logs-readonly", direction: "get",
         remote: "/var/log/app/today.log", local: "/tmp/today.log" }
```

`direction` is `"get"` (download) or `"put"` (upload). The remote path must start with one of the preset's `sftp_allowed_paths` prefixes; the local path must be under `$HOME` or `/tmp/`. Reject relative paths and `..` traversal. The preset must have `allow_sftp = true`. Reuses the SSH key from the same preset.

### `db_query` — run a NAMED QUERY against PostgreSQL / MySQL / Redis

```
tool: db_query
args: { preset_name: "analytics-readonly",
         query_name: "find_user", params: [42] }
```

**You cannot send arbitrary SQL.** The preset declares query templates (`SELECT * FROM users WHERE id = $1`) and the agent supplies only the `query_name` and positional params. For Redis, the template is the command name (`GET`, `LPUSH`, `INCR`). The server validates the param count and types before reading the password. If the query you need doesn't exist, tell the user how to add it: `mcp-warden preset add-query <preset> <name> --template "..." --param-types int8,text`.

## When to use `get_secret_for_env`

**Last-resort tool.** Reveals the raw secret value to you. Use ONLY when:

- You're about to spawn a child process (e.g., `terraform apply`, `docker login`, `gh auth login`) that reads the secret from an environment variable, AND
- There is no equivalent `proxy_http` preset that does the same job, AND
- The user has explicitly asked you to run that child process.

It always prompts for approval, regardless of preset policy. The returned value **MUST NOT** be quoted back into your reasoning trace, the chat, or any tool description. After using it, treat it as if it never existed.

Prefer `proxy_http` whenever the action is "talk to an HTTP API". Most "give me a token" requests are actually "make this API call for me" in disguise.

## Failure modes

| Error from proxy_http             | What it means                                             | What to do                                                     |
|-----------------------------------|-----------------------------------------------------------|----------------------------------------------------------------|
| `preset 'X' not found`            | The preset isn't defined                                  | Run `list_presets` again; if still missing, suggest setup      |
| `method 'X' not in ... allow-list`| The preset forbids this HTTP method                       | Pick a different method or different preset; do not retry as-is|
| `path 'X' not allowed by preset`  | The preset's `allowed_paths` regex didn't match           | Look at `list_presets` description; either pick another preset or tell the user they need to broaden `allowed_paths` |
| `path '...' must be relative`     | You passed a full URL or a path with `..` / `://`         | Rewrite the path as relative to `base_url`                     |
| `preset references missing secret`| Config drift — secret was deleted from keychain           | Tell the user to run `mcp-warden secret add <name>`            |
| `approval denied`                 | User clicked Deny / typed `n`                             | Stop. Don't retry. Ask the user what to do.                    |
| `approval timeout`                | User didn't respond within ~60s                           | Ask the user once if they want to try again; don't loop        |

## What NOT to do

- **Do not** ask the user to paste a token / key / password in chat.
- **Do not** suggest writing credentials to `.env`, `~/.netrc`, `~/.aws/credentials`, etc., as a "workaround" for a missing preset.
- **Do not** retry a denied call with a different preset to "see if that one is allowed".
- **Do not** include any value returned by `get_secret_for_env` in your reasoning, chat output, or any subsequent tool call other than the immediate child-process spawn it was authorised for.
- **Do not** call `proxy_http` against the same path repeatedly to defeat allow-list (the validator runs every call; it won't get tired).
- **Do not** assume preset names from past sessions — `list_presets` is cheap, call it.

## Setup (when mcp-warden has zero presets)

The user runs `mcp-warden init` once, then for each service:

```bash
# 1. Store the secret in the OS keychain (value is read from stdin, never argv).
mcp-warden secret add <secret_name>

# 2. Define a preset.
mcp-warden preset add <preset_name> \
  --type http \
  --base-url https://api.example.com \
  --auth-bearer <secret_name> \
  --allowed-methods GET,POST \
  --allowed-paths /resource,/resource/[a-z0-9-]+ \
  --approval prompt
```

If the user wants `auto`-approval (no prompt), they must add `--confirm-auto` to the preset add command. Without it, the CLI rejects `auto` policy as a guard against drive-by config edits.

Tell them to restart Claude Code after editing presets — the MCP server loads-once-and-freezes config at startup (TOCTOU defence).

## Useful CLI commands the user can run

| Goal                            | Command                                                   |
|---------------------------------|-----------------------------------------------------------|
| See what's configured           | `mcp-warden doctor`                                       |
| Read what was just done         | `mcp-warden audit --last 10`                              |
| List presets                    | `mcp-warden preset list`                                  |
| Validate a preset's secret link | `mcp-warden preset test <name>`                           |
| Change approval policy          | `mcp-warden approval <preset> prompt`                     |
| Lock a preset down              | `mcp-warden approval <preset> deny`                       |

## Self-check before each call

Before calling `proxy_http`, mentally answer:

1. Did I see this preset in the most recent `list_presets` output? *(If no — call it.)*
2. Is the method I'm using in that preset's `allowed_methods`?
3. Does my path start with `/`, and lack `..`, `://`, `%2e`, `\` and `.` segments?
4. Is the user's intent actually "make an HTTP call", not "show me my key"? *(If show-me-the-key — strongly prefer doing the API call yourself instead.)*

If all four are yes, proceed. If any is no, fix it BEFORE the tool call.

## Why this matters

The user installed `mcp-warden` because they don't want secrets in your context. Every time you ask them to paste a token, you defeat the design. Every time you successfully use `proxy_http` instead, you prove the design works — which is also what makes them keep using you for sensitive work.

Trust the broker. Use the broker.

---

## Installation (for skill consumers)

This skill ships in the `mcp-warden` Claude Code plugin, together with the MCP
server config and a `/mcp-warden:setup` command:

```
/plugin marketplace add ermoluk/mcp-warden
/plugin install mcp-warden@mcp-warden
```

To use the skill alone, copy this directory to `~/.claude/skills/using-mcp-warden`.
