---
description: Set up mcp-warden — install check, config, a first preset, and storing its secret without it ever entering this chat
argument-hint: "[service, e.g. github, stripe, ssh to prod]"
---

Walk the user through setting up mcp-warden so you can use their credentials
without ever seeing them. Service they asked about, if any: $ARGUMENTS

Work through these steps in order. Run the commands yourself unless a step says
the user must do it. Keep the user informed in one line per step.

## 1. Binary

Run `mcp-warden --version` (fall back to `~/.cargo/bin/mcp-warden --version`).

If it is missing, tell the user the two ways to install it and ask which they
want before running anything:

- `cargo install --locked mcp-warden` (needs a Rust toolchain)
- a prebuilt binary for macOS or Linux from https://github.com/ermoluk/mcp-warden/releases

## 2. Config

Run `mcp-warden doctor`. If it reports no config file, run `mcp-warden init`.
`doctor` prints where the config lives; use that path, not a guessed one.

## 3. Pick a preset

Run `mcp-warden preset list` to see what already exists, then
`mcp-warden preset scaffold --list` for built-in templates.

- If a template fits the service, run `mcp-warden preset scaffold <template>`.
  Note the secret name it binds (shown in `--list` as "default secret").
- Otherwise build `mcp-warden preset add <name> ...` with the narrowest
  allow-list that does the job: only the methods and paths (HTTP), commands
  (SSH, anchored regexes) or named queries (databases) the user actually needs.
  Run `mcp-warden preset add --help` for the flags.

Approval policy: keep the default `prompt`. Use `auto` only if the user asks for
it explicitly, and then it needs `--confirm-auto`. Say plainly that `auto` means
calls run without asking them.

## 4. Store the secret — the user does this, not you

Never ask the user to paste a token, key or password into this chat, and never
pipe a secret value into a command yourself. Tell the user to run this in their
own terminal (not through you) and paste the value when it prompts:

```
mcp-warden secret add <secret-name>
```

Wait until they confirm it is done.

## 5. Verify

Run `mcp-warden preset test <name>` and `mcp-warden doctor`. Fix anything they
report before going on.

## 6. Reload

mcp-warden loads its config once at startup, so new presets need a fresh MCP
server. Ask the user to restart Claude Code (or reconnect the server from
`/mcp`). Then call `list_presets` to confirm the preset is visible, and offer a
first safe call through it — for example a read-only request.
