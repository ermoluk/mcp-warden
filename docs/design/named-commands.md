# Design: named commands for SSH presets

Status: proposal (written for 0.5.3, not implemented). Nothing in this document
changes behaviour until it is built and released.

## Problem

An SSH preset allows commands with `allowed_commands`: anchored regexes over the
whole command string. Since 0.5.2 a per-word filter refuses shell syntax first,
so `git checkout \S+` can no longer smuggle `$(…)`. Three problems remain:

- **Patterns are hard to get right.** One regex has to describe both the
  command and every argument, and a loose one (`git pull.*`) still admits extra
  options made of permitted characters: `git pull --upload-pack=/tmp/x`
  (threat model R4).
- **The agent composes the command.** It has to guess the exact string the
  pattern expects, and a refusal says "not allowed" without saying which part
  of the string was wrong.
- **The surface is invisible.** `list_presets` can show the patterns, but
  nothing tells the agent, or a reviewer, what each one is for.

`db_query` already solved the same problem for SQL: the preset declares named
queries with a fixed template and typed parameters, and the agent sends only
the name and the values. Named commands apply that to SSH.

## Configuration

```toml
[[preset]]
name = "deploy"
type = "ssh"
description = "Production deploy host"
host = "deploy.example.com"
user = "warden-deploy"
secret = "deploy_key"
approval = "prompt"

[[preset.commands]]
name = "trash_file"
description = "Move one uploaded file to the trash folder"
template = "mv {path} /srv/app/.trash/"
params.path = { type = "path", pattern = "/srv/app/uploads/[a-z0-9._-]+" }

[[preset.commands]]
name = "restart"
description = "Restart one of the app's services"
template = "sudo -n systemctl restart {unit}"
params.unit = { type = "enum", values = ["app.service", "worker.service"] }

[[preset.commands]]
name = "tail_log"
description = "Last N lines of the app log"
template = "journalctl -u app -n {lines} --no-pager"
params.lines = { type = "int", min = 1, max = 500 }
```

- `name` — `[a-z][a-z0-9_]{0,31}`, unique within the preset.
- `description` — shown to the agent: in `list_presets`, and as the tool
  description if the command becomes a tool (below).
- `template` — words separated by single spaces. A word is either literal text
  or exactly one placeholder `{param}`. In this first version a placeholder
  can't share a word with literal text (`--lines={n}` is an open question).
- `params.<name>` — one entry per placeholder:

| `type` | Required | Accepts |
|---|---|---|
| `string` | `pattern` | one word matching the anchored pattern |
| `path` | `pattern` | an absolute path matching the pattern, with no `.` / `..` segment and no `//` |
| `int` | `min`, `max` | a decimal integer in range, no sign or leading zeros |
| `enum` | `values` | exactly one of the listed words |

- `allowed_commands` stays. A preset may have both: `ssh_exec` keeps using
  `allowed_commands`, and named commands are run as described below. The docs
  will recommend named commands for anything with an argument.
- `expose_as_tools` (preset level, default `false`) — also offer each named
  command as an MCP tool of its own. See [Tools](#tools-built-from-the-frozen-config).

## Validation at startup

Templates are parsed and checked when the MCP server loads the config, with the
other checks of `load_and_validate`. One bad command refuses the whole start,
loudly, naming the preset and the command (invariant 10). The checks:

1. Every literal word passes `check_words`, the same per-word character
   allow-list `ssh_exec` applies (letters, digits, `- _ . / : = @ , + %`, no
   leading `=`).
2. Every placeholder is a whole word and names a declared parameter, and every
   declared parameter is used exactly once.
3. Each `pattern` compiles with `anchored_regex` (`^(?:…)$`). An `enum` value
   must itself pass `check_words`. For `int`, `min` ≤ `max`.
4. Command names are unique within the preset, and the tool names they would
   generate are unique across the config and fit the tool-name rules below.
5. The template's longest possible expansion fits `MAX_SSH_COMMAND_BYTES`. A
   value can't exceed its own limit (below), so this can be computed up front.

The parsed commands are frozen with the rest of the presets; editing them takes
a restart, as for every other preset field.

## Running a named command

A new tool, `ssh_run { preset_name, command, params: { name: value } }`, does
the following. Each step happens before the next and before any credential is
read (invariant 3):

1. **Limits.** At most 16 parameters, each value at most 256 bytes. These are
   new constants in `executor/limits.rs`.
2. **Lookup.** The preset exists and is an SSH preset, the command exists, and
   the parameters given are exactly the declared ones. Each refusal is audited
   as `refused`, as today.
3. **Each value**:
   - checked against its type (and pattern / range / values);
   - must pass `check_words` and be a single word: no spaces;
   - must not start with `-`, unless its pattern can only match a leading `-`.
     This is the option-injection defence: `{path}` can't become `--help` or
     `-rf`.
4. **Substitution.** The template's placeholders are replaced, and the whole
   command is checked once more with `check_words` and the length limit
   (belt and braces).
5. **Authorisation.** The same `authorise` path as `ssh_exec`.
   - The approval prompt shows the command name, each parameter and the final
     command.
   - The audit summary is `ssh <host> -- <final command>`, with the command name
     in front: `deploy.trash_file: ssh h -- mv /srv/app/uploads/a.png /srv/app/.trash/`.
6. **Execution.** Unchanged: the `russh` exec channel. The remote login shell
   still parses the string. It can't find any syntax in it: literal words and
   values come from the same character set, and each value is one word
   (invariant 5).

`mcp-warden preset test deploy --run trash_file --param path=/srv/app/uploads/a.png`
runs steps 1–4 and reports the verdict, through the same policy function as the
server. The hostile-input corpus gains a file of `(command, params)` cases.

## Tools built from the frozen config

With `expose_as_tools = true`, each command also becomes a tool of its own,
`ssh_<preset>_<command>`. Its input schema lists the parameters with their
type, pattern, range or enum values, and its description is the command's
`description` plus a fixed sentence: the command runs on `<host>` as `<user>`
after the preset's approval policy.

- **Built at startup, never later.** The tool list is computed once from the
  config validated at startup and does not change while the process runs.
  Today's tools come from `rmcp`'s `#[tool_router]` macros, which are static,
  so the generated tools need hand-written `list_tools` / `call_tool` entries
  that merge them with the static router. A generated tool calls the same code
  as `ssh_run`.
- **Names.** MCP clients commonly accept `^[a-zA-Z0-9_-]{1,64}$`. Preset names
  are free text today, so a preset whose generated tool name wouldn't fit is
  refused at startup if it has `expose_as_tools = true`.
- **Descriptions are configuration, not secrets.** They come from the preset
  author, like `list_presets` output today, and never include a secret or a
  secret's name (invariant 2). The generator is pinned with an `insta` snapshot
  over a fixture config, since user-specific descriptions can't be.
- **A cap.** At most 32 generated tools across all presets. Beyond that the
  server refuses to start and suggests `ssh_run`, so a big config can't flood
  the agent's context with schemas.

## How this fits the invariants

| Invariant | |
|---|---|
| 2 — no secrets in tool descriptions or errors | Descriptions and schemas come from command metadata only; errors name the parameter and the rule it broke, not the secret or the host key. |
| 3 — allow-lists before credential injection | Steps 1–4 happen before `authorise` and the keychain read. |
| 4 — `prompt` by default | Named commands inherit the preset's policy; `auto` still needs `--confirm-auto`. |
| 5 — SSH: exec channel, strict per-argument character class, no `sh -c` | Per-argument validation is the whole point: typed values, one word each, the same character class, no leading `-`. The exec channel is unchanged. |
| 7 — append-only audit | No new write paths; summaries carry the command name. |
| 10 — refuse to start, load once and freeze | Templates and parameters are validated at startup; invalid ones stop the server; generated tools are built from the frozen config. |

## Risks

- **The template is still trusted.** `rm -rf {path}` with a loose pattern is as
  dangerous as a loose regex today. As with named queries (threat model R7),
  each command is a public API, and the docs must say so. The startup check
  can warn about known destructive verbs (`rm`, `dd`, `mkfs`, `chmod -R`) in
  templates.
- **Paths are checked as text.** We can check that `{path}` matches
  `/srv/app/uploads/…`, but not where a symlink on the server leads. The server
  side still needs a dedicated account, or a gate script and chroot
  (`docs/ssh-hardening.md`).
- **The tool list costs context.** Every generated schema is sent to the agent;
  hence the opt-in and the cap.
- **Window granularity.** Today an approval window covers `(preset, ssh_exec)`.
  Should one approved `restart` also cover `trash_file`? Probably not; see the
  open questions.
- **Two ways to do one thing.** `allowed_commands` and named commands side by
  side may confuse preset authors. Docs and `preset scaffold` should steer to
  named commands, and `doctor` could flag `allowed_commands` patterns with
  `.*` or `\S+`.

## Open questions

1. Placeholders inside a word (`--lines={n}`, `user@{host}:{path}`): useful,
   but they complicate the "one value = one word" argument. Allow them only for
   `int` and `enum`?
2. `ssh_run` only, per-command tools only, or both behind `expose_as_tools` as
   proposed?
3. Approval-window key: `(preset, ssh_run)`, `(preset, command)` or per tool?
   Per command is the most precise, and the window button text (0.5.3) would
   say so.
4. A per-command `approval` that overrides the preset's, so `tail_log` can be
   `auto` while `restart` prompts? It would need its own `--confirm-auto` path.
5. More types: a git ref (`refname` rules), a hostname, a duration?
6. Should `sftp_transfer` get the same treatment: named transfers with a typed
   file-name parameter instead of free remote paths?
7. Output: `ssh_exec` output is not scrubbed (threat model N3). Named commands
   could declare `max_output_bytes`. Separate design?
