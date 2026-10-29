# Presets cookbook

Worked examples for each preset type. Copy → adjust → drop into your config file (`mcp-warden doctor` prints its path: `~/.config/mcp-warden/` on Linux, `~/Library/Application Support/io.mcp-warden.mcp-warden/` on macOS). Validate with `mcp-warden preset test <name>`.

## HTTP — GitHub read-only

```toml
[[preset]]
name = "github-read"
type = "http"
description = "GitHub API (read-only)"
base_url = "https://api.github.com"
auth = { type = "bearer", secret = "gh_pat" }
allowed_methods = ["GET"]
allowed_paths = ["/user/repos", "/repos/OWNER/[^/]+"]
approval = "auto"
```

```bash
mcp-warden secret add gh_pat
mcp-warden preset add github-read \
  --type http --base-url https://api.github.com \
  --auth-bearer gh_pat --allowed-methods GET \
  --allowed-paths '/user/repos,/repos/OWNER/[^/]+' \
  --approval auto --confirm-auto
```

Replace `OWNER` with your account or org. Without `allowed_paths`, every path under `base_url` is allowed: with a classic PAT and `approval = "auto"` the agent could read every private repo the token can see, without a prompt — so keep `auto` only on narrowed presets (the built-in `github-read` template ships with `approval = "prompt"` because it has no paths) and prefer a fine-grained PAT limited to specific repositories — `mcp-warden doctor` warns about every HTTP preset without `allowed_paths`.

Each `allowed_paths` entry must match the whole path, as an exact string or a regex anchored as `^(?:…)$` — never as a prefix, so `/repos/` allows only `/repos/` itself — and `[^/]+` is safer than `.*` for one path segment, because `.*` also matches `/` and reaches everything below.

Patterns are matched against the percent-decoded path; the request still goes out with the path exactly as the agent sent it. `%2F` therefore counts as a separator: `/repos/OWNER/[^/]+` does not let `/repos/OWNER/x%2Fcollaborators` through, and a GitLab-style namespaced id like `/projects/group%2Fproject` needs `/projects/[^/]+/[^/]+` (one more `/[^/]+` per nested subgroup level). Paths with an empty segment (`//`), or that decode to invalid UTF-8, control characters, `\` or `.` / `..` segments, are always refused.

## HTTP — Stripe write (prompt per call)

```toml
[[preset]]
name = "stripe-write"
type = "http"
description = "Stripe API — create customers/charges"
base_url = "https://api.stripe.com/v1"
auth = { type = "bearer", secret = "stripe_key" }
allowed_paths = ["/customers", "/charges", "/refunds"]
allowed_methods = ["GET", "POST"]
approval = "prompt"
```

## HTTP — chatty read API with time-boxed approval

```toml
[[preset]]
name = "linear-read"
type = "http"
description = "Linear API (read-only). One approve covers ~10 min of follow-up reads."
base_url = "https://api.linear.app"
auth = { type = "header", secret = "linear_key", name = "Authorization" }
allowed_methods = ["POST"]   # GraphQL
allowed_paths = ["/graphql"]
approval = "prompt"
approval_window_seconds = 600
```

When the agent triggers the first call, the approval prompt offers a
third choice: **Approve for 10 min: every proxy_http call linear-read allows
runs without asking until 14:32** (the time the window ends, fixed when the
prompt appears). Subsequent `proxy_http` calls on `linear-read` inside the
window proceed without re-prompting and are recorded with
`decision = "windowed"` — `mcp-warden audit --decision windowed` lists them.
Restart `mcp-warden mcp` to clear all active windows.

Set or change the cap from the CLI:

```bash
mcp-warden approval linear-read prompt --window 600   # set 10 min
mcp-warden approval linear-read prompt --window 0     # disable windowing
```

Windows are per `(preset, action_type)`: an approve-for-window on
`proxy_http` does **not** cover `ssh_exec` on the same preset, and
`get_secret_for_env` is *never* windowed (it always re-prompts).

## SSH — Production deploy

```toml
[[preset]]
name = "deploy-prod"
type = "ssh"
description = "Production deploy host"
host = "deploy.example.com"
user = "deploy"
port = 22
secret = "prod_ssh_key"
allowed_commands = [
  "^docker compose (pull|up -d|ps|logs --tail \\d+)$",
  "^git pull$",
  "^systemctl status [a-z0-9_-]+$",
]
approval = "prompt"
timeout_seconds = 300
```

The remote shell runs the command, so `ssh_exec` refuses shell syntax whatever
the patterns say: words are separated by single spaces and may contain only
letters, digits and `- _ . / : = @ , + %`. Quotes, `$`, backticks, globs and
redirections never reach the host, so don't write patterns that need them.
Still keep each argument tight (`[a-z0-9_-]+`, `\d+`) — a loose `.*` lets
the agent add options of its own.

## SSH + SFTP — Log fetcher

```toml
[[preset]]
name = "logs-readonly"
type = "ssh"
description = "Pull rotated logs from prod"
host = "logs.example.com"
user = "logreader"
secret = "logs_ssh_key"
allowed_commands = [
  "^ls /var/log/app/$",
  "^tail -n [0-9]+ /var/log/app/[a-z0-9._-]+$",
]
allow_sftp = true
sftp_allowed_paths = ["/var/log/app/"]
approval = "auto"
```

```bash
# Agent can now: ssh_exec "ls /var/log/app/"
#               sftp_transfer get /var/log/app/today.log /tmp/today.log
```

## PostgreSQL — Read-only analytics

```toml
[[preset]]
name = "analytics-readonly"
type = "postgres"
description = "Read-only analytics queries"
host = "db.example.com"
user = "analytics_ro"
port = 5432
database = "analytics"
secret = "analytics_pg_password"
approval = "auto"

  [[preset.queries]]
  name = "find_user"
  template = "SELECT id, email, created_at FROM users WHERE id = $1"
  param_types = ["int8"]
  readonly = true

  [[preset.queries]]
  name = "signups_by_day"
  template = "SELECT date_trunc('day', created_at) AS day, count(*) FROM users WHERE created_at >= $1 GROUP BY day ORDER BY day DESC"
  param_types = ["text"]
  readonly = true
```

```bash
mcp-warden secret add analytics_pg_password
mcp-warden preset add analytics-readonly \
  --type postgres --host db.example.com --port 5432 \
  --user analytics_ro --secret analytics_pg_password --database analytics \
  --approval auto --confirm-auto
mcp-warden preset add-query analytics-readonly find_user \
  --template "SELECT id, email FROM users WHERE id = \$1" \
  --param-types int8 --readonly
```

## Redis — Cache ops

```toml
[[preset]]
name = "cache-ops"
type = "redis"
description = "Read keys; flush is locked behind prompt"
host = "cache.example.com"
port = 6379
user = "default"
secret = "redis_password"
approval = "prompt"

  [[preset.queries]]
  name = "get"
  template = "GET"
  param_types = ["text"]

  [[preset.queries]]
  name = "set"
  template = "SET"
  param_types = ["text", "text"]

  [[preset.queries]]
  name = "incr"
  template = "INCR"
  param_types = ["text"]
```

The Redis `template` is the command name; `param_types` is the positional arg schema.

## HTTP — limit what the agent sees

A list endpoint can return megabytes, and most of it is noise in the agent's context — or text written by strangers (issue bodies, comments) that can try to steer it. Cap the size and keep only the fields the task needs:

```toml
[[preset]]
name = "gh-issues"
type = "http"
description = "Issue titles and states for one repo"
base_url = "https://api.github.com"
auth = { type = "bearer", secret = "gh_pat" }
allowed_methods = ["GET"]
allowed_paths = ["/repos/OWNER/REPO/issues"]
approval = "auto"
max_response_bytes = 200000
response_fields = ["[].number", "[].title", "[].state", "[].user.login"]
```

- **Too large.** A body larger than `max_response_bytes` is not returned. The agent gets the status, `body: null` and a `notice`.
- **Field paths.** Keys are separated by `.`, and `[]` means "every element": `items[].title`. A leading `[]` addresses a top-level array.
- **CLI.** The same flags exist: `preset add … --max-response-bytes 200000 --response-fields '[].number,[].title'`.

## More templates

`mcp-warden preset scaffold --list` shows every built-in template. All of these are `prompt`, with allow-lists that keep secret-bearing endpoints out of reach:

| Template | What it reaches | Notes |
|---|---|---|
| `gitlab-read` | user, projects by **numeric** id, issues, MRs, tree, commits | A looser pattern would also reach `/projects/:id/variables` (CI secrets) |
| `linear` | `POST /graphql` | GraphQL carries mutations too, so every call prompts |
| `jira-read` | myself, `search/jql`, issues and comments, projects | Basic auth with your account e-mail; set `MCP_WARDEN_JIRA_BASE_URL` / `MCP_WARDEN_JIRA_EMAIL` before scaffolding, or edit afterwards |
| `slack-read` | `auth.test`, `conversations.*` reads, `users.list` / `users.info` | Bot token (`xoxb-…`) |
| `vercel-read` | user, projects, deployments | Not `/v9/projects/:id/env`, which returns a project's secrets |

## Patterns to AVOID

- **Wildcard SSH commands.** `^git.*$` lets the agent run `git rebase --continue || rm -rf /`. Always anchor the entire pattern with explicit alternations.
- **Open-ended SFTP allow-lists.** `sftp_allowed_paths = ["/"]` is a footgun. Pick the narrowest prefix that covers your use case.
- **Destructive named queries with `auto` approval.** `DELETE FROM users WHERE id = $1` paired with `approval = "auto"` lets the agent drop arbitrary rows. Use `prompt` (or `deny`) for any query that mutates.
- **Sharing a preset secret across types.** A preset's `secret` is read once per call; don't reuse the same keychain entry as both an SSH key and a DB password — rotate independently.
