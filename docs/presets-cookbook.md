# Presets cookbook

Worked examples for each preset type. Copy → adjust → drop into `~/.config/mcp-warden/config.toml`. Validate with `mcp-warden preset test <name>`.

## HTTP — GitHub read-only

```toml
[[preset]]
name = "github-read"
type = "http"
description = "GitHub API (read-only)"
base_url = "https://api.github.com"
auth = { type = "bearer", secret = "gh_pat" }
allowed_methods = ["GET"]
approval = "auto"
```

```bash
mcp-warden secret add gh_pat
mcp-warden preset add github-read \
  --type http --base-url https://api.github.com \
  --auth-bearer gh_pat --allowed-methods GET \
  --approval auto --confirm-auto
```

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

When the agent triggers the first call, the TUI / desktop prompt offers a
third choice: **Approve for 10 min**. Subsequent `proxy_http` calls on
`linear-read` inside the window proceed without re-prompting and are
recorded with `decision = "windowed"` in `mcp-warden audit recent`.
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

## Patterns to AVOID

- **Wildcard SSH commands.** `^git.*$` lets the agent run `git rebase --continue || rm -rf /`. Always anchor the entire pattern with explicit alternations.
- **Open-ended SFTP allow-lists.** `sftp_allowed_paths = ["/"]` is a footgun. Pick the narrowest prefix that covers your use case.
- **Destructive named queries with `auto` approval.** `DELETE FROM users WHERE id = $1` paired with `approval = "auto"` lets the agent drop arbitrary rows. Use `prompt` (or `deny`) for any query that mutates.
- **Sharing a preset secret across types.** A preset's `secret` is read once per call; don't reuse the same keychain entry as both an SSH key and a DB password — rotate independently.
