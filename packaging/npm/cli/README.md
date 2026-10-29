# @mcp-warden/cli

[mcp-warden](https://github.com/ermoluk/mcp-warden) — a local-first credential
broker for the Model Context Protocol — packaged for `npx`. Your agent calls
`proxy_http`, `ssh_exec`, `sftp_transfer` or `db_query`; mcp-warden checks the
request against the preset's allow-list, asks you when the preset says so,
injects the secret from the OS keychain and returns only the result.

```json
{
  "mcpServers": {
    "mcp-warden": { "command": "npx", "args": ["-y", "@mcp-warden/cli", "mcp"] }
  }
}
```

The same command manages presets and secrets: `npx @mcp-warden/cli init`,
`npx @mcp-warden/cli secret add NAME`.

The binary comes from an optional dependency for your platform
(`@mcp-warden/darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64`,
`win32-x64`). Nothing is downloaded at install or run time, and there is no
install script.

The unscoped `mcp-warden` package on npm is an unrelated project.

Documentation, security model and other ways to install:
https://github.com/ermoluk/mcp-warden
