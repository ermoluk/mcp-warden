#!/bin/sh
# SessionStart: if the mcp-warden binary is missing, tell Claude (stdout is
# added to the session context) so it can point the user at the install step.
# Silent when the binary is present. Never touches the keychain or config.
if command -v mcp-warden >/dev/null 2>&1 || [ -x "$HOME/.cargo/bin/mcp-warden" ]; then
  exit 0
fi
cat <<'MSG'
The mcp-warden Claude Code plugin is installed, but the mcp-warden binary was
not found, so its MCP server cannot start. If the user asks for anything that
needs credentials, tell them to install it first:
  cargo install --locked mcp-warden
or download a prebuilt binary from https://github.com/ermoluk/mcp-warden/releases
then restart Claude Code and run /mcp-warden:setup.
MSG
