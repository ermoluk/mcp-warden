#!/bin/sh
# SessionStart: if the mcp-warden binary is missing, tell Claude (stdout is
# added to the session context) so it can point the user at the install step.
# Silent when the binary is present. Never touches the keychain or config.
# Looks where .mcp.json does: PATH, then where installers put it (GUI apps on
# macOS don't get Homebrew's or ~/.local/bin on their PATH).
for b in "$(command -v mcp-warden)" "$HOME/.local/bin/mcp-warden" \
  /opt/homebrew/bin/mcp-warden /usr/local/bin/mcp-warden \
  "$HOME/.cargo/bin/mcp-warden" "$HOME/.nix-profile/bin/mcp-warden"; do
  if [ -n "$b" ] && [ -x "$b" ]; then
    exit 0
  fi
done
cat <<'MSG'
The mcp-warden Claude Code plugin is installed, but the mcp-warden binary was
not found, so its MCP server cannot start. If the user asks for anything that
needs credentials, tell them to install it first, for example:
  brew install ermoluk/tap/mcp-warden                       (macOS, Linux)
  winget install ermoluk.mcp-warden                         (Windows)
  curl -fsSL https://github.com/ermoluk/mcp-warden/releases/latest/download/install.sh | sh
  cargo install --locked mcp-warden                         (Rust toolchain)
All options: https://github.com/ermoluk/mcp-warden#install
then restart Claude Code and run /mcp-warden:setup.
MSG
