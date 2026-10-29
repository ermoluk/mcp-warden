#!/bin/sh
# Install mcp-warden from a GitHub release on macOS or Linux.
#
#   curl -fsSL https://github.com/ermoluk/mcp-warden/releases/latest/download/install.sh | sh
#
# Downloads the archive for this machine and the release's SHA256SUMS,
# refuses to install unless the checksum matches, and copies the binary into
# a directory you own. No sudo, no edits to your shell profile or PATH, and
# nothing that runs again later: to update, run it again.
#
# Environment:
#   MCP_WARDEN_VERSION       release to install, e.g. 0.5.3 (default: the latest)
#   MCP_WARDEN_INSTALL_DIR   where the binary goes (default: ~/.local/bin)
#   MCP_WARDEN_DOWNLOAD_URL  base URL of the release assets, for mirrors and
#                            tests (default: GitHub releases)
set -eu

repo=https://github.com/ermoluk/mcp-warden

say() { printf 'mcp-warden install: %s\n' "$*" >&2; }
die() { say "error: $*"; exit 1; }

detect_target() {
	os=$(uname -s)
	arch=$(uname -m)
	case $os in
	Darwin)
		# A shell running under Rosetta reports x86_64 on Apple silicon.
		if [ "$arch" = x86_64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null)" = 1 ]; then
			arch=arm64
		fi
		case $arch in
		arm64 | aarch64) echo aarch64-apple-darwin ;;
		x86_64) echo x86_64-apple-darwin ;;
		*) die "unsupported macOS architecture: $arch" ;;
		esac
		;;
	Linux)
		# Static musl builds: no glibc version requirement.
		case $arch in
		x86_64 | amd64) echo x86_64-unknown-linux-musl ;;
		aarch64 | arm64) echo aarch64-unknown-linux-musl ;;
		*) die "unsupported Linux architecture: $arch" ;;
		esac
		;;
	*) die "unsupported OS: $os (on Windows, use install.ps1)" ;;
	esac
}

fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	else
		die "need curl or wget"
	fi
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d' ' -f1
	else
		openssl dgst -sha256 -r "$1" | cut -d' ' -f1
	fi
}

main() {
	version=${MCP_WARDEN_VERSION:-}
	dir=${MCP_WARDEN_INSTALL_DIR:-$HOME/.local/bin}
	if [ -n "${MCP_WARDEN_DOWNLOAD_URL:-}" ]; then
		base=${MCP_WARDEN_DOWNLOAD_URL%/}
	elif [ -n "$version" ]; then
		base="$repo/releases/download/v${version#v}"
	else
		base="$repo/releases/latest/download"
	fi

	target=$(detect_target)
	archive="mcp-warden-$target.tar.gz"
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	trap 'exit 130' INT TERM

	say "downloading $archive from $base"
	fetch "$base/$archive" "$tmp/$archive"
	fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS"
	want=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/SHA256SUMS")
	[ -n "$want" ] || die "SHA256SUMS has no entry for $archive"
	got=$(sha256 "$tmp/$archive")
	[ "$want" = "$got" ] || die "checksum mismatch for $archive: expected $want, got $got"
	say "checksum ok"

	mkdir "$tmp/unpacked"
	tar -xzf "$tmp/$archive" -C "$tmp/unpacked"
	[ -f "$tmp/unpacked/mcp-warden" ] || die "$archive has no mcp-warden binary"
	mkdir -p "$dir"
	# Copy, then rename over the old binary, so a running server is never
	# replaced half-written.
	cp "$tmp/unpacked/mcp-warden" "$dir/.mcp-warden.new"
	chmod 755 "$dir/.mcp-warden.new"
	mv -f "$dir/.mcp-warden.new" "$dir/mcp-warden"
	say "installed $("$dir/mcp-warden" --version) to $dir/mcp-warden"

	case ":$PATH:" in
	*":$dir:"*) ;;
	*)
		say "$dir is not on your PATH; add it in your shell profile:"
		say "  export PATH=\"$dir:\$PATH\""
		;;
	esac
}

main "$@"
