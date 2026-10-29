#!/bin/sh
# Turn release binaries into the assets attached to a GitHub release:
#   mcp-warden-<target>.tar.gz  (.zip on Windows) + <archive>.sha256
#   mcp-warden-<target>.mcpb    Claude Desktop bundle (not for the -gnu build)
#   install.sh, install.ps1
#   SHA256SUMS                  every asset above except the .sha256 files
#
# Usage: packaging/package.sh VERSION BIN_DIR DIST_DIR
#   BIN_DIR has one directory per target triple holding `mcp-warden`
#   (`mcp-warden.exe` for Windows), as the release workflow downloads them.
#
# Archives are flat (`./mcp-warden`, `./README.md`, `./LICENSE`), the layout
# releases have always had; Homebrew, Scoop, winget, AUR, cargo-binstall,
# npm and the install scripts all rely on it.
set -eu

[ $# -eq 3 ] || { echo "usage: $0 VERSION BIN_DIR DIST_DIR" >&2; exit 2; }
version=$1
bins=$2
dist=$3
root=$(cd "$(dirname "$0")/.." && pwd)

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

# No AppleDouble `._*` entries in archives built on macOS.
COPYFILE_DISABLE=1
export COPYFILE_DISABLE

mkdir -p "$dist"
dist=$(cd "$dist" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

found=0
for dir in "$bins"/*/; do
	target=$(basename "$dir")
	case $target in
	*-windows-*) exe=mcp-warden.exe ;;
	*) exe=mcp-warden ;;
	esac
	if [ ! -f "$dir/$exe" ]; then
		echo "package.sh: $dir has no $exe" >&2
		exit 1
	fi
	found=$((found + 1))
	name="mcp-warden-$target"

	stage="$work/$target"
	mkdir -p "$stage"
	cp "$dir/$exe" "$stage/$exe"
	chmod 755 "$stage/$exe"
	cp "$root/README.md" "$root/LICENSE" "$stage/"
	case $target in
	*-windows-*)
		archive="$name.zip"
		(cd "$stage" && zip -q -X "$dist/$archive" "$exe" README.md LICENSE)
		;;
	*)
		archive="$name.tar.gz"
		tar -czf "$dist/$archive" -C "$stage" .
		;;
	esac
	(cd "$dist" && sha256 "$archive" >"$archive.sha256")

	# The -gnu build is kept for links to it; the static musl builds are
	# the Linux packages.
	case $target in
	*-linux-gnu) continue ;;
	*-apple-darwin) platform=darwin ;;
	*-windows-*) platform=win32 ;;
	*-linux-*) platform=linux ;;
	*)
		echo "package.sh: unknown platform for $target" >&2
		exit 1
		;;
	esac
	bundle="$work/mcpb-$target"
	mkdir -p "$bundle/server"
	cp "$dir/$exe" "$bundle/server/$exe"
	chmod 755 "$bundle/server/$exe"
	cp "$root/docs/brand/mcp-warden-icon.png" "$bundle/icon.png"
	cp "$root/LICENSE" "$bundle/LICENSE"
	sed -e "s|@VERSION@|$version|g" \
		-e "s|@PLATFORM@|$platform|g" \
		-e "s|@EXE@|$exe|g" \
		"$root/packaging/mcpb/manifest.json.in" >"$bundle/manifest.json"
	(cd "$bundle" && zip -q -X -r "$dist/$name.mcpb" manifest.json icon.png LICENSE server)
done
[ "$found" -gt 0 ] || { echo "package.sh: no binaries in $bins" >&2; exit 1; }

cp "$root/install.sh" "$root/install.ps1" "$dist/"
(
	cd "$dist"
	# shellcheck disable=SC2046 # asset names never contain spaces
	sha256 $(ls | grep -v -e '\.sha256$' -e '^SHA256SUMS$') >SHA256SUMS
)
echo "package.sh: $found target(s) packaged into $dist"
