#!/bin/sh
# Build the npm packages from a release's archives, ready for `npm publish`.
#
# Usage: packaging/npm/pack.sh VERSION ASSET_DIR OUT_DIR
#   ASSET_DIR holds the release archives and SHA256SUMS (packaging/package.sh
#   output, or `gh release download vVERSION`). Every archive is checked
#   against SHA256SUMS before its binary is used.
#
# Writes to OUT_DIR one tarball per platform package (@mcp-warden/darwin-arm64,
# darwin-x64, linux-arm64, linux-x64, win32-x64) and one for @mcp-warden/cli.
# Publish the platform packages first:
#   for f in OUT_DIR/mcp-warden-*-*.tgz; do npm publish "$f" --access public; done
#   npm publish OUT_DIR/mcp-warden-cli-VERSION.tgz --access public
# A platform whose archive is missing is skipped with a warning.
set -eu

[ $# -eq 3 ] || { echo "usage: $0 VERSION ASSET_DIR OUT_DIR" >&2; exit 2; }
version=${1#v}
assets=$(cd "$2" && pwd)
mkdir -p "$3"
out=$(cd "$3" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

packed=0
for spec in \
	darwin-arm64:darwin:arm64:aarch64-apple-darwin:tar.gz \
	darwin-x64:darwin:x64:x86_64-apple-darwin:tar.gz \
	linux-arm64:linux:arm64:aarch64-unknown-linux-musl:tar.gz \
	linux-x64:linux:x64:x86_64-unknown-linux-musl:tar.gz \
	win32-x64:win32:x64:x86_64-pc-windows-msvc:zip; do
	IFS=: read -r platform os cpu target ext <<SPEC
$spec
SPEC
	archive="mcp-warden-$target.$ext"
	if [ ! -f "$assets/$archive" ]; then
		echo "pack.sh: warning: no $archive, skipping @mcp-warden/$platform" >&2
		continue
	fi
	want=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1; exit }' "$assets/SHA256SUMS")
	got=$(sha256 "$assets/$archive")
	if [ -z "$want" ] || [ "$want" != "$got" ]; then
		echo "pack.sh: $archive does not match SHA256SUMS" >&2
		exit 1
	fi
	pkg="$work/$platform"
	mkdir -p "$pkg/bin" "$work/x-$platform"
	case $ext in
	zip) (cd "$work/x-$platform" && unzip -q "$assets/$archive") ;;
	*) tar -xzf "$assets/$archive" -C "$work/x-$platform" ;;
	esac
	exe=mcp-warden
	[ "$os" = win32 ] && exe=mcp-warden.exe
	cp "$work/x-$platform/$exe" "$pkg/bin/$exe"
	chmod 755 "$pkg/bin/$exe"
	cp "$root/LICENSE" "$pkg/"
	sed -e "s|@VERSION@|$version|g" -e "s|@NPM_PLATFORM@|$platform|g" \
		-e "s|@NPM_OS@|$os|g" -e "s|@NPM_CPU@|$cpu|g" \
		"$here/platform/package.json.in" >"$pkg/package.json"
	(cd "$pkg" && npm pack --silent --pack-destination "$out" >/dev/null)
	packed=$((packed + 1))
done

cli="$work/cli"
mkdir -p "$cli/bin"
cp "$here/cli/bin/mcp-warden.js" "$cli/bin/"
chmod 755 "$cli/bin/mcp-warden.js"
cp "$here/cli/README.md" "$root/LICENSE" "$cli/"
sed -e "s|@VERSION@|$version|g" "$here/cli/package.json.in" >"$cli/package.json"
(cd "$cli" && npm pack --silent --pack-destination "$out" >/dev/null)
echo "pack.sh: $packed platform package(s) and @mcp-warden/cli in $out"
