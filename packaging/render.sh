#!/bin/sh
# Render the package-manager manifests for a release from its SHA256SUMS.
#
# Usage: packaging/render.sh VERSION SHA256SUMS [OUT_DIR] [--server-json]
#   OUT_DIR defaults to packaging/dist/VERSION and receives:
#     homebrew/mcp-warden.rb                               ermoluk/homebrew-tap, Formula/
#     scoop/mcp-warden.json                                ermoluk/scoop-bucket, bucket/
#     winget/manifests/e/ermoluk/mcp-warden/VERSION/*.yaml PR to microsoft/winget-pkgs
#     aur/PKGBUILD, aur/.SRCINFO                           the mcp-warden-bin AUR repo
#     server.json                                          MCP Registry
#   --server-json also writes server.json over the repository's own copy, which
#   `mcp-publisher publish` reads.
#
# Get SHA256SUMS from the release (`gh release download vVERSION -p SHA256SUMS`)
# or from packaging/package.sh. Every placeholder must resolve, and every hash
# must look like one, or nothing is written.
set -eu

usage() { echo "usage: $0 VERSION SHA256SUMS [OUT_DIR] [--server-json]" >&2; exit 2; }
[ $# -ge 2 ] || usage
version=${1#v}
sums=$2
shift 2
root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/packaging/dist/$version"
write_server_json=0
for arg in "$@"; do
	case $arg in
	--server-json) write_server_json=1 ;;
	-*) usage ;;
	*) out=$arg ;;
	esac
done
case $version in
*[!0-9A-Za-z.+-]* | '') echo "render.sh: bad version '$version'" >&2; exit 1 ;;
esac

script=$(mktemp)
trap 'rm -f "$script"' EXIT
{
	echo "s|@VERSION@|$version|g"
	echo "s|@DATE@|$(date -u +%Y-%m-%d)|g"
	while read -r hash file; do
		file=${file#\*}
		case $hash in
		*[!0-9a-f]*) echo "render.sh: bad hash for $file in $sums" >&2; exit 1 ;;
		esac
		[ ${#hash} -eq 64 ] || { echo "render.sh: bad hash for $file in $sums" >&2; exit 1; }
		echo "s|@SHA256:$file@|$hash|g"
		echo "s|@SHA256_UPPER:$file@|$(echo "$hash" | tr a-f A-F)|g"
	done <"$sums"
} >"$script"

render() {
	mkdir -p "$(dirname "$out/$2")"
	sed -f "$script" "$root/packaging/$1" >"$out/$2.tmp"
	if grep -n -E '@(VERSION|DATE|SHA256(_UPPER)?:[^@]*)@' "$out/$2.tmp" >&2; then
		echo "render.sh: unresolved placeholders in $2 — is $sums from release $version?" >&2
		rm -f "$out/$2.tmp"
		exit 1
	fi
	mv "$out/$2.tmp" "$out/$2"
}

winget="winget/manifests/e/ermoluk/mcp-warden/$version"
render homebrew/mcp-warden.rb.in homebrew/mcp-warden.rb
render scoop/mcp-warden.json.in scoop/mcp-warden.json
render winget/ermoluk.mcp-warden.yaml.in "$winget/ermoluk.mcp-warden.yaml"
render winget/ermoluk.mcp-warden.installer.yaml.in "$winget/ermoluk.mcp-warden.installer.yaml"
render winget/ermoluk.mcp-warden.locale.en-US.yaml.in "$winget/ermoluk.mcp-warden.locale.en-US.yaml"
render aur/PKGBUILD.in aur/PKGBUILD
render aur/SRCINFO.in aur/.SRCINFO
render server.json.in server.json
if [ "$write_server_json" = 1 ]; then
	cp "$out/server.json" "$root/server.json"
	echo "render.sh: wrote $root/server.json"
fi
echo "render.sh: manifests for $version in $out"
