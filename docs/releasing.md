# Releasing mcp-warden

How a release is built, what it publishes on its own, and the steps that stay
manual. The release workflow never publishes to a package registry; those
steps need the maintainer's own accounts and tokens.

## What the workflow does

`.github/workflows/release.yml` runs on a `v*` tag, and on demand
(`workflow_dispatch`) as a dry run that publishes nothing.

1. **build** — one job per target, with `cargo build --release --locked`:

   | Target | Runner | Notes |
   |---|---|---|
   | `aarch64-apple-darwin` | `macos-latest` | |
   | `x86_64-apple-darwin` | `macos-latest` | cross-compiled |
   | `x86_64-unknown-linux-gnu` | `ubuntu-latest` | kept for existing links |
   | `x86_64-unknown-linux-musl` | `ubuntu-latest` | static |
   | `aarch64-unknown-linux-musl` | `ubuntu-24.04-arm` | static |
   | `x86_64-pc-windows-msvc` | `windows-latest` | |

   Every binary must stay under 20 MB and print `--version`. The musl ones must
   be static, and on Linux a `secret add` → `list` → `remove` round trip checks
   the kernel keyring, which `linux-keyutils` reaches through raw syscalls.
2. **package** — `packaging/package.sh` builds the release assets. Each check
   below has to pass:
   - the MCPB manifests (`@anthropic-ai/mcpb validate`);
   - `install.sh` against the fresh assets;
   - `packaging/render.sh` and the manifests it writes (`ruby -c`, `jq`, `yq`,
     and `makepkg --printsrcinfo` in an Arch container must reproduce `.SRCINFO`);
   - `packaging/npm/pack.sh` and an `npx` run from the packed tarballs;
   - `shellcheck` on the scripts.

   Everything is uploaded as the workflow artifact `release-VERSION`, with
   `dist/` (release assets) and `out/` (`manifests/`, `npm/`).
3. **publish** (tags only) — a build-provenance attestation for every archive,
   bundle and install script, then the GitHub release with notes taken from
   this version's `CHANGELOG.md` section. Last, if the `HOMEBREW_TAP_TOKEN`
   secret exists, it pushes the rendered formula to `ermoluk/homebrew-tap`.

Release assets, all listed in `SHA256SUMS`:

- `mcp-warden-<target>.tar.gz` (`.zip` for Windows) and `<archive>.sha256`. Archives are flat: `mcp-warden`, `README.md`, `LICENSE`.
- `mcp-warden-<target>.mcpb` for the five targets other than `-gnu`.
- `install.sh`, `install.ps1`.

## Checklist

Before tagging:

1. The version is bumped in `Cargo.toml`, `core/Cargo.toml` (and the
   `mcp-warden-core` dependency), `Cargo.lock`, `server.json`,
   `.claude-plugin/marketplace.json` and `plugins/mcp-warden/.claude-plugin/plugin.json`.
2. `CHANGELOG.md` has a `## [VERSION]` section.
3. `cargo publish --workspace --dry-run` passes.
4. A dry run of the release workflow passes:
   `gh workflow run release.yml --ref <branch>`.

Then, in this order:

1. **Tag and push:** `git tag vVERSION && git push origin vVERSION`. Wait for the
   release workflow to finish; the GitHub release now has every asset.
2. **crates.io.** From a clean checkout of the tag:

   ```bash
   git worktree add --detach ../mcp-warden-release vVERSION
   cd ../mcp-warden-release
   cargo publish --workspace
   ```

   Then delete the worktree. Never use `--allow-dirty`.
3. **Render the manifests** from the published checksums:

   ```bash
   gh release download vVERSION -p SHA256SUMS -D /tmp/mcp-warden-VERSION
   packaging/render.sh VERSION /tmp/mcp-warden-VERSION/SHA256SUMS --server-json
   ```

   The manifests land in `packaging/dist/VERSION/`, and `server.json` at the
   repository root now carries the real MCPB hashes. Commit it:
   `chore: server.json hashes for VERSION`.
4. **Homebrew tap**, first release only:
   - create the public repository `ermoluk/homebrew-tap`;
   - add a fine-grained token with *Contents: read and write* on that repository
     only, as the secret `HOMEBREW_TAP_TOKEN` in `ermoluk/mcp-warden`;
   - re-run the release workflow's *publish* job, or commit
     `packaging/dist/VERSION/homebrew/mcp-warden.rb` as `Formula/mcp-warden.rb` yourself.

   Later releases update the tap on their own.

   Check: `brew install ermoluk/tap/mcp-warden && brew test mcp-warden`.
5. **Scoop bucket:**
   - first release only: create `ermoluk/scoop-bucket` from the
     [Scoop bucket template](https://github.com/ScoopInstaller/BucketTemplate),
     whose Excavator workflow keeps manifests current from `checkver` / `autoupdate`;
   - commit `packaging/dist/VERSION/scoop/mcp-warden.json` as `bucket/mcp-warden.json`.
6. **AUR** (`mcp-warden-bin`):

   ```bash
   git clone ssh://aur@aur.archlinux.org/mcp-warden-bin.git
   cp packaging/dist/VERSION/aur/PKGBUILD packaging/dist/VERSION/aur/.SRCINFO mcp-warden-bin/
   cd mcp-warden-bin && git add PKGBUILD .SRCINFO && git commit -m "VERSION" && git push
   ```

   The first push creates the package; it needs an AUR account with your SSH key.
7. **winget.** Validate on Windows, then open a PR to `microsoft/winget-pkgs`:
   - copy `packaging/dist/VERSION/winget/manifests/e/ermoluk/mcp-warden/VERSION/`
     to the same path in a fork of `microsoft/winget-pkgs`;
   - run `winget validate --manifest <that directory>`;
   - open the PR.

   Or have `wingetcreate submit <directory>` do the PR.
8. **npm.** The first release needs the free npm organisation `mcp-warden`
   (owner: you). Build the tarballs from the release assets, then publish the
   platform packages before `@mcp-warden/cli`, which depends on them:

   ```bash
   gh release download vVERSION -D /tmp/mcp-warden-VERSION --clobber
   packaging/npm/pack.sh VERSION /tmp/mcp-warden-VERSION /tmp/mcp-warden-npm
   for f in /tmp/mcp-warden-npm/mcp-warden-*-*-VERSION.tgz; do npm publish "$f" --access public; done
   npm publish /tmp/mcp-warden-npm/mcp-warden-cli-VERSION.tgz --access public
   ```

   The `release-VERSION` workflow artifact has the same tarballs under `out/npm/`.
   `@mcp-warden/cli` carries `mcpName`, which the MCP Registry checks.
9. **MCP Registry**, after npm (the registry checks that the npm package exists):

   ```bash
   mcp-publisher login github   # if the stored token has expired
   mcp-publisher publish
   ```

   PulseMCP picks servers up from the registry. Smithery is not a channel: it
   stopped accepting new servers in October 2026, and its API and CLI end on
   31 October 2026.
10. **Check what users get:**
    - `cargo binstall mcp-warden`;
    - `npx -y @mcp-warden/cli --version`;
    - `curl -fsSL https://github.com/ermoluk/mcp-warden/releases/latest/download/install.sh | sh`;
    - the crates.io API (`curl -s https://crates.io/api/v1/crates/mcp-warden | jq .crate.max_version`);
    - the MCP Registry entry, which should show `isLatest`.

## Where things are

| Path | What |
|---|---|
| `packaging/package.sh` | binaries → archives, `.sha256`, MCPB bundles, `SHA256SUMS` |
| `packaging/render.sh` | `SHA256SUMS` → Homebrew, Scoop, winget, AUR, `server.json` |
| `packaging/npm/pack.sh` | release archives → npm tarballs |
| `packaging/*/…in` | templates (`@VERSION@`, `@SHA256:<asset>@`) |
| `install.sh`, `install.ps1` | one-line installers, also attached to every release |
| `flake.nix`, `flake.lock` | Nix build from source; `.github/workflows/nix.yml` builds it when dependencies change |
