{
  description = "mcp-warden: local-first credential broker MCP server for AI coding agents";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  # Builds from source with nixpkgs' Rust toolchain:
  #   nix run github:ermoluk/mcp-warden -- mcp
  #   nix profile install github:ermoluk/mcp-warden
  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      manifest = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package;
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "mcp-warden";
          inherit (manifest) version;
          src = pkgs.lib.cleanSource ./.;
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [
            "--package"
            "mcp-warden"
          ];
          # The test suite needs the OS keychain, approval dialogs and the
          # network, none of which the build sandbox has; CI runs it.
          doCheck = false;
          meta = {
            inherit (manifest) description;
            homepage = "https://github.com/ermoluk/mcp-warden";
            changelog = "https://github.com/ermoluk/mcp-warden/blob/main/CHANGELOG.md";
            license = pkgs.lib.licenses.asl20;
            mainProgram = "mcp-warden";
            platforms = systems;
          };
        };
      });

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = "${self.packages.${pkgs.stdenv.hostPlatform.system}.default}/bin/mcp-warden";
          meta.description = manifest.description;
        };
      });
    };
}
