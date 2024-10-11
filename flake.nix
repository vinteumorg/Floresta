{
  description = "Flake for Floresta development";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
    flake-utils.url = "github:numtide/flake-utils";
    pre-commit-hooks.url = "github:cachix/pre-commit-hooks.nix";
  };
  outputs = { self, nixpkgs, rust-overlay, flake-utils, pre-commit-hooks, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];

        pkgs = import nixpkgs {
          inherit system overlays;
        };

        lib = pkgs.lib;
        stdenv = pkgs.stdenv;

        libsDarwin = with pkgs.darwin.apple_sdk.frameworks; lib.optionals isDarwin [ Security ];

        devTools = with pkgs; [
          rustup
          just
        ];

        buildInputs =
          if system then [
            pkgs.openssl
            pkgs.pkg-config
          ] ++ libsDarwin else [
            pkgs.openssl
            pkgs.pkg-config
          ];

      in
      with pkgs;
      {
        checks = {
          pre-commit-check = pre-commit-hooks.lib.${system}.run {
            src = ./.;
            hooks = {
              typos.enable = true;

              rustfmt.enable = true;

              clippy.enable = true;

              nixpkgs-fmt.enable = true;
            };
          };
        };

        packages.default = import ./build.nix {
          inherit (pkgs) lib rustPlatform;
          inherit buildInputs libsDarwin;

          rust = pkgs.rust;
          rust-overlay = rust-overlay;
        };

        flake.overlays.default = (final: prev: {
          florestad = self.packages.${final.system}.default;
        });

        devShells.default =
          let
            _shellHook = (self.checks.${system}.pre-commit-check.shellHook or "");
          in
          mkShell {
            inherit buildInputs;
            inherit devTools;

            shellHook = ''
              		${ _shellHook}
              		echo "Floresta Nix-shell"
              	'';
          };
      });
}
