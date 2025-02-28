{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
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

        libsDarwin = with pkgs.darwin.apple_sdk.frameworks; lib.optionals (system == "x86_64-darwin" || system == "aarch64-darwin") [ Security ];

        #This is the dev tools used while developing in Floresta.
        devTools = with pkgs; [
          rustup
          just
        ];

        buildInputs =
          if system == "x86_64-darwin" || system == "aarch64-darwin" then [
            pkgs.openssl
            pkgs.pkg-config
          ] ++ libsDarwin else [
            pkgs.openssl
            pkgs.pkg-config
          ];

        florestaRust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      in
      with pkgs;
      {
        checks = {
          #TODO: Add relevant checks here to be executed by CI with nix flake check
        };

        packages = {
          default = import ./build.nix {
            inherit lib rustPlatform florestaRust buildInputs;
          };
        };

        flake.overlays.default = (final: prev: {
          floresta-node = self.packages.${final.system}.default;
        });

        devShells = {
          pythonTests =
            let
              _scriptSetup = ''bash ./tests/prepare.sh'';
              # Packages fetched from ./pyproject.toml
              pythonDeps = with python312Packages; [
                black
                requests
                pylint
                jsonrpc-base
              ];
            in
            pkgs.mkShell {
              buildInputs = with pkgs; [
                florestaRust
                python312
                poetry
                poethepoet
                go
              ] ++ pythonDeps;
              shellHook = ''
                ${_scriptSetup}
                echo -e "you may execute \n\t bash ./tests/run.sh \nto execute Florestas Python tests"
              '';
            };
          default =
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
        };
      });
}
