{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";

    };

    flake-utils = {
      url = "github:numtide/flake-utils";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];

        pkgs = (import nixpkgs { inherit system overlays; });
      in
      with pkgs;
      {
        checks = {
          # Usefull Checks here
          python-sanity =
            let
              source = ./tests;

            in
            pkgs.runCommandLocal "Python Fmt Check"
              {
                nativeBuildInputs = [
                  python312Packages.black
                ];
              }
              ''
                black --check --diff ${source} >> $out
              '';
        };

        packages =
          let
            utreexodSrc = fetchFromGitHub {
              owner = "utreexo";
              repo = "utreexod";
              rev = "v0.4.1";
              sha256 = "sha256-oC+OqRuOp14qW2wrgmf4gss4g1DoaU4rXorlUDsAdRA=";
            };
            florestaSrc = ./.;
          in
          rec {
            florestad = import ./contrib/nix/build_floresta.nix { inherit pkgs florestaSrc; };

            utreexod = import ./contrib/nix/build_utreexod.nix { inherit pkgs utreexodSrc; };

            default = florestad;
          };

        flake.overlays.default = (
          final: prev: {
            floresta-overlay = self.packages.${final.system}.default;
          }
        );

        devShells =
          let
            # This is the dev tools used while developing in Floresta. see _florestaRust above.
            devTools = with pkgs; [
              just
              rustup
            ];
          in
          {
            default = mkShell {
              #TO-DO: Use the standar way to include things inside the shell.
              nativeBuildInputs = devTools;

              shellHook = "\n";
            };
            func-tests-env =
              let
                prepareHook = ''
                  # Modified version of the prepare.sh script from the floresta project.
                  # This script is used to prepare the environment for the functional tests using nix to provide packages
                  # without messing with the existing logic of how tests work in the floresta project.

                  HEAD_COMMIT_HASH=$(git rev-parse HEAD)

                  export FLORESTA_TEMP_DIR="/tmp/floresta-temp-dir.$HEAD_COMMIT_HASH"

                  mkdir -p $FLORESTA_TEMP_DIR/binaries

                  ln -s ${self.packages.${system}.florestad}/bin/florestad $FLORESTA_TEMP_DIR/binaries/florestad

                  ln -s ${self.packages.${system}.utreexod}/bin/utreexod $FLORESTA_TEMP_DIR/binaries/utreexod

                  alias run_test="uv run tests/run_tests.py"
                  echo "run_test alias is set"

                  echo "Floresta func-test-env Nix-Shell"
                '';
                testBinaries = [
                  self.packages.${system}.florestad
                  self.packages.${system}.utreexod
                ];
                pythonDevTools = with pkgs; [
                  uv
                  # If needed, one can add more tools to be used with python. Uv deal with dependencies declared in pyproject.toml
                ];
              in
              mkShell {
                packages = devTools ++ pythonDevTools;

                inputsFrom = testBinaries;

                shellHook = prepareHook;
              };
          };
      }
    );
}
