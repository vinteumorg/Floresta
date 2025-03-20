{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = { nixpkgs.follows = "nixpkgs"; };
    };

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];

        pkgs = import nixpkgs { inherit system overlays; };

        lib = pkgs.lib;

        # libsDarwin are the necessary deps that are needed to build the floresta project for Darwin devices (?)
        libsDarwin = with pkgs.darwin.apple_sdk.frameworks;
          lib.optionals
          (system == "x86_64-darwin" || system == "aarch64-darwin")
          [ Security ];

        # This are deps needed to run and build rust projects.
        basicDeps = [ pkgs.openssl pkgs.pkg-config ];

        # Here we set system related deps, checking if we are building for a Darwin device
        buildInputs =
          if system == "x86_64-darwin" || system == "aarch64-darwin" then
            basicDeps ++ libsDarwin
          else
            basicDeps;

        # This is the 1.74.1 rustup (and its components) toolchain from our `./rust-toolchain.toml`
        florestaRust =
          pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

      in with pkgs; {
        checks = {
          # Usefull Checks here
        };

        packages = let
          # Here we set system related deps. See _buildInputs above.
          inherit buildInputs florestaRust;

          utreexodGithubSrc = fetchFromGitHub {
            owner = "utreexo";
            repo = "utreexod";
            rev = "v0.4.1";
            sha256 = "sha256-oC+OqRuOp14qW2wrgmf4gss4g1DoaU4rXorlUDsAdRA=";
          };

        in rec {
          florestad = import ./build_floresta.nix {
            inherit lib rustPlatform florestaRust buildInputs;
          };

          utreexod = import ./build_utreexod.nix {
            inherit pkgs;
            src = utreexodGithubSrc;
          };
          default = florestad;
        };

        flake.overlays.default = (final: prev: {
          floresta-overlay = self.packages.${final.system}.default;
        });

        devShells = let
          # This is the dev tools used while developing in Floresta. see _florestaRust above.
          devTools = with pkgs; [ just florestaRust ];
        in {
          default = mkShell {
            nativeBuildInputs = devTools;

            shellHook = "\n";
          };
          int-tests-env = let
            FLORESTA_PROJ_DIR = ./.;

            prepareHook = ''
                      
              # Modified version of the prepare.sh script from the floresta project.
              # This script is used to prepare the environment for the integration tests using nix to provide packages
              # without messing with the existing logic of how tests work in the floresta project.

              FLORESTA_PROJ_DIR=${FLORESTA_PROJ_DIR}

              HEAD_COMMIT_HASH=$(git rev-parse HEAD)

              export FLORESTA_TEMP_DIR="/tmp/floresta-integration-tests.$HEAD_COMMIT_HASH"

              mkdir -p $FLORESTA_TEMP_DIR/binaries

              ln -s ${
                self.packages.${system}.florestad
              }/bin/florestad $FLORESTA_TEMP_DIR/binaries/florestad

              ln -s ${
                self.packages.${system}.utreexod
              }/bin/florestad $FLORESTA_TEMP_DIR/binaries/utreexod

              alias run_test="uv run tests/run_tests.py"

              echo "int-test-env Nix-Shell"
              echo "The hook has set the run_test alias"
            '';
            testBinaries = [
              self.packages.${system}.florestad
              self.packages.${system}.utreexod
            ];
            int-tests-deps = with pkgs;
              [
                (pkgs.python312.withPackages (python-pkgs:
                  with python-pkgs; [
                    uv
                    # Offering python dependencies so uv doesn`t need to download them.
                    jsonrpc-base
                    requests
                    black
                    pylint
                  ]))
              ];
          in mkShell {
            nativeBuildInputs = devTools ++ testBinaries ++ int-tests-deps;

            shellHook = prepareHook;
          };
        };
      });
}
