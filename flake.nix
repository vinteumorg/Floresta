{
  inputs = {
    nixpkgs = {
      url = "github:NixOS/nixpkgs/nixos-24.05";
    };
    flake-utils = {
      url = "github:numtide/flake-utils";
    };
    pre-commit-hooks = {
      url = "github:cachix/git-hooks.nix";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    utreexod-flake = {
      url = "github:jaoleal/utreexod-flake";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      flake-utils,
      pre-commit-hooks,
      utreexod-flake,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];

        utils = import ./contrib/nix/utils.nix { inherit pkgs; };

        pkgs = import nixpkgs { inherit system overlays; };
      in
      with pkgs;
      {
        checks = {
          # This check runs nixfmt, statix and flake health checker on all defined files in `fileset`,
          # the nix files we have in this project
          nix-sanity-check =
            let
              fileSet = lib.fileset.unions [
                ./contrib/nix
                ./flake.nix
                ./flake.lock
              ];
            in
            pre-commit-hooks.lib.${system}.run {
              src = lib.fileset.toSource {
                root = ./.;
                fileset = fileSet;
              };
              hooks = {
                nixfmt-rfc-style = {
                  enable = true;
                };
                statix.enable = true;
                flake-checker = {
                  enable = true;
                  # I want to keep nixpkgs pinned, update = things breaking.
                  args = [
                    "--check-outdated"
                    "false"
                  ];
                };
              };
            };

          # This check runs clippy and rustfmt on all defined files in `fileset`,
          # the rust files we have in this project
          rust-sanity-check =
            let
              # since the rust code of this project is spread across multiple files,
              # it's better to track them using file sets to avoid useless operations.
              fileSet = lib.fileset.unions [
                ./Cargo.toml
                ./Cargo.lock
                ./rust-toolchain.toml
                ./.rustfmt.toml
                ./crates
                ./bin
                ./metrics
                ./fuzz
                ./doc/rpc
              ];
              # Nightly cargo
              cargo = rust-bin.selectLatestNightlyWith (toolchain: toolchain.default);
            in
            pre-commit-hooks.lib.${system}.run {
              src = lib.fileset.toSource {
                root = ./.;
                fileset = fileSet;
              };
              settings = {
                rust = {
                  check.cargoDeps = pkgs.rustPlatform.importCargoLock { lockFile = ./Cargo.lock; };
                  cargoManifestPath = "./Cargo.toml";
                };
              };
              hooks = {
                clippy = {
                  packageOverrides = {
                    inherit cargo;
                    clippy = cargo;
                  };
                  enable = true;
                  settings.denyWarnings = true;
                  settings.extraArgs = "--no-deps";
                };
                rustfmt = {
                  packageOverrides = {
                    inherit cargo;
                  };
                  enable = true;
                };
              };
            };

          # This check runs black on check mode on all defined files in `fileset`,
          # the python files we have in this project
          python-sanity-check =
            let
              fileSet = lib.fileset.unions [
                ./pyproject.toml
                ./uv.lock
                ./tests
              ];
            in
            pre-commit-hooks.lib.${system}.run {
              src = lib.fileset.toSource {
                root = ./.;
                fileset = fileSet;
              };
              hooks = {
                black = {
                  enable = true;
                  settings.flags = "--check --verbose ./tests";
                };
              };
            };
        };
        packages =
          let
            src = lib.fileset.toSource {
              root = ./.;
              fileset = lib.fileset.unions [
                ./Cargo.toml
                ./Cargo.lock
                ./rust-toolchain.toml
                ./.rustfmt.toml
                ./crates
                ./metrics
                ./bin
                ./fuzz
                ./doc/rpc
              ];
            };
          in
          {
            florestad =
              let
                packageName = "florestad";
              in
              import ./contrib/nix/build_floresta.nix { inherit packageName pkgs src; };

            floresta-cli =
              let
                packageName = "floresta-cli";
              in
              import ./contrib/nix/build_floresta.nix { inherit packageName pkgs src; };

            libfloresta =
              let
                packageName = "libfloresta";
              in
              import ./contrib/nix/build_floresta.nix { inherit packageName pkgs src; };

            default =
              let
                packageName = "all";
              in
              import ./contrib/nix/build_floresta.nix { inherit packageName pkgs src; };

          };
        devShells =
          let
            # This is the dev tools used while developing in Floresta.
            basicDevTools = with pkgs; [
              just
              rustup
              git
              typos
              rust-bin.stable.latest.default
              (rust-bin.selectLatestNightlyWith (toolchain: toolchain.default))
            ];
            testBinaries = [
              self.packages.${system}.florestad
              utreexod-flake.packages.${system}.utreexod
              pkgs.bitcoind
            ];

          in
          {
            default = mkShell {
              buildInputs = basicDevTools;

              shellHook = "";
            };
            func-tests-env =
              let
                prepareHook = utils.prepareBinariesScript {
                  binariesToLink = testBinaries;
                  gitRev = self.rev or self.dirtyRev;
                };
                pythonDevTools = with pkgs; [
                  uv
                  python312
                  # If needed, one can add more tools to be used with python. Uv deal with dependencies declared in pyproject.toml
                ];
              in
              mkShell {
                packages = basicDevTools ++ pythonDevTools;

                inputsFrom = testBinaries;

                shellHook = prepareHook + ''
                  alias run_test="uv run tests/test_runner.py"
                  echo "run_test alias is set"
                '';
              };
          };
      }
    );
}
