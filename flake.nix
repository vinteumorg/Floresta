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
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      flake-utils,
      pre-commit-hooks,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];

        pkgs = import nixpkgs { inherit system overlays; };
      in
      with pkgs;
      {
        devShells =
          let
            # This is the dev tools used while developing in Floresta.
            deps = with pkgs; [
              just
              rustup
              git
              rust-bin.stable.latest.default
              boost
              cmake
              (rust-bin.selectLatestNightlyWith (toolchain: toolchain.default))
              typos
            ];
            hooks = pre-commit-hooks.lib.${system}.run {
              src = {
                root = ./.;
              };
              settings = {
                rust = {
                  cargoManifestPath = "./Cargo.toml";
                };
              };
              hooks = {
                clippy = {
                  packageOverrides = {
                    inherit cargo;
                  };
                  enable = true;
                  settings = {
                    denyWarnings = true;
                    extraArgs = "--all-targets --no-deps";
                  };
                };
                rustfmt = {
                  packageOverrides = {
                    inherit cargo;
                  };
                  enable = true;
                };
                check-merge-conflicts.enable = true;
                nixfmt-rfc-style.enable = true;
                commitizen.enable = true; # The default commitizen rules are conventional commits.
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
            # Floresta flavored commitizen config file.
            #
            # Since floresta doesnt use any hooks and these are only
            # inside this
            czFlorestaConfigFile = pkgs.writeText ".cz.toml" ''
              [tool.commitizen]
              name = "cz_customize"

              [tool.commitizen.customize]
              types = [
                { type = "feat",    description = "A new feature" },
                { type = "fix",     description = "A bug fix" },
                { type = "docs",    description = "Documentation changes" },
                { type = "style",   description = "Code style changes (formatting, missing semicolons, etc.)" },
                { type = "refactor",description = "Code changes that neither fix a bug nor add a feature" },
                { type = "test",    description = "Adding missing tests or correcting existing tests" },
                { type = "perf",    description = "A code change that improves performance" },
                { type = "ci",      description = "Changes to CI configuration files and scripts" },
                { type = "chore",   description = "Other changes that don't modify src or test files" },
                { type = "fuzz",    description = "Fuzzing-related changes" },
                { type = "bench",   description = "Benchmark-related changes" }
              ]

              schema_pattern = '^(feat|fix|docs|style|refactor|test|perf|ci|chore|fuzz|bench)(\([^)]+\))?: [^\n]+(\n\n[\s\S]+)?$'
            '';

            czHook = ''
              cp -f ${czFlorestaConfigFile} .cz.toml
              echo "Commitizen config written"
            '';
          in
          {
            default =
              let
                inherit (hooks) shellHook enabledPackages;
              in
              mkShell {
                shellHook = shellHook + czHook;
                buildInputs = enabledPackages ++ deps;
                packages = enabledPackages ++ deps;
              };

            func-tests-env =
              let
                python-hook =
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
                pythonTestDeps = with pkgs; [
                  uv
                  python312
                ];
              in
              mkShell {
                packages = deps ++ pythonTestDeps;

                inputsFrom = testBinaries;

                shellHook = python-hook ++ ''
                  # Modified version of the prepare.sh script adaptated for this nix devshell.

                  HEAD_COMMIT_HASH=${self.rev or self.dirtyRev}
                  export FLORESTA_TEMP_DIR="/tmp/floresta-temp-dir.$HEAD_COMMIT_HASH"

                  mkdir -p "$FLORESTA_TEMP_DIR/binaries"

                  # Generate symlink commands for each binary in the list

                  ${toString (
                    pkgs.lib.lists.forEach testBinaries (binary: ''
                      ln -s ${binary}/bin/${pkgs.lib.strings.getName binary} "$FLORESTA_TEMP_DIR/binaries/${pkgs.lib.strings.getName binary}"
                    '')
                  )}

                  alias run_test="uv run tests/test_runner.py"
                  echo "run_test alias is set."
                '';
              };
          };
      }
    );
}
