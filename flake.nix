{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    nixpkgs-unstable.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    utreexod-flake.url = "github:jaoleal/utreexod-flake";
    floresta-flake.url = "github:jaoleal/floresta-flake";
    pre-commit-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs-unstable";
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
      nixpkgs-unstable,
      floresta-flake,
      utreexod-flake,
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
              boost
              cmake
              typos
            ];
            hooks = pre-commit-hooks.lib.${system}.run {
              src = {
                root = ./.;
              };
              hooks = {
                clippy = {
                  enable = true;
                  settings = {
                    denyWarnings = true;
                    extraArgs = "--all-targets --no-deps";
                  };
                };
                rustfmt = {
                  enable = true;
                };
                check-merge-conflicts.enable = true;
                nixfmt-rfc-style.enable = true;
                commitizen.enable = true; # The default commitizen rules are conventional commits.
                statix.enable = true;
                flake-checker.enable = true;
                typos = {
                  enable = true;
                  settings.configPath = "typos.toml";
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
                inherit (hooks) shellHook;
              in
              mkShell {
                shellHook = shellHook + czHook;
                packages = deps;
              };

            python-env =
              let
                inherit (floresta-flake.lib.${system}) florestaBuild;

                rev = self.rev or self.dirtyRev;

                python-hook = pre-commit-hooks.lib.${system}.run {
                  src = lib.fileset.toSource {
                    root = ./.;
                    fileset = lib.fileset.unions [
                      ./pyproject.toml
                      ./uv.lock
                      ./tests
                    ];
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

                testBinaries = [
                  (florestaBuild {
                    inherit pkgs;
                    packageName = "florestad";
                    src = ./.;
                  })
                  utreexod-flake.packages.${system}.utreexod
                  bitcoin
                ];
              in
              mkShell {
                packages = deps ++ pythonTestDeps;

                inputsFrom = testBinaries;

                shellHook = python-hook.shellHook + ''
                  # Modified version of the prepare.sh script adapted for this nix devshell.

                  HEAD_COMMIT_HASH=${rev}
                  export FLORESTA_TEMP_DIR="/tmp/floresta-temp-dir.$HEAD_COMMIT_HASH"

                  mkdir -p "$FLORESTA_TEMP_DIR/binaries"

                  # Generate symlink commands for each binary in the list

                  ${toString (
                    pkgs.lib.lists.forEach testBinaries (binary: ''
                      ln -s ${binary}/bin/${pkgs.lib.strings.getName binary} "$FLORESTA_TEMP_DIR/binaries/${pkgs.lib.strings.getName binary}"
                    '')
                  )}

                  echo "To run the tests:"
                  echo "just test-functional-run"
                '';
              };
          };
      }
    );
}
