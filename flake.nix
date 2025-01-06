{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";
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
          pre-commit-check = pre-commit-hooks.lib.${system}.run {
            src = ./.;
            hooks = {
              typos.enable = true;

              rustfmt = {
                enable = true;
                entry = "cargo +nightly fmt --all --check";
              };

              clippy = {
                enable = true;
                entry = "cargo +nightly clippy --all-targets";
              };

              nixpkgs-fmt.enable = true;
            };
          };
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
              _scriptSetup = ''
                mkdir -p ./bin

                cd bin

                # Download and build utreexod
                ls -la utreexod &>/dev/null

                if [ $? -ne 0 ]
                then
                  	git clone https://github.com/utreexo/utreexod
                fi
                cd utreexod

                go build . &>/dev/null
                echo "All done!"
              '';
              _scriptRun = "poetry run poe tests";
            in
            pkgs.mkShell {
              buildInputs = with pkgs; [
                cargo
                python312
                poetry
                go
              ] ++ [ self.packages.${system}.default ];
              shellHook = ''
                ${_scriptSetup}
                ${_scriptRun}

                exit
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
