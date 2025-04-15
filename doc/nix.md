# Nix on floresta project

Nix is a declarative package manager that uses the equally named Nix programing language to build expressions.
You can know more about Nix in their [page](https://nixos.org/) but lets focus on what it does inside this project.

To accomplish any steps down below you only need nix installed.

- [Using Floresta in a Nix expression](#using_floresta_via_nix)
- [Building](#Building_Floresta_with_nix)
    - [With flakes](#With_flakes)
    - [Without flakes](#Without_flakes)
- [Dev: devShells](#Dev_environments_with_devshells)
- [Dev: checks](#Running_flake_checks)

How to build the projects components using flakes and without it.
notify flake checks (CI & manual).
developer shells

## Building Floresta with Nix

  The nix expressions in this project provides few ways to use floresta via nix.

  ### Using Floresta in a Nix expression.

  You can consume its flake as a input for another flake.

  Example from: https://github.com/jaoleal/nix_floresta_example

  ```Nix
  {
    description = "A very basic flake example about consuming the floresta project";

    inputs = {
      nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
      floresta-master.url = "github:vinteumorg/floresta"; # Using the latest nix expressions
      floresta-by-tag.url = "github:vinteumorg/floresta?tag=0.X.0"; # you can specify a tag.
      # *Attention*: The flake and nix expressions inside floresta became stable on 0.8.0
    };

    outputs =
      { self, ... }@inputs:
      let
        # Specify your system, these are the ones we support by now: platforms = [ "aarch64-linux" "x86_64-linux" "aarch64-darwin" "x86_64-darwin" ];
        system = "x86_64-linux";
        floresta = inputs.floresta-master.packages.${system}.default; # the "default" package will retrieve these components: [ libfloresta, florestad , floresta-cli ]
        florestad = inputs.floresta-master.packages.${system}.florestad;
        floresta-cli = inputs.floresta-master.packages.${system}.floresta-cli;
      in
      (import inputs.nixpkgs { inherit system; }).lib.mkShell {

        nativeBuildInputs = [
          floresta
          florestad
          floresta-cli
        ];

        shellHook = ''
          echo "floresta @: ${floresta}"
          echo "florestad @: ${florestad}"
          echo "floresta-cli @: ${floresta-cli}"

          echo "Try running it!"
          echo ""
          echo "$ florestad"

          echo "$ floresta-cli getblockchaininfo"
        '';
      } // ./checks;
  }
  ```

  ### With flakes (recommended)

  From the root source of this project you have the following alternatives to build using flakes:

  ```Bash
  # The default building derivation, build all the components this project provide: florestad, floresta-cli and libfloresta.
  $ nix build

  $ ls ./result/bin/
  floresta-cli  florestad

  $ ls ./result/lib/
  libfloresta.a  libfloresta_chain.so  libfloresta.so
  ```

  You can specify the component to build a derivation only for it.

  ```Bash
  # The available options are: florestad, floresta-cli and libfloresta
  $ nix build .#florestad

  $ ls ./result/bin
  florestad
  ```
  Its recommended to use the default build command.

## Dev environments with devshells

This project offers two devshells that facilitates development for nix users.

```Bash
# This command will set up tour default devshell which include just and rustup. 
$ nix develop

$ exit

# you can also use the func-tests-env which is a helper to run 
# the projects functional tests
$ nix develop .#func-tests-env

```

The `func-tests-env` devshell provides:
  - `uv`.
  - Python dependencies
  - `utreexod` included in `$PATH` and linked in `$FLORESTA_TEMP_DIR`
  - `florestad` included in `$PATH` and linked in `$FLORESTA_TEMP_DIR`
  - `run_test` alias. `run_test="uv run tests/run_tests.py"`

you can see more about our tests in [running tests](./running-tests.md)

## Running flake checks

This project also integrates some checks for CI.

```Bash
# This command will run all the checks setted by flake.nix
$ nix flake check
```
Checks enabled:

1. Nix
  - nixfmt-rfc-style
  - statix
  - flake-checker
  
2. Rust
  - clippy (check mode)
  - rustfmt (check mode)
  
3. Python
  - black (check mode)