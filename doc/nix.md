# Nix on floresta project

Nix is a declarative package manager that uses the equally named Nix programing language to build expressions.
You can learn more about Nix in their [page](https://nixos.org/) but let's focus on what it does inside this project.

To accomplish any of the steps down below you only need nix installed.


- [Building floresta with Nix](#building-floresta-with-nix)
- [Using Floresta in a Nix expression](#using-floresta-in-a-nix-expression)
- [With flakes](#with-flakes)
- [Dev: devShells](#Dev-environments-with-devshells)
- [Dev: checks](#Running-flake-checks)

## Building floresta with nix

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

  ### With flakes

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
  It's recommended to use the default build command.

## Dev environments with devshells

This project offers two devshells that facilitates development for nix users.

```Bash
# This command will source the default devshell which include just and rustup.
$ nix develop

$ exit # To exit the shell

# you can also use the func-tests-env which is a helper to run
# the projects functional tests
$ nix develop .#func-tests-env

```

The `func-tests-env` devshell provides:
  - `uv`.
  - Python dependencies
  - `utreexod` included in `$PATH` and linked in `$FLORESTA_TEMP_DIR`
  - `florestad` included in `$PATH` and linked in `$FLORESTA_TEMP_DIR`
- `run_test` alias. `run_test="uv run tests/test_runner.py"`

You can find more information about our tests in [running tests](./running-tests.md)

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
