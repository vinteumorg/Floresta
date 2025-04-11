# Using Nix
## Building with Nix

If you're using Nix, you can add Florestad to your system with its overlay.

```nix
{
  #Here you declare the floresta set for your flake
  inputs.floresta-node = {
    url = "github:vinteumorg/Floresta";
    inputs = {
      nixpkgs.follows = "nixpkgs";
      flake-parts.follows = "flake-parts";
    };
  };
  #Pass floresta-node as a input to "output".
  outputs = { self, floresta-node }:
  {
    imports = [
      {
        overlays = [
            # Here you use the floresta overlay with your others
            floresta-node.overlay.default
        ];
      }
    ];
  };
```
then `florestad` and `floresta-cli` will be available just like any other package with

```nix
pkgs.floresta-node
```

## Developing with Nix

If you already have [Nix](https://nixos.org/) you just need to do:

```bash
nix develop
```

and use our flake for development which include

- nix(fmt) and rust(fmt)  in pre-commit.
- [pre-commit](https://pre-commit.com/).
- [rustup](https://rustup.rs/).
- Typos in pre-commit.
- [Just, the command runner](https://just.systems/).

If you do not have Nix you can [Check their guide](https://nixos.org/download/).

## Testing with Nix
If you have nix, we provide a devshell that you can access with

```bash
nix develop .#func-tests-env
```
The `func-tests-env` devshell provides:
  - `uv`.
  - Python dependencies
  - `utreexod` included in `$PATH` and linked in `$FLORESTA_TEMP_DIR`
  - `florestad` included in `$PATH` and linked in `$FLORESTA_TEMP_DIR`
  - `run_test` alias. `run_test="uv run tests/run_tests.py"`
