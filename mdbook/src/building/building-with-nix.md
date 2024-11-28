### Building with Nix

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