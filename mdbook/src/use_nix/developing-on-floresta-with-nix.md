## Developing on Floresta with Nix

If you already have [Nix](https://nixos.org/) you just need to do:

```Bash
$ nix develop
```

and use our flake for development which include

- nix(fmt) and rust(fmt)  in pre-commit.
- [pre-commit](https://pre-commit.com/).
- [rustup](https://rustup.rs/).
- Typos in pre-commit.
- [Just, the command runner](https://just.systems/).

If you do not have Nix you can [Check their guide](https://nixos.org/download/).