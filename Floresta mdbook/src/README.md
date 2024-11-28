# Introduction

Welcome to Floresta, a lightweight Bitcoin full node implementation written in Rust, powered by [Utreexo](https://eprint.iacr.org/2019/611) a novel dynamic accumulator  designed for the Bitcoin UTXO set.

This project is composed of two parts, `libfloresta` and `florestad`. `libfloresta` is
a set of reusable components that can be used to build Bitcoin applications. `florestad` is built on top of `libfloresta` to provide a full node implementation, including a watch-only wallet and an Electrum server. If you just want to run a full node, you can use `florestad` directly, either by building it from source or by downloading a pre-built binary from the [releases](https://github.com/vinteumorg/Floresta/releases/tag/v0.4.0).

If you want to use `libfloresta` to build your own Bitcoin application, you can find the documentation [here](https://docs.getfloresta.sh/floresta/).

## Table of Contents

- [Building](building/building.md)
  - [Prerequisites](building/prerequisites.md)
  - [Instructions for macOS Users](building/instructions-for-macos-users.md)
  - [Building with Nix](building/building-with-nix.md)
- [Running](running/running.md)
  - [Assume Utreexo](running/assume-utreexo.md)
  - [Compact Filters](running/compact-filters.md)
  - [Getting Help](running/getting-help.md)
  - [Wallet](running/wallet.md)
- [Running the Tests](tests/running-the-tests.md)
  - [Requirements](tests/requirements.md)
  - [Testing Options](tests/testing-options.md)
- [Running Benchmarks](benchmarks/running-benchmarks.md)
- [Fuzzing](fuzz/fuzzing.md)
- [Contributing](contrib/contributing.md)
- [Using Nix](developing-on-floresta-with-nix.md)
- [License](license.md)
- [Acknowledgments](acknowledgments.md)
- [Consensus Implementation](consensus-implementation.md)

## Community

If you want to discuss this project, you can join our Discord server [here](https://discord.gg/5Wj8fjjS93). If you want to disclose
a security vulnerability, please email `Davidson Souza at me AT dlsouza DOT lol`, using the PGP key [`2C8E0F 836FD7D BBBB9E 9B2EF899 64EC3AB 22B2E3`](https://blog.dlsouza.lol/assets/pgp.asc).