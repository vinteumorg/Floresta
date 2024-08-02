[![Docker Publish](https://github.com/Davidson-Souza/Floresta/actions/workflows/docker.yml/badge.svg)](https://github.com/Davidson-Souza/Floresta/actions/workflows/docker.yml)
[![Docker Publish](https://github.com/Davidson-Souza/Floresta/actions/workflows/docker.yml/badge.svg)](https://github.com/Davidson-Souza/Floresta/actions/workflows/docker.yml)
[![functional](https://github.com/Davidson-Souza/Floresta/actions/workflows/functional.yml/badge.svg)](https://github.com/Davidson-Souza/Floresta/actions/workflows/functional.yml)

### Floresta

Welcome to Floresta, a lightweight Bitcoin full node implementation written in Rust, powered by [Utreexo](https://eprint.iacr.org/2019/611) a novel dynamic accumulator  designed for the Bitcoin UTXO set.

This project is composed of two parts, `libfloresta` and `florestad`. `libfloresta` is
a set of reusable components that can be used to build Bitcoin applications. `florestad` is built on top of `libfloresta` to provide a full node implementation, including a watch-only wallet and an Electrum server. If you just want to run a full node, you can use `florestad` directly, either by building it from source or by downloading a pre-built binary from the [releases](https://github.com/Davidson-Souza/Floresta/releases/tag/v0.4.0).

If you want to use `libfloresta` to build your own Bitcoin application, you can find the documentation [here](https://docs.getfloresta.sh/floresta/).

### ToC

- [Community](#community)
- [Building](#building)
  - [Building with nix](#building-with-nix)
- [Running](#running)
  - [Assume Utreexo](#assume-utreexo)
  - [Compact Filters](#compact-filters)
  - [Getting help](#getting-help)
  - [Wallet](#wallet)
- [Running the tests](#running-the-tests)
- [Contributing](#contributing)
- [Using Nix](#using-nix)
- [License](#license)
- [Acknowledgments](#acknowledgments)
- [Consensus implementation](#consensus-implementation)

### Community

If you want to discuss this project, you can join our Discord server [here](https://discord.gg/5Wj8fjjS93). If you want to disclose
a security vulnerability, please email `Davidson Souza at me AT dlsouza DOT lol`, using the PGP key [`2C8E0F 836FD7D BBBB9E 9B2EF899 64EC3AB 22B2E3`](https://blog.dlsouza.lol/assets/pgp.asc).

## Building

You'll need Rust and Cargo, refer to [this](https://www.rust-lang.org/) for more details. Minimum support version is rustc 1.74 and newer.

Once you have Cargo, clone the repository with:

```bash
git clone https://github.com/Davidson-Souza/Floresta.git
```

go to the Floresta directory

```bash
cd Floresta/
```

and build with cargo build

```bash
cargo build --release
# Optionally, you can add florestad to the path with
cargo install --path ./florestad
```

### Building with nix

If you're using Nix, you can add Florestad to your system with its overlay.

```nix
{
  #Here you declare the import for your flake
  inputs.florestad = {
    url = "github:Davidson-Souza/Floresta";
    inputs = {
      nixpkgs.follows = "nixpkgs";
      flake-parts.follows = "flake-parts";
    };
  };

  outputs = inputs @ { self, ... }:
  {
    imports = [
      {
        nixpkgs.overlays = [
          # Here you use the floresta overlay with your others
          inputs.florestad.overlays.default
        ];
      }
    ];
  };
```
then Florestad will be available just like any other package with

```nix
pkgs.florestad
```


But if you just want to test it or quickly run a instance you can do 
```bash
$ nix run github:Davidson-Souza/Floresta
```

### Running

After building, florestad and floresta-cli will be available in the target directory. You can run the full node with
```bash
./target/release/florestad
# or, if you installed it with cargo install
florestad
```

This will start the full node, and you can connect to it with an Electrum wallet or with the `floresta-cli` tool.

```bash
floresta-cli getblockchaininfo
```

For more information on how to use the `floresta-cli` tool, you can check the [api documentation](https://github.com/Davidson-Souza/Floresta/blob/master/crates/floresta-cli/README.md).

#### Assume Utreexo
If you want to skip the IBD process, you can use the `--assumeutreexo` flag. This flag will start the node at a given height, with the state
provided by this implementation. Therefore, you're trusting that we are giving you the correct state. Everything after that height will be
verified by the node just like any other node.

```bash
florestad --assumeutreexo
```

#### Compact Filters

Floresta supports compact block filters, which can be used to scan for transactions in a block without downloading the entire block. You can start the node with the `--cfilters` flag to download the filters for the blocks that you're interested in. You can also use the `--filters-start-height` flag to specify the block height that you want to start downloading the filters from. This is useful if you want to download only the filters for a specific range of blocks.

```bash
florestad --cfilters --filters-start-height 800000
```

#### Getting help

You can get a list of all the available commands by running

```bash
floresta-cli help
```

and you can get the cli parameters by running
```bash
floresta-cli help <command>
```

#### Wallet

Floresta comes with a watch-only wallet that you can use to track your transactions. You just need to provide the wallet 
information, either as a configuration file or as a command line argument. See the [sample configuration file](florestad/config.toml) for an example config. Floresta supports SLIP-132 extended public keys (xpubs) and output descriptors. You can add new wallets to follow at any time, just
call the `rescan` rpc after adding the wallet.

You can add new descriptors to the wallet with the `importdescriptor` rpc.

```bash
floresta-cli importdescriptor "wpkh(xpub6CFy3kRXorC3NMTt8qrsY9ucUfxVLXyFQ49JSLm3iEG5gfAmWewYFzjNYFgRiCjoB9WWEuJQiyYGCdZvUTwPEUPL9pPabT8bkbiD9Po47XG/<0;1>/*)"
```

The rescan assumes that you have compact block filters for the blocks that you're scanning. You can either download all the filters 
(about 11GB on mainnet) or, if you know the block range that you're interested in, you can download only the filters for that range
using the `--filters-start-height` option. Let's you know that none of your wallets are older than block 800,000. Just start the node with.

```bash
./target/release/florestad --cfilters --filters-start-height 800000
```

if you add a wallet and want to rescan the blocks from 800,000 to the current height, you can use the `rescan` rpc.

```bash
floresta-cli rescan 800000
```

Once you have a transaction cached in your watch-only, you can use either the rpc or integrated electrum server to retrieve information about your wallet. You can use wallets like Electrum or Sparrow to connect to your node and retrieve information about your wallet. Just connect with the server running at `127.0.0.1:50001:t`. On electrum you may want to use the `--oneserver` flag to connect to a single server, for better privacy.

### Running the tests

#### Requirements

```bash
cargo build
```

There's a set of unit tests that you can run with
```bash
cargo test
```

There's also a set of functional tests that you can run with

```bash
pip3 install -r tests/requirements.txt
python tests/run_tests.py
```

### Contributing
Contributions are welcome, feel free to open an issue or a pull request.

If you want to contribute but don't know where to start, take a look at the issues, there's a few of them marked as `good first issue`.

Here's some Guidelines:
- Has to compile.
- Has to run.
- Use [pre-commit](https://pre-commit.com/) for the language that you're using (if possible 👍).

You can accomplish that using our flake.nix for development.

### Using Nix

If you already have [Nix](https://nixos.org/) you just need to do:

```Bash
$ nix develop
```

and use our flake for development which include

- nix(fmt) and rust(fmt) pre-commit.
- Rust Msrv(1.74.0).
- Clippy and some libs so rust can compile.
- Typos for good spelling.

If you do not have Nix
[Check their guide](https://nixos.org/download/).

### License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

### Acknowledgments
* [Utreexo](https://eprint.iacr.org/2019/611)
* [Bitcoin Core](https://github.com/bitcoin/bitcoin)
* [Rust Bitcoin](https://github.com/rust-bitcoin/rust-bitcoin)
* [Rust Miniscript](https://github.com/rust-bitcoin/rust-miniscript)

### Consensus implementation

One of the most challenging parts of working with Bitcoin is keeping up with the consensus rules. Given it's nature as a consensus protocol, it's very important to make sure that the implementation is correct. Instead of reimplementing a Script interpreter, we use [`rust-bitcoinconsensus`](https://github.com/rust-bitcoin/rust-bitcoinconsensus/) to verify transactions. This is a bind around a shared library that is part of Bitcoin Core. This way, we can be sure that the consensus rules are the same as Bitcoin Core, at least for scripts.

Although tx validation is arguably the hardest part in this process. This integration can be further improved by using `libbitcoinkernel`, that will increase the scope of `libbitcoinconsensus` to outside scripts, but this is still a work in progress.
