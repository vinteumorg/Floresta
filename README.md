[![Docker Publish][docker-badge]][docker-url]
[![Functional][functional-badge]][functional-url]
[![Rust][rust-badge]][rust-url]
[![Docs][docs-badge]][docs-url]
[![License][license-badge]][license-url]

[docker-badge]: https://github.com/vinteumorg/Floresta/actions/workflows/docker.yml/badge.svg
[docker-url]: https://github.com/vinteumorg/Floresta/actions/workflows/docker.yml
[functional-badge]: https://github.com/vinteumorg/Floresta/actions/workflows/functional.yml/badge.svg
[functional-url]: https://github.com/vinteumorg/Floresta/actions/workflows/functional.yml
[rust-badge]: https://github.com/vinteumorg/Floresta/actions/workflows/rust.yml/badge.svg
[rust-url]: https://github.com/vinteumorg/Floresta/actions/workflows/rust.yml
[docs-badge]: https://img.shields.io/badge/docs-floresta-green
[docs-url]: https://docs.getfloresta.sh/floresta/
[license-badge]: https://img.shields.io/badge/license-MIT-blue
[license-url]: https://github.com/vinteumorg/Floresta/blob/master/LICENSE

# Floresta

Welcome to Floresta, a lightweight Bitcoin full node implementation written in Rust, powered by [Utreexo](https://eprint.iacr.org/2019/611) a novel dynamic accumulator  designed for the Bitcoin UTXO set.

This project is composed of two parts, `libfloresta` and `florestad`. `libfloresta` is
a set of reusable components that can be used to build Bitcoin applications. `florestad` is built on top of `libfloresta` to provide a full node implementation, including a watch-only wallet and an Electrum server. If you just want to run a full node, you can use `florestad` directly, either by building it from source or by downloading a pre-built binary from the [releases](https://github.com/vinteumorg/Floresta/releases/tag/v0.4.0).

If you want to use `libfloresta` to build your own Bitcoin application, you can find the documentation [here](https://docs.getfloresta.sh/floresta/).

## Table of Contents

- [Building](#building)
  - [(Prerequisites)](#prerequisites)
  - [Instructions for macOS Users](#instructions-for-macos-users)
  - [Building with Nix](#building-with-nix)
- [Running](#running)
  - [Assume Utreexo](#assume-utreexo)
  - [Compact Filters](#compact-filters)
  - [Getting Help](#getting-help)
  - [Wallet](#wallet)
- [Running the Tests](#running-the-tests)
  - [Requirements](#requirements)
  - [Testing Options](#testing-options)
- [Running Benchmarks](#running-benchmarks)
- [Fuzzing](#fuzzing)
- [Contributing](#contributing)
- [Using Nix](#developing-on-floresta-with-nix)
- [License](#license)
- [Acknowledgments](#acknowledgments)
- [Consensus Implementation](#consensus-implementation)

## Community

If you want to discuss this project, you can join our Discord server [here](https://discord.gg/5Wj8fjjS93). If you want to disclose
a security vulnerability, please email `Davidson Souza at me AT dlsouza DOT lol`, using the PGP key [`2C8E0F 836FD7D BBBB9E 9B2EF899 64EC3AB 22B2E3`](https://blog.dlsouza.lol/assets/pgp.asc).

## Building

### (Prerequisites)
```bash
sudo apt update
sudo apt install gcc build-essential pkg-config libssl-dev
```

You'll need Rust and Cargo, refer to [this](https://www.rust-lang.org/) for more details. Minimum support version is rustc 1.74 and newer.

Once you have Cargo, clone the repository with:

```bash
git clone https://github.com/vinteumorg/Floresta.git
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

### Instructions for macOS Users
The following steps should be executed in a Terminal application. Tip: press `Command (⌘) + Space` and search for `terminal`. 

#### 1. Xcode Command Line Tools

To install, run the following command from your terminal:

``` bash
xcode-select --install
```

Upon running the command, you should see a popup appear.
Click on `Install` to continue the installation process.

#### 2. Homebrew Package Manager

Homebrew is a package manager for macOS that allows one to install packages from the command line easily. You can use the package manager of your preference.

To install the Homebrew package manager, see: https://brew.sh

Note: If you run into issues while installing Homebrew or pulling packages, refer to [Homebrew's troubleshooting page](https://docs.brew.sh/Troubleshooting).

#### 3. Install Required Dependencies

On the Terminal, using Homebrew, run the following:
```bash
brew update
brew install gcc pkg-config openssl
```
* At this point you can proceed from cargo and rust at the previous section.

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

## Running

After building, florestad and floresta-cli will be available in the target directory. You can run the full node with
```bash
./target/release/florestad
# or, if you installed it with cargo install
florestad
```

You may run it as a background process with the `--daemon` flag.

```bash
florestad --daemon
```

This will start the full node, and you can connect to it with an Electrum wallet or with the `floresta-cli` tool.

```bash
floresta-cli getblockchaininfo
```

For more information on how to use the `floresta-cli` tool, you can check the [api documentation](https://github.com/vinteumorg/Floresta/blob/master/crates/floresta-cli/README.md).

Before running you can create the SSL certificates. If you don't do it, it will display a logging `Failed to load SSL certificates, ignoring SSL`. However, it is not mandatory to have the certificates to run the full node.

### Assume Utreexo
If you want to skip the IBD process, you can use the `--assume-utreexo` flag. This flag will start the node at a given height, with the state
provided by this implementation. Therefore, you're trusting that we are giving you the correct state. Everything after that height will be
verified by the node just like any other node.

```bash
florestad --assume-utreexo
```

### Compact Filters

Floresta supports compact block filters, which can be used to scan for transactions in a block without downloading the entire block. You can start the node with the `--cfilters` flag to download the filters for the blocks that you're interested in. You can also use the `--filters-start-height` flag to specify the block height that you want to start downloading the filters from. This is useful if you want to download only the filters for a specific range of blocks.

```bash
florestad --cfilters --filters-start-height 800000
```

### Getting Help

You can get a list of all the available commands by running

```bash
floresta-cli help
```

and you can get the cli parameters by running
```bash
floresta-cli help <command>
```

### Wallet

Floresta comes with a watch-only wallet that you can use to track your transactions. You just need to provide the wallet
information, either as a configuration file or as a command line argument. See the [sample configuration file](config.toml.sample) for an example config. Floresta supports SLIP-132 extended public keys (xpubs) and output descriptors. You can add new wallets to follow at any time, just
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

## Running the Tests

### Requirements

The tests in `floresta-cli` depend on the compiled `florestad` binary. Make sure to build the entire project first by running:

```bash
cargo build
```

### Testing Options

There's a set of tests that you can run with:

```bash
cargo test
```

For the full test suite, including long-running tests, use:

```bash
cargo test --release
```

Additional functional tests are available. Install dependencies and run the test script with:

```bash
pip3 install -r tests/requirements.txt
python tests/run_tests.py
```

## Running Benchmarks

Floresta uses `criterion.rs` for benchmarking. You can run the default set of benchmarks with:

```bash
cargo bench
```

By default, benchmarks that are resource-intensive are excluded to allow for quicker testing. If you'd like to include all benchmarks, use the following command:

```bash
EXPENSIVE_BENCHES=1 cargo bench
```

> **Note**: Running with `EXPENSIVE_BENCHES=1` enables the full benchmark suite, which will take several minutes to complete.

## Fuzzing

This project uses `cargo-fuzz` (libfuzzer) for fuzzing, you can run a fuzz target with:
```bash
cargo +nightly fuzz run local_address_str
```

You can replace `local_address_str` with the name of any other target you want to run.

## Metrics

This project uses [`Prometheus`](https://prometheus.io/) as a monitoring system. To enable it you must build the project with the `metrics` feature enabled:

```sh
cargo build --release --features metrics
```

The easiest way to visualize those metrics is by using some observability graphic tool like [Grafana](https://grafana.com/). To make it easier, you can also straight away use the `docker-compose.yml` file to spin up an infrastructure that will run the project with Prometheus and Grafana.

To run it, first make sure you have [Docker Compose](https://docs.docker.com/compose/) installed and then:

```sh
docker-compose up -d --build
```

Grafana should now be available to you at http://localhost:3000. To log in, please check the credentials defined in the `docker-compose.yml` file.

## Contributing
Contributions are welcome, feel free to open an issue or a pull request.

If you want to contribute but don't know where to start, take a look at the issues, there's a few of them marked as `good first issue`.

Here's some Guidelines:
- Has to compile.
- Has to run.
- Use [pre-commit](https://pre-commit.com/) for the language that you're using (if possible 👍).

You can run `just pcc`, which stands for pre-commit check, to check everything is correct before opening a pull request.

You can also accomplish that using our flake.nix for development.

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

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

## Acknowledgments
* [Utreexo](https://eprint.iacr.org/2019/611)
* [Bitcoin Core](https://github.com/bitcoin/bitcoin)
* [Rust Bitcoin](https://github.com/rust-bitcoin/rust-bitcoin)
* [Rust Miniscript](https://github.com/rust-bitcoin/rust-miniscript)

## Consensus Implementation

One of the most challenging parts of working with Bitcoin is keeping up with the consensus rules. Given its nature as a consensus protocol, it's very important to make sure that the implementation is correct. Instead of reimplementing a Script interpreter, we use [`rust-bitcoinconsensus`](https://github.com/rust-bitcoin/rust-bitcoinconsensus/) to verify transactions. This is a bind around a shared library that is part of Bitcoin Core. This way, we can be sure that the consensus rules are the same as Bitcoin Core, at least for scripts.

Although tx validation is arguably the hardest part in this process. This integration can be further improved by using `libbitcoinkernel`, that will increase the scope of `libbitcoinconsensus` to outside scripts, but this is still a work in progress.
