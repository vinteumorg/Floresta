### Floresta

**This is a WIP project, and should not be used with real money!**

This is a WIP for a wallet/node powered by utreexo. This codebase can download and parse blocks ~~(from a Utreexod cli)~~, find transactions we need to our wallet and do some basic consensus validation. The consensus part is incomplete, and should not be trusted yet.
This code also have an out-of-the-box Electrum Server that you can use with any wallet that supports it.

### Building

You'll need Rust and Cargo, refer to [this](https://www.rust-lang.org/) for more details. Minimum support version is rustc 1.64 and newer.

Once you have Cargo, clone the repository with:

```bash
git clone https://github.com/Davidson-Souza/Floresta.git
```

Navegue para dentro da pasta com

```bash
cd Floresta/
```

and build with cargo build

```bash
cargo build --release
```

### Running
Right now, this project is working on signet only. Mainnet support is still a todo thing. You can get some signet coins [here](signetfaucet.com/) and just play around with it.
Copy `config.toml.sample` to `config.toml`, and fill up your xpubs and addresses that you intend to track, and then run with

```bash
floresta -c config.toml --network signet run
```

or

```bash
./target/release/floresta -c config.toml --network signet run
```

or

```bash
cargo run --release -- -c config.toml --network signet run
```
