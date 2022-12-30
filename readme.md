### Utreexo Electrum Server
**This is a WIP project, and should not be used with real money!**

This is a WIP for a wallet/node powered by utreexo. This codebase can download and parse blocks (from a Utreexod cli), find transactions we need to our wallet and do some basic consensus validation.
This code also has an out-of-the-box Electrum Server that you can use with any wallet that supports it.

### Building
You'll need Rust and Cargo, refer to [this](https://www.rust-lang.org/) for more details.
Once you have Cargo, clone the repository with:
```bash
$ git clone https://github.com/Davidson-Souza/utreexo-electrum-server
```
and build with cargo build
```bash
$ cd utreexo-electrum-server
$ cargo build --release
```

### Running
Before running, you have to get an Extended Public Key from your wallet. You'll also need a running [Utreexod](https://github.com/utreexo/utreexod) (If you want to test on signet, you can ask me to use mine, but signet is really easy to sync up).

Copy `config.toml.sample` to `config.toml`, and fill all related fields, like xpubs and rpc credentials. Then just run
```bash
$ utreexo-wallet -c config.toml --network signet run
```
