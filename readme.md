### Utreexo Electrum Server
**This is a WIP project, and should not be used with real money!**

This is a WIP for a wallet/node powered by utreexo. This codebase can download and parse blocks (from a Utreexod cli), find transactions we need to our wallet and do some basic consensus validation.
This code also has an out-of-the-box Electrum Server that you can use with any wallet that supports it.

#### Building
You'll need Rust and Cargo, refer to [this](https://www.rust-lang.org/), for more details.
Once you have Cargo, clone the repository with:
```bash
$ git clone https://github.com/Davidson-Souza/utreexo-electrum-server
```
and build with cargo build
```bash
$ cd utreexo-electrum-server
$ cargo build --release
```

#### Running
Before running, you have to get an Extended Public Key from your wallet. You'll also need a running [Utreexod](https://github.com/Davidson-Souza/utreexo-electrum-server) (If you want to test on signet, you can ask me to use mine, but signet is really easy to sync up).
One you have all setup, just run
```bash
$ cargo run --release run -- setup <your_xpub> <where_should_we_put_stuff>
```
**example**:
```bash
$ cargo run -- setup "xpub68k3rQ4eumEr3QVbryTCD7k2Pq3yCtx7qTBdmTd2Hb2W6fSre44qxyyJjg2kXi9NQhSsTK7McwyjQpqxqSZVrx82oTEeCKSEjfdVM8vmFGk" /tmp/my_nice_utreexo_wallet/
```
and start sync
```bash
$ cargo run -- run <where_should_we_put_stuff> --rpc-user <rpc_username> --rpc-password <rpc_password> --rpc-host <rpc_host>
```

After the initial wallet sync-up, the Electrum server will start running at `127.0.0.1:50001` in raw tcp, so if you want to connect Electrum wallet you have to use `127.0.0.1:50001:t` otherwise it won't work.