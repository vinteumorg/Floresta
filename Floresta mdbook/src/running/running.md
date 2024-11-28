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

### Next
  - [Assume Utreexo](assume-utreexo.md)
  - [Compact Filters](compact-filters.md)
  - [Getting Help](getting-help.md)
  - [Wallet](wallet.md)