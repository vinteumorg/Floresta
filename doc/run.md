# Running Floresta

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

## Assume Utreexo

If you want to start your node and get up and running quickly, you can use the Assume Utreexo feature. This is enabled by defalt, but you can disable it with the `--no-assume-utreexo` flag.

```bash
florestad --no-assume-utreexo
```

## Backfill

After the node starts it will validate everything in the background, downloading blocks from genesis to the assumed height, validating them and compare with the provided value. This way, you can start using the node right away, but still validate everything. This option, however, will take some time to complete, using a lot of CPU and bandwidth.

This is the default behavior of the `florestad` if no flags are provided. You can disable it using:

```bash
florestad --no-backfill
```

## Compact Filters

Floresta supports compact block filters, which can be used to scan for transactions in a block without downloading the entire block. You can start the node with the `--cfilters` flag to download the filters for the blocks that you're interested in. You can also use the `--filters-start-height` flag to specify the block height that you want to start downloading the filters from. This is useful if you want to download only the filters for a specific range of blocks.

```bash
florestad --cfilters --filters-start-height 800000
```

## Getting Help

You can get a list of all the available commands by running

```bash
floresta-cli help
```

and you can get the cli parameters by running
```bash
floresta-cli help <command>
```

## Wallet

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
