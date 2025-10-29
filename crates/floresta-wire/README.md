# floresta-wire

`floresta-wire` is the P2P layer for the Floresta project: a lightweight, Utreexo-powered Bitcoin node. It supports Bitcoin P2P transport v1 and v2/BIP324, with peer discovery via DNS seeds, hardcoded addresses, and user-provided peers. It learns about new blocks and transactions, selects the best header chain, performs IBD, maintains a mempool, and stays in sync with the network.

It also supports compact block filters, which are particularly helpful for rescans because Floresta is fully pruned, and an optional SOCKS5 proxy to route all P2P traffic and DNS seed queries.

This crate delegates chain state, validation, and persistence to [`floresta-chain`](https://github.com/vinteumorg/Floresta/tree/master/crates/floresta-chain) and is used by the `florestad` binary.

## Usage

Construct a node with `UtreexoNode`:

```rust
let node = UtreexoNode::<_, RunningNode>::new(
    /* UtreexoNodeConfig */,
    /* ChainState */,
    /* Mempool */,
    /* Optional compact block filters */,
    /* Kill signal */,
    /* AddressMan */,
).unwrap();
```

Where:

- `UtreexoNodeConfig`, `Mempool`, and `AddressMan` are defined in this crate.
- `ChainState` is provided by `floresta-chain` (implements the `ChainBackend` trait).
- Optional compact filters use `NetworkFilters` from `floresta-compact-filters`.
- The kill signal is an `Arc<tokio::sync::RwLock<bool>>`. Set it to `true` to stop the node.

`UtreexoNode` can run in three contexts: `RunningNode` (default, high-level), `SyncNode` (IBD), and `ChainSelector` (header chain selection). In most cases you want the default `RunningNode` context, which delegates to `SyncNode`/`ChainSelector` as needed based on the current phase.

> To start the node, regardless of context, call the `run` method. To stop it, set the kill signal you passed to the builder to `true`.

## Peer sources

Just after the node startup, it will attempt to discover and/or load peers in the following order:

- `peers.json`: a file in the node's data directory that can contain user-provided peers. If not present, this file will be created after the first run. Its purpose is to **store all known peers** and their metadata.
- DNS seeds: active peers fetched via the system DNS resolver, or (if a proxy is configured) via DNS-over-HTTPS routed through SOCKS5. We usually get a few hundred peers with this method. DNS seeds can be disabled with `UtreexoNodeConfig.disable_dns_seeds`.
- Hardcoded addresses (from the `seeds` directory): used only if the node is not connected to any peers within one minute of startup. Acts as a fallback when the previous two methods are unused or fail.

Once the node has at least one peer, it will be able to discover additional peers through the P2P network's address gossip (all of them saved in `peers.json`).

Example `peers.json`:

```json
[
  {
    "address": {
      "V4": "1.228.21.110"
    },
    "last_connected": 1678986166,
    "state": {
      "Tried": 0
    },
    "services": 50331657,
    "port": 8333
  }
]
```

## Cargo features

- `metrics`: when enabled, `floresta-wire` links in a small Prometheus exporter so your node can expose runtime metrics over HTTP (start with `metrics::metrics_server(addr)`).

## Minimum Supported Rust Version (MSRV)

This library should compile with any combination of features on **Rust 1.90.0**.

## License

`floresta-wire` is released under the terms of the MIT license. See [LICENSE](https://github.com/vinteumorg/Floresta/blob/master/LICENSE) for more information or see https://opensource.org/licenses/MIT.
