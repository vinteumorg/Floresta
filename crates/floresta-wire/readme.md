floresta-wire is one of the crates that make up the Floresta project. It is a library that provides a set of functions to communicate with some source of blocks and transactions. It is used by florestad to communicate with the Bitcoin network, learning about new blocks and transactions.

There are two types of wire implementation: one is based on the p2p protocol used by full nodes to communicate with each other, and the other is based on [utreexod](https://github.com/utreexo/utreexod) JSON-RPC interface. While the p2p protocol is more decentralized, the utreexod interface is easier to implement and takes less resources to run. You can choose which one best fits your needs.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
floresta-wire = "0.1.0"
```

you can build a new node as follows:

```rust
let p2p: UtreexoNode = UtreexoNode::new(
    /* ChainState */,
    /* Mempool */,
    /* Network */,
    /* DataDir */,
);
```
where `ChainState` is a struct that implements the `ChainState` trait, `Mempool` is a struct that can be found in `crate::mempool`, `Network` is the network we are on, example `Network::Bitcoin` for mainnet, and `DataDir` is where the node will store its data.

Nodes can be `RunningNode` or `IDBNode`, the former is a node that is used outside of IBD, it's super CPU and network efficient and can do things like rescan and broadcast transactions. while the latter is used during Initial Block Download, it's super fast and can download blocks from peers and verify them.

On any normal situation, just create a `RunningNode` and use it. The running node
creates a IBD node internally and uses it to download blocks and verify them. You can select the node flavor by setting the `Context` generic parameter to `RunningNode` or `IDBNode`.

```rust
let p2p: UtreexoNode<RunningNode, _> = UtreexoNode::new(
    /* ChainState */,
    /* Mempool */,
    /* Network */,
    /* DataDir */,
);
// or
let p2p: UtreexoNode<IDBNode, _> = UtreexoNode::new(
    /* ChainState */,
    /* Mempool */,
    /* Network */,
    /* DataDir */,
);
```

## License

floresta-wire is released under the terms of the MIT license. See [LICENSE](LICENSE) for more information or see https://opensource.org/licenses/MIT.
