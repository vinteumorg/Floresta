// SPDX-License-Identifier: MIT

//! Floresta, a collection of crates to build lightweight, fast, and reliable
//! Bitcoin nodes and wallets, powered by Utreexo, a novel accumulator to represent
//! the Bitcoin UTXO set.
//!
//! This project is layed out as a collection of crates, each implementing one functionality.
//! They are all named floresta-*. The main crate is floresta, which is a meta-crate
//! that depends on all the others. It is meant to be used as a dependency in other projects.
//!
//! A Bitcoin node is composed of several components. You need some way to express the current
//! network state, some way to communicate with other nodes, some way to store the blockchain,
//! validate data you receive and interact with the user.
//! The current network state (including the accumulator) is tracked by the floresta-chain crate.
//! It doesn't know where data comes from, it just tracks the state, exposing a simple API to
//! update it. The chain is reactive, meaning that it will only update when new data is received.
//!
//! The floresta-wire crate is responsible for communicating with other nodes. It is a simple
//! node implementation that can connect to other nodes, send and receive messages, and
//! handle the peer-to-peer protocol. It is not a full node, it doesn't store the blockchain
//! or validate data, it just sends and receives messages.
//!
//! Floresta also provides a simple watch-only wallet an an electrum server implementation.
//! They are meant to be used in `florestad`, a full node implementation that uses all the
//! crates in this project.
//!
//! You can find examples of how to use the crates in the examples directory.
//! # Name
//! Floresta is the Portuguese word for forest. It is a reference to the Utreexo accumulator,
//! which is a forest of trees. It's pronounced /floˈɾɛstɐ/.
pub use floresta_chain as chain;
pub use floresta_common as common;
pub use floresta_watch_only as wallet;
pub use floresta_wire as wire;
