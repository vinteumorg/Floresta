//! Main module for the p2p chain. This is a blockchain provider, just like cli-chain, but it's
//! backed by p2p Bitcoin's p2p network.
pub mod address_man;
pub mod error;
pub mod mempool;
pub mod node;
pub mod node_context;
pub mod node_interface;
pub mod peer;
pub mod stream_reader;
