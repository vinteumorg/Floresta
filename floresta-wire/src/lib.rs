mod p2p_wire;

use bitcoin::{Block, BlockHeader, Transaction};
pub use p2p_wire::{address_man, mempool, node, node_interface};

/// NodeHooks is a trait that defines the hooks that a node can use to interact with the network
/// and the blockchain. Every time an event happens, the node will call the corresponding hook.
pub trait NodeHooks {
    /// We've received a new block
    fn on_block_received(&mut self, block: &Block);
    /// We've received a new transaction
    fn on_transaction_received(&mut self, transaction: &Transaction);
    /// We've received a new peer
    fn on_peer_connected(&mut self, peer: &u32);
    /// We've lost a peer
    fn on_peer_disconnected(&mut self, peer: &u32);
    /// We've received a new header
    fn on_header_received(&mut self, header: &BlockHeader);
}
