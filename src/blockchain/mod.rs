pub mod chain_state;
pub mod chainstore;
pub mod cli_blockchain;
pub mod error;
pub mod udata;

use async_std::channel::Sender;
use bitcoin::{hashes::sha256, Block, BlockHash, BlockHeader};
use rustreexo::accumulator::proof::Proof;

use self::error::BlockchainError;

type Result<T> = std::result::Result<T, BlockchainError>;
/// This trait is the main interface between our blockchain backend and other services.
/// It'll be useful for transitioning from rpc to a p2p based node
pub trait BlockchainInterface {
    /// Returns the block with a given height in our current tip.
    fn get_block_hash(&self, height: u32) -> Result<bitcoin::BlockHash>;
    /// Returns a bitcoin [Transaction] given it's txid.
    fn get_tx(&self, txid: &bitcoin::Txid) -> Result<Option<bitcoin::Transaction>>;
    /// Get the height of our best know chain.
    fn get_height(&self) -> Result<u32>;
    /// Broadcasts a transaction to the network.
    fn broadcast(&self, tx: &bitcoin::Transaction) -> Result<()>;
    /// Returns fee estimation for inclusion in `target` blocks.
    fn estimate_fee(&self, target: usize) -> Result<f64>;
    /// Returns a block with a given `hash` if any.
    fn get_block(&self, hash: &BlockHash) -> Result<Block>;
    /// Returns the best known block
    fn get_best_block(&self) -> Result<(u32, BlockHash)>;
    /// Returns associated header for block with `hash`
    fn get_block_header(&self, hash: &BlockHash) -> Result<BlockHeader>;
    /// Register for receiving notifications for some event. Right now it only works for
    /// new blocks, but may work with transactions in the future too.
    fn subscribe(&self, tx: Sender<Notification>);
    /// Tells whether or not we are on ibd
    fn is_in_idb(&self) -> bool;
}
/// A [BlockchainProviderInterface] is the trait that a implementation of blockchain uses to update
/// the chainstate.
pub trait BlockchainProviderInterface {
    /// Sends the notification across all subscribers.
    fn notify(&self, what: Notification);
    /// This is one of the most important methods for a ChainState, it gets a block and some utreexo data,
    /// validates this block and connects to our chain of blocks.
    fn connect_block(
        &self,
        block: &Block,
        proof: Proof,
        del_hashes: Vec<sha256::Hash>,
    ) -> Result<()>;
    /// If we detect a reorganization of blocks, this function should reconciliate our view of
    /// the network.
    fn handle_reorg(&self) -> Result<()>;
    /// Not used for now, but in a future blockchain with mempool, we can process transactions
    /// that are not in a block yet.
    fn handle_transaction(&self) -> Result<()>;
    /// Persists our data. Should be invoked periodically.
    fn flush(&self) -> Result<()>;
}
/// A notification is a hook that a type implementing [BlockchainInterface] sends each
/// time the given event happens. This is use to notify new blocks to the Electrum server.
/// In the future, it can be expanded to send more data, like transactions.
pub enum Notification {
    NewBlock(Block),
}
