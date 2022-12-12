pub mod chain_state;
pub mod chainstore;
pub mod error;
pub mod cli_blockchain;
pub mod udata;

use std::sync::Arc;
use bitcoin::{Block, BlockHash, BlockHeader};
use btcd_rpc::{
    client::{BTCDClient, BtcdRpc},
    json_types::transaction::BestBlock,
};

use self::error::BlockchainError;

type Result<T> = std::result::Result<T, BlockchainError>;
/// This trait is the main interface between our blockchain backend and other services.
/// It'll be useful for transitioning from rpc to a p2p based node
pub trait BlockchainInterface {
    /// Accepts a new blok to our local state. Returns the best chain height
    fn connect_block(&self, block: Block) -> Result<u32>;
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
    fn subscribe<F: Fn(Block) -> () + 'static>(&self, callback: F);
}

pub struct ChainWatch;

impl ChainWatch {
    pub fn get_block(rpc: &Arc<BTCDClient>) -> u64 {
        rpc.getbestblock()
            .unwrap_or(BestBlock {
                height: 0,
                hash: "".into(),
            })
            .height
    }
}
