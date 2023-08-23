extern crate alloc;
pub mod chain_state;
pub mod chain_state_builder;
pub mod chainparams;
pub mod chainstore;
pub mod consensus;
pub mod error;
pub mod partial_chain;
pub mod udata;

use crate::{prelude::*, BestChain, BlockchainError, DatabaseError, DiskBlockHeader};
use async_std::channel::Sender;
use bitcoin::{hashes::sha256, Block, BlockHash, BlockHeader, OutPoint, Transaction, TxOut};
use rustreexo::accumulator::{node_hash::NodeHash, proof::Proof};

/// This trait is the main interface between our blockchain backend and other services.
/// It'll be useful for transitioning from rpc to a p2p based node
pub trait BlockchainInterface {
    type Error: core2::error::Error + Send + Sync + 'static;
    /// Returns the block with a given height in our current tip.
    fn get_block_hash(&self, height: u32) -> Result<bitcoin::BlockHash, Self::Error>;
    /// Returns a bitcoin [Transaction] given it's txid.
    fn get_tx(&self, txid: &bitcoin::Txid) -> Result<Option<bitcoin::Transaction>, Self::Error>;
    /// Get the height of our best know chain.
    fn get_height(&self) -> Result<u32, Self::Error>;
    /// Broadcasts a transaction to the network.
    fn broadcast(&self, tx: &bitcoin::Transaction) -> Result<(), Self::Error>;
    /// Returns fee estimation for inclusion in `target` blocks.
    fn estimate_fee(&self, target: usize) -> Result<f64, Self::Error>;
    /// Returns a block with a given `hash` if any.
    fn get_block(&self, hash: &BlockHash) -> Result<Block, Self::Error>;
    /// Returns the best known block
    fn get_best_block(&self) -> Result<(u32, BlockHash), Self::Error>;
    /// Returns associated header for block with `hash`
    fn get_block_header(&self, hash: &BlockHash) -> Result<BlockHeader, Self::Error>;
    /// Register for receiving notifications for some event. Right now it only works for
    /// new blocks, but may work with transactions in the future too.
    fn subscribe(&self, tx: Sender<Notification>);
    /// Tells whether or not we are on ibd
    fn is_in_idb(&self) -> bool;
    /// Returns the list of unbroadcasted transactions.
    fn get_unbroadcasted(&self) -> Vec<Transaction>;
    /// Checks if a coinbase is mature
    fn is_coinbase_mature(&self, height: u32, block: BlockHash) -> Result<bool, Self::Error>;
    /// Returns a block locator
    fn get_block_locator(&self) -> Result<Vec<BlockHash>, Self::Error>;
    /// Returns the last block we validated
    fn get_validation_index(&self) -> Result<u32, Self::Error>;
    /// Triggers a rescan, downloading (but not validating) all blocks in [start_height:tip]
    fn rescan(&self, start_height: u32) -> Result<(), Self::Error>;
    fn get_rescan_index(&self) -> Option<u32>;
}
/// [UpdatableChainstate] is a contract that a is expected from a chainstate
/// implementation, that wishes to be updated. Using those methods, a backend like the p2p-node,
/// can notify new blocks and transactions to a chainstate, allowing it to update it's state.
pub trait UpdatableChainstate {
    /// This is one of the most important methods for a ChainState, it gets a block and some utreexo data,
    /// validates this block and connects to our chain of blocks. This function is meant to
    /// be atomic and prone of running in parallel.
    fn connect_block(
        &self,
        block: &Block,
        proof: Proof,
        inputs: HashMap<OutPoint, TxOut>,
        del_hashes: Vec<sha256::Hash>,
    ) -> Result<u32, BlockchainError>;
    /// Accepts a new header to our chain. This method is called before connect_block, and
    /// makes some basic checks on a header and saves it on disk. We only accept a block as
    /// valid after calling connect_block.
    fn accept_header(&self, header: BlockHeader) -> Result<(), BlockchainError>;
    /// Not used for now, but in a future blockchain with mempool, we can process transactions
    /// that are not in a block yet.
    fn handle_transaction(&self) -> Result<(), BlockchainError>;
    /// Persists our data. Should be invoked periodically.
    fn flush(&self) -> Result<(), BlockchainError>;
    /// Toggle ibd on/off
    fn toggle_ibd(&self, is_ibd: bool);
    /// Tells this blockchain to consider this block invalid, and not build on top of it
    fn invalidate_block(&self, block: BlockHash) -> Result<(), BlockchainError>;
    /// Gives a requested block for rescan
    fn process_rescan_block(&self, block: &Block) -> Result<(), BlockchainError>;
    /// Returns the root hashes of our utreexo forest
    fn get_root_hashes(&self) -> Vec<NodeHash>;
}

/// [ChainStore] is a trait defining how we interact with our chain database. This definitions
/// will be used by the [ChainState] to save and retrieve data about the blockchain, likely
/// on disk.
/// Right now, you can use the [KvChainStore] in your code, it implements this trait and
/// uses a key-value store to save data.
/// The [DatabaseError] is a simple trait that can be implemented by any error type that
/// implements [std::error::Error] and [std::fmt::Display]. This is useful to abstract
/// the database implementation from the blockchain.
/// See the documentation of [DatabaseError] for more info.
pub trait ChainStore {
    type Error: DatabaseError;
    /// Saves the current state of our accumulator.
    fn save_roots(&self, roots: Vec<u8>) -> Result<(), Self::Error>;
    /// Loads the state of our accumulator.
    fn load_roots(&self) -> Result<Option<Vec<u8>>, Self::Error>;
    /// Loads the blockchain height
    fn load_height(&self) -> Result<Option<BestChain>, Self::Error>;
    /// Saves the blockchain height.
    fn save_height(&self, height: &BestChain) -> Result<(), Self::Error>;
    /// Get a block header from our database. See [DiskBlockHeader] for more info about
    /// the data we save.
    fn get_header(&self, block_hash: &BlockHash) -> Result<Option<DiskBlockHeader>, Self::Error>;
    /// Saves a block header to our database. See [DiskBlockHeader] for more info about
    /// the data we save.
    fn save_header(&self, header: &DiskBlockHeader) -> Result<(), Self::Error>;
    /// Returns the block hash for a given height.
    fn get_block_hash(&self, height: u32) -> Result<Option<BlockHash>, Self::Error>;
    /// Flushes write buffers to disk, this is called periodically by the [ChainState],
    /// so in case of a crash, we don't lose too much data. If the database doesn't support
    /// write buffers, this method can be a no-op.
    fn flush(&self) -> Result<(), Self::Error>;
    /// Associates a block hash with a given height, so we can retrieve it later.
    fn update_block_index(&self, height: u32, hash: BlockHash) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone)]
/// A notification is a hook that a type implementing [BlockchainInterface] sends each
/// time the given event happens. This is use to notify new blocks to the Electrum server.
/// In the future, it can be expanded to send more data, like transactions.
pub enum Notification {
    NewBlock((Block, u32)),
}
