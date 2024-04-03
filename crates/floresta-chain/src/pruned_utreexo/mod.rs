extern crate alloc;

pub mod chain_state;
pub mod chain_state_builder;
pub mod chainparams;
pub mod chainstore;
pub mod consensus;
pub mod error;
pub mod partial_chain;
pub mod udata;

use alloc::sync::Arc;

use bitcoin::block::Header as BlockHeader;
use bitcoin::hashes::sha256;
use bitcoin::p2p::utreexo::UtreexoBlock;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::OutPoint;
use bitcoin::Transaction;
use bitcoin::TxOut;
use rustreexo::accumulator::node_hash::NodeHash;
use rustreexo::accumulator::proof::Proof;
use rustreexo::accumulator::stump::Stump;

use self::partial_chain::PartialChainState;
use crate::prelude::*;
use crate::BestChain;
use crate::BlockConsumer;
use crate::BlockchainError;
use crate::DatabaseError;
use crate::DiskBlockHeader;

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
    /// if a module performs some heavy-lifting on the block's data, it should pass in a
    /// vector or a channel where data can be  transfered to the atual worker, otherwise
    /// chainstate will be stuck for as long as you have work to do.
    fn subscribe(&self, tx: Arc<dyn BlockConsumer>);
    /// Tells whether or not we are on ibd
    fn is_in_idb(&self) -> bool;
    /// Returns the list of unbroadcasted transactions.
    fn get_unbroadcasted(&self) -> Vec<Transaction>;
    /// Checks if a coinbase is mature
    fn is_coinbase_mature(&self, height: u32, block: BlockHash) -> Result<bool, Self::Error>;
    /// Returns a block locator
    fn get_block_locator(&self) -> Result<Vec<BlockHash>, Self::Error>;
    /// Returns a block locator from a given tip
    ///
    /// This method may be used to get the locator from a tip that's not the best one
    fn get_block_locator_for_tip(&self, tip: BlockHash) -> Result<Vec<BlockHash>, BlockchainError>;
    /// Returns the last block we validated
    fn get_validation_index(&self) -> Result<u32, Self::Error>;
    /// Triggers a rescan, downloading (but not validating) all blocks in [start_height:tip]
    fn rescan(&self, start_height: u32) -> Result<(), Self::Error>;
    /// Returns where we are in the rescan
    fn get_rescan_index(&self) -> Option<u32>;
    /// Returns the height of a block, given it's hash
    fn get_block_height(&self, hash: &BlockHash) -> Result<Option<u32>, Self::Error>;
    fn update_acc(
        &self,
        acc: Stump,
        block: UtreexoBlock,
        height: u32,
        proof: Proof,
        del_hashes: Vec<sha256::Hash>,
    ) -> Result<Stump, Self::Error>;

    fn get_chain_tips(&self) -> Result<Vec<BlockHash>, Self::Error>;

    fn validate_block(
        &self,
        block: &Block,
        proof: Proof,
        inputs: HashMap<OutPoint, TxOut>,
        del_hashes: Vec<sha256::Hash>,
        acc: Stump,
    ) -> Result<(), Self::Error>;

    fn get_fork_point(&self, block: BlockHash) -> Result<BlockHash, Self::Error>;
}
/// [UpdatableChainstate] is a contract that a is expected from a chainstate
/// implementation, that wishes to be updated. Using those methods, a backend like the p2p-node,
/// can notify new blocks and transactions to a chainstate, allowing it to update it's state.
pub trait UpdatableChainstate {
    /// This is one of the most important methods for a ChainState,
    /// it gets a block and some utreexo data, validates this block and
    /// connects to our chain of blocks. This function is meant to be atomic
    /// and prone of running in parallel.
    fn connect_block(
        &self,
        block: &Block,
        proof: Proof,
        inputs: HashMap<OutPoint, TxOut>,
        del_hashes: Vec<sha256::Hash>,
    ) -> Result<u32, BlockchainError>;

    fn switch_chain(&self, new_tip: BlockHash) -> Result<(), BlockchainError>;
    /// Accepts a new header to our chain. This method is called before connect_block, and
    /// makes some basic checks on a header and saves it on disk. We only accept a block as
    /// valid after calling connect_block.
    ///
    /// This function returns whether this block is on our best-known chain, or in a fork
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
    /// Returns a partial chainstate from a range of blocks.
    ///
    /// [PartialChainState] is a simplified version of `ChainState` that is used during IBD.
    /// It doesn't suport reorgs, only hold headers for a subset of blocks and isn't [Sync].
    /// The idea here is that you take a OS thread or some async task that will drive one
    /// [PartialChainState] to completion by downloading blocks inside that chainstate's range.
    /// If all goes right, it'll end without error, and you should mark blocks in this range as
    /// valid.
    ///
    /// Since this chainstate may start from a height with an existing UTXO set, you need to
    /// provide a [Stump] for that block.
    fn get_partial_chain(
        &self,
        initial_height: u32,
        final_height: u32,
        acc: Stump,
    ) -> Result<PartialChainState, BlockchainError>;
    /// Marks a chain as fully-valid
    ///
    /// This mimics the behavour of checking every block before this block, and continues
    /// from this point
    fn mark_chain_as_valid(&self, acc: Stump) -> Result<bool, BlockchainError>;
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
