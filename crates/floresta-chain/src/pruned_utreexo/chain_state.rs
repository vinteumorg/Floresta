//! This module is centered around the `ChainState` type, defining it and providing
//! implementations for the [BlockchainInterface] and [UpdatableChainstate] traits.
//!
//! Consequently, `ChainState` serves as the blockchain backend for our node and is
//! the highest-level type in `floresta-chain`. It is responsible for:
//!
//! - Keeping track of the chain state, and using a [ChainStore] for persisted storage
//! - Correctly updating the state with the help of the `consensus.rs` functions
//! - Interfacing with other components, and providing data about the current view of the chain
//!
//! The primary methods for updating our state are [ChainState::accept_header], which constructs
//! a chain of headers, and [ChainState::connect_block], which verifies the corresponding blocks.
//!
//! Key types:
//! - [ChainState]: The high-level chain backend
//! - [BlockConsumer]: Trait for receiving new block notifications
//! - [BestChain]: Tracks the current best chain and alternative forks
extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::fmt::format;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
#[cfg(feature = "bitcoinconsensus")]
use core::ffi::c_uint;

use bitcoin::block::Header as BlockHeader;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::deserialize_partial;
use bitcoin::consensus::Decodable;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::sha256;
use bitcoin::script;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::Network;
use bitcoin::OutPoint;
use bitcoin::Target;
use bitcoin::Transaction;
use bitcoin::Work;
use floresta_common::Channel;
use log::debug;
use log::info;
use log::warn;
#[cfg(feature = "metrics")]
use metrics;
use rustreexo::accumulator::node_hash::BitcoinNodeHash;
use rustreexo::accumulator::proof::Proof;
use rustreexo::accumulator::stump::Stump;
use spin::RwLock;

use super::chain_state_builder::BlockchainBuilderError;
use super::chain_state_builder::ChainStateBuilder;
use super::chainparams::ChainParams;
use super::chainstore::DiskBlockHeader;
use super::consensus::Consensus;
use super::error::BlockValidationErrors;
use super::error::BlockchainError;
use super::partial_chain::PartialChainState;
use super::partial_chain::PartialChainStateInner;
use super::BlockchainInterface;
use super::ChainStore;
use super::UpdatableChainstate;
use crate::prelude::*;
use crate::pruned_utreexo::utxo_data::UtxoData;
use crate::read_lock;
use crate::write_lock;
use crate::UtreexoBlock;

/// Trait for components that need to receive notifications about new blocks.
pub trait BlockConsumer: Sync + Send + 'static {
    fn consume_block(&self, block: &Block, height: u32);
}

impl BlockConsumer for Channel<(Block, u32)> {
    fn consume_block(&self, block: &Block, height: u32) {
        self.send((block.to_owned(), height));
    }
}

/// Internal state of the blockchain managed by `ChainState`.
pub struct ChainStateInner<PersistedState: ChainStore> {
    /// The acc we use for validation.
    acc: Stump,
    /// All data is persisted here.
    chainstore: PersistedState,
    /// Best known block, cached in a specific field to faster access.
    best_block: BestChain,
    /// When one of our consumers tries to broadcast a transaction, this transaction gets
    /// written to broadcast_queue, and the ChainStateBackend can use it's own logic to actually
    /// broadcast the tx.
    broadcast_queue: Vec<Transaction>,
    /// We may have multiple modules that needs to receive and process blocks as they come, to
    /// be notified of new blocks, a module should implement the [BlockConsumer] trait, and
    /// subscribe by passing an [Arc] of itself to chainstate.
    /// When a new block is accepted (as valid) we call `consume_block` from [BlockConsumer].
    /// If a module just wants pass in a channel, [Sender] implements [BlockConsumer], and can
    /// be used during subscription (just keep the [Receiver] side.
    subscribers: Vec<Arc<dyn BlockConsumer>>,
    /// Fee estimation for 1, 10 and 20 blocks
    fee_estimation: (f64, f64, f64),
    /// Are we in Initial Block Download?
    ibd: bool,
    /// Parameters for the chain and functions that verify the chain.
    consensus: Consensus,
    /// Assume valid is a Core-specific config that tells the node to not validate signatures
    /// in blocks before this one. Note that we only skip signature validation, everything else
    /// is still validated.
    assume_valid: Option<BlockHash>,
}

/// The high-level chain backend managing the blockchain state.
///
/// `ChainState` is responsible for:
/// - Keeping track of the chain state with the help of a `ChainStore` for persisted storage.
/// - Correctly updating the state using consensus functions.
/// - Interfacing with other components and providing data about the current view of the chain.
pub struct ChainState<PersistedState: ChainStore> {
    inner: RwLock<ChainStateInner<PersistedState>>,
}

#[derive(Debug, Copy, Clone)]
/// Represents the argument for the assume-valid configuration.
///
/// This enum indicates the state of the assume-valid configuration,
/// which defines whether we should validate the scripts for blocks before this one.
/// You can either disable it, use a value provided by floresta or use your own value.
pub enum AssumeValidArg {
    /// Do not assume any script are valid, check every single one from genesis. This should make IBD considerably slower, but in theory has the best security model
    Disabled,
    /// Use the hard-coded value provided by Floresta. In this case, you trust that the Floresta repository faces enough scrutiny and review, and therefore the value can be trusted.
    Hardcoded,
    /// Provide your own value, moving the trust assumption to your program.
    UserInput(BlockHash),
}

impl<PersistedState: ChainStore> ChainState<PersistedState> {
    fn maybe_reindex(&self, potential_tip: &DiskBlockHeader) {
        if let DiskBlockHeader::HeadersOnly(_, height) = potential_tip {
            let best_height = self
                .get_best_block()
                .expect("infallible: in-memory BestChain is initialized")
                .0;

            if *height > best_height {
                let best_chain = self.reindex_chain();
                write_lock!(self).best_block = best_chain;
            }
        }
    }

    /// Just adds headers to the chainstate, without validating them.
    pub fn push_headers(
        &self,
        headers: Vec<BlockHeader>,
        height: u32,
    ) -> Result<(), BlockchainError> {
        let chainstore = &read_lock!(self).chainstore;
        for (offset, &header) in headers.iter().enumerate() {
            let block_hash = header.block_hash();
            let disk_header = DiskBlockHeader::FullyValid(header, height + offset as u32);
            chainstore.save_header(&disk_header)?;
            chainstore.update_block_index(height + offset as u32, block_hash)?;
        }
        Ok(())
    }
    #[cfg(feature = "bitcoinconsensus")]
    /// Returns the validation flags, given the current block height
    fn get_validation_flags(&self, height: u32, hash: BlockHash) -> c_uint {
        let chain_params = &read_lock!(self).consensus.parameters;

        if let Some(flag) = chain_params.exceptions.get(&hash) {
            return *flag;
        }

        // From Bitcoin Core:
        // BIP16 didn't become active until Apr 1 2012 (on mainnet, and
        // retroactively applied to testnet)
        // However, only one historical block violated the P2SH rules (on both
        // mainnet and testnet).
        // Similarly, only one historical block violated the TAPROOT rules on
        // mainnet.
        // For simplicity, always leave P2SH+WITNESS+TAPROOT on except for the two
        // violating blocks.
        let mut flags = bitcoinconsensus::VERIFY_P2SH | bitcoinconsensus::VERIFY_WITNESS;

        if height >= chain_params.params.bip65_height {
            flags |= bitcoinconsensus::VERIFY_CHECKLOCKTIMEVERIFY;
        }
        if height >= chain_params.params.bip66_height {
            flags |= bitcoinconsensus::VERIFY_DERSIG;
        }
        if height >= chain_params.csv_activation_height {
            flags |= bitcoinconsensus::VERIFY_CHECKSEQUENCEVERIFY;
        }
        if height >= chain_params.segwit_activation_height {
            flags |= bitcoinconsensus::VERIFY_NULLDUMMY;
        }
        flags
    }

    fn update_header(&self, header: &DiskBlockHeader) -> Result<(), BlockchainError> {
        Ok(read_lock!(self).chainstore.save_header(header)?)
    }

    fn validate_header(&self, block_header: &BlockHeader) -> Result<BlockHash, BlockchainError> {
        let prev_block = self.get_disk_block_header(&block_header.prev_blockhash)?;
        let height = prev_block
            .height()
            .ok_or(BlockValidationErrors::BlockExtendsAnOrphanChain)?
            + 1;

        // Check pow
        let expected_target = self.get_next_required_work(&prev_block, height, block_header);

        let actual_target = block_header.target();
        if actual_target > expected_target {
            return Err(BlockValidationErrors::NotEnoughPow)?;
        }

        let block_hash = block_header
            .validate_pow(actual_target)
            .map_err(|_| BlockValidationErrors::NotEnoughPow)?;
        Ok(block_hash)
    }

    #[inline]
    /// Whether a node is the genesis block for this net
    fn is_genesis(&self, header: &BlockHeader) -> bool {
        header.block_hash() == self.chain_params().genesis.block_hash()
    }
    #[inline]
    /// Returns the ancestor of a given block
    fn get_ancestor(&self, header: &BlockHeader) -> Result<DiskBlockHeader, BlockchainError> {
        self.get_disk_block_header(&header.prev_blockhash)
    }
    /// Returns the cumulative work in this branch
    fn get_branch_work(&self, header: &BlockHeader) -> Result<Work, BlockchainError> {
        let mut header = *header;
        let mut work = Work::from_be_bytes([0; 32]);
        while !self.is_genesis(&header) {
            work = work + header.work();
            header = *self.get_ancestor(&header)?;
        }

        Ok(work)
    }
    /// Checks if a branch is valid (i.e. all ancestors are known)
    fn check_branch(&self, branch_tip: &BlockHeader) -> Result<(), BlockchainError> {
        let mut header = *branch_tip;

        while !self.is_genesis(&header) {
            let _header = self.get_ancestor(&header)?;
            if let DiskBlockHeader::Orphan(block) = _header {
                return Err(BlockchainError::InvalidTip(format(format_args!(
                    "Block {} doesn't have a known ancestor (i.e an orphan block)",
                    block.block_hash()
                ))));
            }
            header = *_header;
        }

        Ok(())
    }
    /// Returns the depth of a branch (i.e. how many blocks are in the branch)
    fn get_chain_depth(&self, branch_tip: &BlockHeader) -> Result<u32, BlockchainError> {
        let mut header = *branch_tip;

        let mut counter = 0;
        while !self.is_genesis(&header) {
            header = *self.get_ancestor(&header)?;
            counter += 1;
        }

        Ok(counter)
    }
    /// Mark the current index as active, because we are in the middle of a reorg
    fn mark_chain_as_active(
        &self,
        new_tip: &BlockHeader,
        fork_point: BlockHash,
    ) -> Result<(), BlockchainError> {
        let mut height = self.get_chain_depth(new_tip)?;
        let mut header = DiskBlockHeader::HeadersOnly(*new_tip, height);

        let inner = read_lock!(self);

        while !self.is_genesis(&header) || header.block_hash() == fork_point {
            inner
                .chainstore
                .update_block_index(height, header.block_hash())?;
            let new_header = DiskBlockHeader::HeadersOnly(*header, height);
            inner.chainstore.save_header(&new_header)?;
            header = self.get_ancestor(&header)?;
            height -= 1;
        }
        Ok(())
    }

    /// Mark the current index as inactive, either because we found an invalid ancestor,
    /// or we are in the middle of reorg
    fn mark_chain_as_inactive(
        &self,
        old_tip: &BlockHeader,
        fork_point: BlockHash,
    ) -> Result<(), BlockchainError> {
        let mut header = *old_tip;
        let mut height = self.get_chain_depth(old_tip)?;

        let inner = read_lock!(self);
        while !self.is_genesis(&header) || header.block_hash() == fork_point {
            let new_header = DiskBlockHeader::InFork(header, height);
            inner.chainstore.save_header(&new_header)?;
            header = *self.get_ancestor(&header)?;
            height -= 1;
        }

        Ok(())
    }
    /// Finds where in the current index, a given branch forks out.
    fn find_fork_point(&self, header: &BlockHeader) -> Result<BlockHeader, BlockchainError> {
        let mut header = *self.get_ancestor(header)?;
        let inner = read_lock!(self);
        while !self.is_genesis(&header) {
            match inner.chainstore.get_header(&header.block_hash())? {
                Some(DiskBlockHeader::HeadersOnly(block, _)) => {
                    return Ok(block);
                }
                Some(DiskBlockHeader::FullyValid(block, _)) => {
                    return Ok(block);
                }
                Some(DiskBlockHeader::InFork(block, _)) => {
                    header = *self.get_ancestor(&block)?;
                    continue;
                }
                Some(DiskBlockHeader::AssumedValid(block, _)) => {
                    return Ok(block);
                }
                Some(DiskBlockHeader::Orphan(header)) => {
                    return Err(BlockchainError::InvalidTip(format(format_args!(
                        "Block {} doesn't have a known ancestor (i.e an orphan block)",
                        header.block_hash()
                    ))));
                }
                Some(DiskBlockHeader::InvalidChain(header)) => {
                    return Err(BlockchainError::InvalidTip(format(format_args!(
                        "Block {} is invalid",
                        header.block_hash()
                    ))));
                }
                None => {
                    return Err(BlockchainError::InvalidTip(format(format_args!(
                        "Block {} isn't in our storage",
                        header.block_hash()
                    ))));
                }
            }
        }
        Err(BlockchainError::InvalidTip(
            "Couldn't find a fork point".to_string(),
        ))
    }

    // This method should only be called after we validate the new branch
    fn reorg(&self, new_tip: BlockHeader) -> Result<(), BlockchainError> {
        let current_best_block = self.get_block_header(&self.get_best_block()?.1)?;
        let fork_point = self.find_fork_point(&new_tip)?;

        self.mark_chain_as_inactive(&current_best_block, fork_point.block_hash())?;
        self.mark_chain_as_active(&new_tip, fork_point.block_hash())?;

        let validation_index = self.get_last_valid_block(&new_tip)?;
        let depth = self.get_chain_depth(&new_tip)?;
        self.change_active_chain(&new_tip, validation_index, depth);

        Ok(())
    }

    /// Changes the active chain to the new branch during a reorg
    fn change_active_chain(&self, new_tip: &BlockHeader, last_valid: BlockHash, depth: u32) {
        let mut inner = self.inner.write();
        inner.best_block.best_block = new_tip.block_hash();
        inner.best_block.validation_index = last_valid;
        inner.best_block.depth = depth;
        inner.acc = Stump::new();
    }
    /// Grabs the last block we validated in this branch. We don't validate a fork, unless it
    /// becomes the best chain. This function technically finds out what is the last common block
    /// between two branches.
    fn get_last_valid_block(&self, header: &BlockHeader) -> Result<BlockHash, BlockchainError> {
        let mut header = *header;

        while !self.is_genesis(&header) {
            let _header = self.get_ancestor(&header)?;
            match _header {
                DiskBlockHeader::FullyValid(_, _) | DiskBlockHeader::AssumedValid(_, _) => {
                    return Ok(header.block_hash())
                }
                DiskBlockHeader::Orphan(_) => {
                    return Err(BlockchainError::InvalidTip(format(format_args!(
                        "Block {} doesn't have a known ancestor (i.e an orphan block)",
                        header.block_hash()
                    ))))
                }
                DiskBlockHeader::HeadersOnly(_, _) | DiskBlockHeader::InFork(_, _) => {}
                DiskBlockHeader::InvalidChain(_) => {
                    return Err(BlockchainError::InvalidTip(format(format_args!(
                        "Block {} is in an invalid chain",
                        header.block_hash()
                    ))))
                }
            }

            header = *_header;
        }
        Ok(header.block_hash())
    }
    /// If we get a header that doesn't build on top of our best chain, it may cause a reorganization.
    /// We check this here.
    fn maybe_reorg(&self, branch_tip: BlockHeader) -> Result<(), BlockchainError> {
        let current_tip = self.get_block_header(&self.get_best_block()?.1)?;
        self.check_branch(&branch_tip)?;

        let current_work = self.get_branch_work(&current_tip)?;
        let new_work = self.get_branch_work(&branch_tip)?;
        // If the new branch has more work, it becomes the new best chain
        if new_work > current_work {
            self.reorg(branch_tip)?;
            return Ok(());
        }
        // If the new branch has less work, we just store it as an alternative branch
        // that might become the best chain in the future.
        self.push_alt_tip(&branch_tip)?;

        let parent_height = self.get_ancestor(&branch_tip)?.try_height()?;

        read_lock!(self)
            .chainstore
            .save_header(&DiskBlockHeader::InFork(branch_tip, parent_height + 1))?;

        Ok(())
    }
    /// Stores a new tip for a branch that is not the best one
    fn push_alt_tip(&self, branch_tip: &BlockHeader) -> Result<(), BlockchainError> {
        let ancestor = self.get_ancestor(branch_tip);
        let ancestor = match ancestor {
            Ok(ancestor) => Some(ancestor),
            Err(BlockchainError::BlockNotPresent) => None,
            Err(e) => return Err(e),
        };
        let mut inner = write_lock!(self);
        if let Some(ancestor) = ancestor {
            let ancestor_hash = ancestor.block_hash();
            if let Some(idx) = inner
                .best_block
                .alternative_tips
                .iter()
                .position(|hash| ancestor_hash == *hash)
            {
                inner.best_block.alternative_tips.remove(idx);
            }
        }
        inner
            .best_block
            .alternative_tips
            .push(branch_tip.block_hash());
        Ok(())
    }

    /// Returns the chain_params struct for the current network
    fn chain_params(&self) -> ChainParams {
        let inner = read_lock!(self);
        // We clone the parameters here, because we don't want to hold the lock for too long
        inner.consensus.parameters.clone()
    }
    // This function should be only called if a block is guaranteed to be on chain
    fn get_block_header_by_height(&self, height: u32) -> BlockHeader {
        let block = self
            .get_block_hash(height)
            .expect("This block should be present");
        self.get_block_header(&block)
            .expect("This block should also be present")
    }
    fn save_acc(&self) -> Result<(), bitcoin::consensus::encode::Error> {
        let inner = read_lock!(self);
        let mut ser_acc: Vec<u8> = Vec::new();
        inner.acc.leaves.consensus_encode(&mut ser_acc)?;

        for root in inner.acc.roots.iter() {
            ser_acc
                .write_all(&**root)
                .expect("String formatting should not err");
        }

        inner
            .chainstore
            .save_roots(ser_acc)
            .expect("Chain store is not working");
        Ok(())
    }
    fn notify(&self, block: &Block, height: u32) {
        let inner = self.inner.read();
        let subs = inner.subscribers.iter();
        for client in subs {
            client.consume_block(block, height);
        }
    }

    pub fn new(
        chainstore: PersistedState,
        network: Network,
        assume_valid: AssumeValidArg,
    ) -> ChainState<PersistedState> {
        // TODO: handle possible Err
        let parameters = network.try_into().expect("Unsupported network");
        let genesis = genesis_block(&parameters);

        chainstore
            .save_header(&super::chainstore::DiskBlockHeader::FullyValid(
                genesis.header,
                0,
            ))
            .expect("Error while saving genesis");

        chainstore
            .update_block_index(0, genesis.block_hash())
            .expect("Error updating index");

        // TODO: handle possible Err
        let assume_valid =
            ChainParams::get_assume_valid(network, assume_valid).expect("Unsupported network");
        ChainState {
            inner: RwLock::new(ChainStateInner {
                chainstore,
                acc: Stump::new(),
                best_block: BestChain {
                    best_block: genesis.block_hash(),
                    depth: 0,
                    validation_index: genesis.block_hash(),
                    alternative_tips: Vec::new(),
                    assume_valid_index: 0,
                },
                broadcast_queue: Vec::new(),
                subscribers: Vec::new(),
                fee_estimation: (1_f64, 1_f64, 1_f64),
                ibd: true,
                consensus: Consensus { parameters },
                assume_valid,
            }),
        }
    }

    /// Fetches a `DiskBlockHeader` from the chain store given its block hash. Returns an error if
    /// it's not present or if the database operation failed.
    fn get_disk_block_header(&self, hash: &BlockHash) -> Result<DiskBlockHeader, BlockchainError> {
        let inner = read_lock!(self);
        if let Some(header) = inner.chainstore.get_header(hash)? {
            return Ok(header);
        }
        Err(BlockchainError::BlockNotPresent)
    }

    /// If we ever find ourselves in an undefined state, with one of our chain pointers
    /// pointing to an invalid block, we'll find out what blocks do we have, and start from this
    /// point.
    fn reindex_chain(&self) -> BestChain {
        let get_disk_block_hash =
            |height: u32| -> Result<Option<BlockHash>, PersistedState::Error> {
                read_lock!(self).chainstore.get_block_hash(height)
            };

        warn!("reindexing our chain");
        let mut best_block = get_disk_block_hash(0)
            // TODO: handle possible Err
            .expect("TODO handle chainstore error")
            .expect("expected genesis block, found None");

        let mut depth = 0;
        let mut validation_index = best_block;
        let mut next_height = depth + 1;

        // Iteratively fetch the disk header given the next height
        while let Ok(Some(block_hash)) = get_disk_block_hash(next_height) {
            match self.get_disk_block_header(&block_hash) {
                Ok(DiskBlockHeader::FullyValid(_, height)) => {
                    assert_eq!(height, next_height);
                    validation_index = block_hash;
                }
                Ok(DiskBlockHeader::HeadersOnly(_, height)) => {
                    assert_eq!(height, next_height);
                }
                _ => break,
            }
            best_block = block_hash;
            depth = next_height;
            next_height += 1;
        }
        BestChain {
            best_block,
            depth,
            validation_index,
            alternative_tips: Vec::new(),
            assume_valid_index: 0,
        }
    }

    pub fn load_chain_state(
        chainstore: PersistedState,
        network: Network,
        assume_valid: AssumeValidArg,
    ) -> Result<ChainState<PersistedState>, BlockchainError> {
        let acc = Self::load_acc(&chainstore);

        let best_block = chainstore
            .load_height()?
            .ok_or(BlockchainError::ChainNotInitialized)?;

        let inner = ChainStateInner {
            acc,
            best_block,
            broadcast_queue: Vec::new(),
            chainstore,
            fee_estimation: (1_f64, 1_f64, 1_f64),
            subscribers: Vec::new(),
            ibd: true,
            consensus: Consensus {
                // TODO: handle possible Err
                parameters: network.try_into().expect("Unsupported network"),
            },
            // TODO: handle possible Err
            assume_valid: ChainParams::get_assume_valid(network, assume_valid)
                .expect("Unsupported network"),
        };
        info!(
            "Chainstate loaded at height: {}, checking if we have all blocks",
            inner.best_block.best_block
        );
        let chainstate = ChainState {
            inner: RwLock::new(inner),
        };
        // Check the integrity of our chain
        chainstate.check_chain_integrity();
        Ok(chainstate)
    }

    fn check_chain_integrity(&self) {
        let (best_height, best_hash) = self
            .get_best_block()
            .expect("infallible: in-memory BestChain is initialized");

        // make sure our index is right for the latest block
        let best_disk_height = self
            .get_disk_block_header(&best_hash)
            .expect("should have this loaded")
            .height()
            .expect("should have this loaded");

        if best_height != best_disk_height {
            self.reindex_chain();
        }

        // make sure our validation index is pointing to a valid block
        let validation_index = self
            .get_best_block()
            .expect("infallible: in-memory BestChain is initialized")
            .1;

        let last_valid_header = self
            .get_disk_block_header(&validation_index)
            .expect("should have this loaded");

        if !matches!(last_valid_header, DiskBlockHeader::FullyValid(_, _)) {
            self.reindex_chain();
        }
    }

    fn load_acc<Storage: ChainStore>(data_storage: &Storage) -> Stump {
        let acc = data_storage
            .load_roots()
            // TODO: handle possible Err
            .expect("load_acc: Could not read roots");

        let mut acc = match acc {
            Some(acc) => acc,
            None => return Stump::new(),
        };

        let leaves = acc.drain(0..8).collect::<Vec<u8>>();
        let (leaves, _) =
            deserialize_partial::<u64>(&leaves).expect("load_acc: Invalid num_leaves");
        let mut roots = Vec::new();
        // Since we only expect hashes after the num_leaves, the length of the acc has to be a multiple of 32.
        assert_eq!(acc.len() % 32, 0);
        while acc.len() >= 32 {
            let root = acc.drain(0..32).collect::<Vec<u8>>();
            let root = BitcoinNodeHash::from(&*root);
            roots.push(root);
        }
        Stump { leaves, roots }
    }
    fn update_view(
        &self,
        height: u32,
        block: &BlockHeader,
        acc: Stump,
    ) -> Result<(), BlockchainError> {
        let mut inner = write_lock!(self);
        inner
            .chainstore
            .save_header(&super::chainstore::DiskBlockHeader::FullyValid(
                *block, height,
            ))?;
        inner
            .chainstore
            .update_block_index(height, block.block_hash())?;
        // Updates our local view of the network
        inner.acc = acc;
        inner.best_block.valid_block(block.block_hash());
        Ok(())
    }
    fn update_tip(&self, best_block: BlockHash, height: u32) {
        let mut inner = write_lock!(self);
        inner.best_block.best_block = best_block;
        inner.best_block.depth = height;
    }
    fn verify_script(&self, height: u32) -> Result<bool, PersistedState::Error> {
        let inner = self.inner.read();
        match inner.assume_valid {
            Some(hash) => {
                match inner.chainstore.get_header(&hash)? {
                    // If the assume-valid block is in the best chain, only verify scripts if we are higher
                    Some(DiskBlockHeader::HeadersOnly(_, assume_h))
                    | Some(DiskBlockHeader::FullyValid(_, assume_h)) => Ok(height > assume_h),
                    // Assume-valid is not in the best chain, so verify all the scripts
                    _ => Ok(true),
                }
            }
            None => Ok(true),
        }
    }
    pub fn acc(&self) -> Stump {
        read_lock!(self).acc.to_owned()
    }
    /// Returns the next required work for the next block, usually it's just the last block's target
    /// but if we are in a retarget period, it's calculated from the last 2016 blocks.
    fn get_next_required_work(
        &self,
        last_block: &BlockHeader,
        next_height: u32,
        next_header: &BlockHeader,
    ) -> Target {
        let params: ChainParams = self.chain_params();
        // Special testnet rule, if a block takes more than 20 minutes to mine, we can
        // mine a block with diff 1
        if params.params.allow_min_difficulty_blocks
            && last_block.time + params.params.pow_target_spacing as u32 * 2 < next_header.time
        {
            return params.params.max_attainable_target;
        }

        // Regtest don't have retarget
        if !params.params.no_pow_retargeting && (next_height) % 2016 == 0 {
            // First block in this epoch
            let first_block = self.get_block_header_by_height(next_height - 2016);
            let last_block = self.get_block_header_by_height(next_height - 1);

            let target =
                Consensus::calc_next_work_required(&last_block, &first_block, self.chain_params());

            if target < params.params.max_attainable_target {
                return target;
            }

            return params.params.max_attainable_target;
        }
        last_block.target()
    }

    pub fn get_bip34_height(&self, block: &Block) -> Option<u32> {
        let cb = block.coinbase()?;
        let input = cb.input.first()?;
        let push = input.script_sig.instructions_minimal().next()?;

        match push {
            Ok(script::Instruction::PushBytes(b)) => {
                let h = script::read_scriptint(b.as_bytes()).ok()?;
                Some(h as u32)
            }

            Ok(script::Instruction::Op(opcode)) => {
                let opcode = opcode.to_u8();
                if (0x51..=0x60).contains(&opcode) {
                    Some(opcode as u32 - 0x50)
                } else {
                    None
                }
            }

            _ => None,
        }
    }

    /// Validates the block without checking whether the inputs are present in the UTXO set. This
    /// function contains the core validation logic.
    ///
    /// The methods `BlockchainInterface::validate_block` and `UpdatableChainstate::connect_block`
    /// call this and additionally verify the inclusion proof (i.e., they perform full validation).
    pub fn validate_block_no_acc(
        &self,
        block: &Block,
        height: u32,
        inputs: HashMap<OutPoint, UtxoData>,
    ) -> Result<(), BlockchainError> {
        if !block.check_merkle_root() {
            return Err(BlockValidationErrors::BadMerkleRoot)?;
        }

        let bip34_height = self.chain_params().params.bip34_height;
        // If bip34 is active, check that the encoded block height is correct
        if height >= bip34_height && self.get_bip34_height(block) != Some(height) {
            return Err(BlockValidationErrors::BadBip34)?;
        }

        if !block.check_witness_commitment() {
            return Err(BlockValidationErrors::BadWitnessCommitment)?;
        }

        if block.weight().to_wu() > 4_000_000 {
            return Err(BlockValidationErrors::BlockTooBig)?;
        }

        // Validate block transactions
        let subsidy = read_lock!(self).consensus.get_subsidy(height);
        let verify_script = self.verify_script(height)?;
        #[cfg(feature = "bitcoinconsensus")]
        let flags = self.get_validation_flags(height, block.block_hash());
        #[cfg(not(feature = "bitcoinconsensus"))]
        let flags = 0;
        Consensus::verify_block_transactions(
            height,
            inputs,
            &block.txdata,
            subsidy,
            verify_script,
            flags,
        )?;
        Ok(())
    }
}

impl<PersistedState: ChainStore> BlockchainInterface for ChainState<PersistedState> {
    type Error = BlockchainError;

    fn get_params(&self) -> bitcoin::params::Params {
        self.chain_params().params
    }

    fn acc(&self) -> Stump {
        read_lock!(self).acc.to_owned()
    }

    fn get_fork_point(&self, block: BlockHash) -> Result<BlockHash, Self::Error> {
        let fork_point = self.find_fork_point(&self.get_block_header(&block)?)?;
        Ok(fork_point.block_hash())
    }

    fn update_acc(
        &self,
        acc: Stump,
        block: UtreexoBlock,
        height: u32,
        proof: Proof,
        del_hashes: Vec<sha256::Hash>,
    ) -> Result<Stump, Self::Error> {
        Consensus::update_acc(&acc, &block.block, height, proof, del_hashes)
    }

    fn get_chain_tips(&self) -> Result<Vec<BlockHash>, Self::Error> {
        let inner = read_lock!(self);
        let mut tips = Vec::new();

        tips.push(inner.best_block.best_block);
        tips.extend(inner.best_block.alternative_tips.iter());

        Ok(tips)
    }

    fn validate_block(
        &self,
        block: &Block,
        proof: Proof,
        inputs: HashMap<OutPoint, UtxoData>,
        del_hashes: Vec<sha256::Hash>,
        acc: Stump,
    ) -> Result<(), Self::Error> {
        // Convert to BitcoinNodeHashes, from rustreexo
        let del_hashes: Vec<_> = del_hashes.into_iter().map(Into::into).collect();

        if !acc.verify(&proof, &del_hashes)? {
            return Err(BlockValidationErrors::InvalidProof)?;
        }

        let height = self
            .get_disk_block_header(&block.block_hash())?
            .try_height()?;

        self.validate_block_no_acc(block, height, inputs)
    }

    fn get_block_locator_for_tip(&self, tip: BlockHash) -> Result<Vec<BlockHash>, BlockchainError> {
        let mut hashes = Vec::new();
        let height = self.get_disk_block_header(&tip)?.try_height()?;

        let mut index = height;
        let mut current_height = height;
        let mut current_header = self.get_disk_block_header(&tip)?;
        let mut step = 1;

        while index > 0 {
            while current_height > index {
                current_header = self.get_ancestor(&current_header)?;
                current_height -= 1;
            }

            if hashes.len() >= 10 {
                step *= 2;
            }

            hashes.push(current_header.block_hash());

            if index > step {
                index -= step;
            } else {
                break;
            }
        }

        // genesis
        hashes.push(self.get_block_hash(0)?);
        Ok(hashes)
    }

    fn is_in_ibd(&self) -> bool {
        self.inner.read().ibd
    }

    fn get_block_height(&self, hash: &BlockHash) -> Result<Option<u32>, Self::Error> {
        self.get_disk_block_header(hash)
            .map(|header| header.height())
    }

    fn get_block_hash(&self, height: u32) -> Result<bitcoin::BlockHash, Self::Error> {
        let inner = self.inner.read();
        if let Some(hash) = inner.chainstore.get_block_hash(height)? {
            return Ok(hash);
        }
        Err(BlockchainError::BlockNotPresent)
    }

    fn get_tx(&self, _txid: &bitcoin::Txid) -> Result<Option<bitcoin::Transaction>, Self::Error> {
        unimplemented!("This chainstate doesn't hold any tx")
    }

    fn get_height(&self) -> Result<u32, Self::Error> {
        let inner = read_lock!(self);
        Ok(inner.best_block.depth)
    }

    fn broadcast(&self, tx: &bitcoin::Transaction) -> Result<(), Self::Error> {
        let mut inner = write_lock!(self);
        inner.broadcast_queue.push(tx.clone());
        Ok(())
    }

    fn estimate_fee(&self, target: usize) -> Result<f64, Self::Error> {
        let inner = read_lock!(self);
        if target == 1 {
            Ok(inner.fee_estimation.0)
        } else if target == 10 {
            Ok(inner.fee_estimation.1)
        } else {
            Ok(inner.fee_estimation.2)
        }
    }

    fn get_block(&self, _hash: &BlockHash) -> Result<bitcoin::Block, Self::Error> {
        unimplemented!("This chainstate doesn't hold full blocks")
    }

    fn get_best_block(&self) -> Result<(u32, BlockHash), Self::Error> {
        let inner = read_lock!(self);
        Ok((inner.best_block.depth, inner.best_block.best_block))
    }

    fn get_block_header(&self, hash: &BlockHash) -> Result<bitcoin::block::Header, Self::Error> {
        let inner = read_lock!(self);
        if let Some(header) = inner.chainstore.get_header(hash)? {
            return Ok(*header);
        }
        Err(BlockchainError::BlockNotPresent)
    }

    fn subscribe(&self, tx: Arc<dyn BlockConsumer>) {
        let mut inner = self.inner.write();
        inner.subscribers.push(tx);
    }

    fn get_block_locator(&self) -> Result<Vec<BlockHash>, BlockchainError> {
        let top_height = self.get_height()?;
        let mut indexes = Vec::new();
        let mut step = 1;
        let mut index = top_height;
        while index > 0 {
            if indexes.len() >= 10 {
                step *= 2;
            }
            indexes.push(index);
            if index > step {
                index -= step;
            } else {
                break;
            }
        }
        indexes.push(0);
        let hashes = indexes
            .iter()
            .flat_map(|idx| self.get_block_hash(*idx))
            .collect();

        Ok(hashes)
    }
    fn get_validation_index(&self) -> Result<u32, Self::Error> {
        let inner = self.inner.read();
        let validation = inner.best_block.validation_index;
        let header = self.get_disk_block_header(&validation)?;
        // The last validated disk header can only be FullyValid
        if let DiskBlockHeader::FullyValid(_, height) = header {
            Ok(height)
        } else {
            unreachable!(
                "Validation index is in an invalid state, you should re-index your node {header:?}"
            )
        }
    }

    fn is_coinbase_mature(&self, height: u32, block: BlockHash) -> Result<bool, Self::Error> {
        let chain_params = self.chain_params();
        let current_height = self.get_disk_block_header(&block)?.try_height()?;

        Ok(height + chain_params.coinbase_maturity <= current_height)
    }

    fn get_unbroadcasted(&self) -> Vec<Transaction> {
        let mut inner = write_lock!(self);
        inner.broadcast_queue.drain(..).collect()
    }
}
impl<PersistedState: ChainStore> UpdatableChainstate for ChainState<PersistedState> {
    fn switch_chain(&self, new_tip: BlockHash) -> Result<(), BlockchainError> {
        let new_tip = self.get_block_header(&new_tip)?;
        self.reorg(new_tip)
    }

    fn get_acc(&self) -> Stump {
        self.acc()
    }

    fn mark_block_as_valid(&self, block: BlockHash) -> Result<(), BlockchainError> {
        let header = self.get_disk_block_header(&block)?;
        let height = header.try_height()?;

        let new_header = DiskBlockHeader::FullyValid(*header, height);
        self.update_header(&new_header)
    }

    fn mark_chain_as_assumed(
        &self,
        acc: Stump,
        assumed_hash: BlockHash,
    ) -> Result<bool, BlockchainError> {
        let mut curr_header = self.get_block_header(&assumed_hash)?;

        while let Ok(header) = self.get_disk_block_header(&curr_header.block_hash()) {
            if self.is_genesis(&header) {
                break;
            }
            let height = header.try_height()?;

            self.update_header(&DiskBlockHeader::FullyValid(*header, height))?;
            curr_header = *self.get_ancestor(&header)?;
        }

        let mut guard = write_lock!(self);
        guard.best_block.validation_index = assumed_hash;
        guard.acc = acc;

        Ok(true)
    }

    fn invalidate_block(&self, block: BlockHash) -> Result<(), BlockchainError> {
        let height = self.get_disk_block_header(&block)?.try_height()?;
        let current_height = self.get_height()?;

        // Mark all blocks after this one as invalid
        for h in height..=current_height {
            let hash = self.get_block_hash(h)?;
            let header = self.get_block_header(&hash)?;
            let new_header = DiskBlockHeader::InvalidChain(header);
            self.update_header(&new_header)?;
        }
        // Row back to our previous state. Note that acc doesn't actually change in this case
        // only the currently best known block.
        self.update_tip(
            self.get_ancestor(&self.get_block_header(&block)?)?
                .block_hash(),
            height - 1,
        );
        Ok(())
    }

    fn toggle_ibd(&self, is_ibd: bool) {
        let mut inner = write_lock!(self);
        inner.ibd = is_ibd;
    }

    fn connect_block(
        &self,
        block: &Block,
        proof: Proof,
        inputs: HashMap<OutPoint, UtxoData>,
        del_hashes: Vec<sha256::Hash>,
    ) -> Result<u32, BlockchainError> {
        let header = self.get_disk_block_header(&block.block_hash())?;
        let height = match header {
            DiskBlockHeader::FullyValid(_, height) => {
                let validation_index = self.get_validation_index()?;

                // If this block is not our validation index, but the caller is trying to connect
                // it, this is a logical error, and we will have spurious errors, specially with
                // invalid proof. They don't mean the block is invalid, just that we are using the
                // wrong accumulator, since we are not processing the right block.
                if height != validation_index {
                    return Err(BlockValidationErrors::BlockDoesntExtendTip)?;
                }

                // If this block is our validation index, but it's fully valid, this clearly means
                // there was some corruption of our state. If we don't process this block, we will
                // be stuck forever.
                //
                // Note: You may think "just kick the validation index one block further and we are
                // good". But this is not the case, because we still need to update our
                // accumulator. Otherwise, the next block will always have an invalid proof
                // (because the accumulator is not updated).
                height
            },

            // Our called tried to connect_block on a block that is not the next one in our chain
            DiskBlockHeader::Orphan(_)
            | DiskBlockHeader::AssumedValid(_, _) // this will be validated by a partial chain
            | DiskBlockHeader::InFork(_, _)
            | DiskBlockHeader::InvalidChain(_) => return Err(BlockValidationErrors::BlockExtendsAnOrphanChain)?,

            DiskBlockHeader::HeadersOnly(_, height) => {
                let validation_index = self.get_validation_index()?;

                // In case of a `HeadersOnly` block, we need to check if the height is
                // the next one after the validation index. If not, we would be trying to
                // connect a block where our accumulator isn't the right one. So the proof will
                // always be invalid.
                if height != validation_index + 1 {
                    return Err(BlockValidationErrors::BlockDoesntExtendTip)?;
                }

                height
            }
        };

        self.validate_block_no_acc(block, height, inputs)?;
        let acc = Consensus::update_acc(&self.acc(), block, height, proof, del_hashes)?;

        self.update_view(height, &block.header, acc)?;

        info!(
            "New tip! hash={} height={height} tx_count={}",
            block.block_hash(),
            block.txdata.len()
        );

        #[cfg(feature = "metrics")]
        metrics::get_metrics().block_height.set(height.into());

        if !self.is_in_ibd() || height % 100_000 == 0 {
            self.flush()?;
        }

        // Notify others we have a new block
        self.notify(block, height);
        Ok(height)
    }

    fn handle_transaction(&self) -> Result<(), BlockchainError> {
        unimplemented!("This chain_state has no mempool")
    }

    fn flush(&self) -> Result<(), BlockchainError> {
        self.save_acc()?;
        let inner = read_lock!(self);
        inner.chainstore.save_height(&inner.best_block)?;
        inner.chainstore.flush()?;
        Ok(())
    }

    fn accept_header(&self, header: BlockHeader) -> Result<(), BlockchainError> {
        debug!("Accepting header {header:?}");
        let disk_header = self.get_disk_block_header(&header.block_hash());

        match disk_header {
            Err(e @ BlockchainError::Database(_)) => {
                // If there's a database error we don't know if we already
                // have the header or not
                return Err(e);
            }
            Ok(found) => {
                // Possibly reindex to recompute the best_block field
                self.maybe_reindex(&found);
                // We already have this header
                return Ok(());
            }
            _ => (),
        }
        // The best block we know of
        let best_block = self.get_best_block()?;

        // Do validation in this header
        let block_hash = self.validate_header(&header)?;

        // Update our current tip
        if header.prev_blockhash == best_block.1 {
            let height = best_block.0 + 1;
            debug!("Header builds on top of our best chain");

            let mut inner = write_lock!(self);
            inner.best_block.new_block(block_hash, height);
            inner
                .chainstore
                .save_header(&super::chainstore::DiskBlockHeader::HeadersOnly(
                    header, height,
                ))?;

            inner.chainstore.update_block_index(height, block_hash)?;
        } else {
            debug!("Header not in the best chain");
            self.maybe_reorg(header)?;
        }

        Ok(())
    }

    fn get_root_hashes(&self) -> Vec<BitcoinNodeHash> {
        let inner = read_lock!(self);
        inner.acc.roots.clone()
    }

    fn get_partial_chain(
        &self,
        initial_height: u32,
        final_height: u32,
        acc: Stump,
    ) -> Result<super::partial_chain::PartialChainState, BlockchainError> {
        let blocks = (0..=final_height)
            .map(|height| {
                let hash = self
                    .get_block_hash(height)
                    .expect("Block should be present");
                *self
                    .get_disk_block_header(&hash)
                    .expect("Block should be present")
            })
            .collect();

        let inner = PartialChainStateInner {
            error: None,
            blocks,
            consensus: Consensus {
                parameters: self.chain_params(),
            },
            current_acc: acc,
            final_height,
            assume_valid: false,
            current_height: initial_height,
        };

        Ok(PartialChainState(UnsafeCell::new(inner)))
    }
}

impl<T: ChainStore> TryFrom<ChainStateBuilder<T>> for ChainState<T> {
    type Error = BlockchainBuilderError;

    fn try_from(mut builder: ChainStateBuilder<T>) -> Result<Self, Self::Error> {
        let inner = ChainStateInner {
            acc: builder.acc().unwrap_or_default(),
            chainstore: builder.chainstore()?,
            best_block: builder.best_block()?,
            assume_valid: builder.assume_valid(),
            ibd: builder.ibd(),
            broadcast_queue: Vec::new(),
            subscribers: Vec::new(),
            fee_estimation: (1_f64, 1_f64, 1_f64),
            consensus: Consensus {
                parameters: builder.chain_params()?,
            },
        };

        let inner = RwLock::new(inner);
        Ok(Self { inner })
    }
}

#[macro_export]
/// Grabs a RwLock for reading
macro_rules! read_lock {
    ($obj:ident) => {
        $obj.inner.read()
    };
}
#[macro_export]
/// Grabs a RwLock for writing
macro_rules! write_lock {
    ($obj:ident) => {
        $obj.inner.write()
    };
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Internal representation of the chain we are in
pub struct BestChain {
    /// Hash of the last block in the chain we believe has more work on
    pub best_block: BlockHash,
    /// How many blocks are pilled on this chain?
    pub depth: u32,
    /// We actually validated blocks up to this point
    pub validation_index: BlockHash,
    /// Blockchains are not fast-forward only, they might have "forks", sometimes it's useful
    /// to keep track of them, in case they become the best one. This keeps track of some
    /// tips we know about, but are not the best one. We don't keep tips that are too deep
    /// or has too little work if compared to our best one
    pub alternative_tips: Vec<BlockHash>,
    /// Saves the height occupied by the assume valid block
    pub assume_valid_index: u32,
}

impl BestChain {
    fn new_block(&mut self, block_hash: BlockHash, height: u32) {
        self.best_block = block_hash;
        self.depth = height;
    }
    fn valid_block(&mut self, block_hash: BlockHash) {
        self.validation_index = block_hash;
    }
}
impl Encodable for BestChain {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> bitcoin::io::Result<usize> {
        let mut len = 0;
        len += self.best_block.consensus_encode(writer)?;
        len += self.depth.consensus_encode(writer)?;
        len += self.validation_index.consensus_encode(writer)?;
        len += self.assume_valid_index.consensus_encode(writer)?;
        len += self.alternative_tips.consensus_encode(writer)?;
        Ok(len)
    }
}

impl From<(BlockHash, u32)> for BestChain {
    fn from((best_block, depth): (BlockHash, u32)) -> Self {
        Self {
            best_block,
            depth,
            validation_index: best_block,
            assume_valid_index: 0,
            alternative_tips: Vec::new(),
        }
    }
}

impl Decodable for BestChain {
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let best_block = BlockHash::consensus_decode(reader)?;
        let depth = u32::consensus_decode(reader)?;
        let validation_index = BlockHash::consensus_decode(reader)?;
        let assume_valid_index = u32::consensus_decode(reader)?;

        let alternative_tips = <Vec<BlockHash>>::consensus_decode(reader)?;
        Ok(Self {
            alternative_tips,
            best_block,
            depth,
            validation_index,
            assume_valid_index,
        })
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use core::str::FromStr;
    use std::format;
    use std::fs::File;
    use std::io::Cursor;
    use std::vec::Vec;

    use bitcoin::block::Header as BlockHeader;
    use bitcoin::consensus::deserialize;
    use bitcoin::consensus::encode::deserialize_hex;
    use bitcoin::consensus::Decodable;
    use bitcoin::Block;
    use bitcoin::BlockHash;
    use bitcoin::Network;
    use bitcoin::OutPoint;
    use floresta_common::assert_ok;
    use floresta_common::bhash;
    use rand::Rng;
    use rustreexo::accumulator::proof::Proof;

    use super::BlockchainInterface;
    use super::ChainParams;
    use super::ChainState;
    use super::DiskBlockHeader;
    use super::UpdatableChainstate;
    use crate::prelude::HashMap;
    use crate::pruned_utreexo::consensus::Consensus;
    use crate::pruned_utreexo::utxo_data::UtxoData;
    use crate::AssumeValidArg;
    use crate::KvChainStore;

    fn setup_test_chain<'a>(
        network: Network,
        assume_valid_arg: AssumeValidArg,
    ) -> ChainState<KvChainStore<'a>> {
        let test_id = rand::random::<u64>();
        let chainstore = KvChainStore::new(format!("./tmp-db/{test_id}/")).unwrap();
        ChainState::new(chainstore, network, assume_valid_arg)
    }

    fn decode_block_and_inputs(
        block_file: File,
        stxos_file: File,
    ) -> (Block, HashMap<OutPoint, UtxoData>) {
        let block_bytes = zstd::decode_all(block_file).unwrap();
        let block: Block = deserialize(&block_bytes).unwrap();

        // Get utxos spent in the block
        let stxos_bytes = zstd::decode_all(stxos_file).unwrap();
        let mut stxos: Vec<UtxoData> =
            serde_json::from_slice(&stxos_bytes).expect("Failed to deserialize JSON");

        let inputs = block
            .txdata
            .iter()
            .skip(1) // Skip the coinbase transaction
            .flat_map(|tx| &tx.input)
            .map(|txin| (txin.previous_output, stxos.remove(0)))
            .collect();

        assert!(stxos.is_empty(), "Moved all stxos to the inputs map");

        (block, inputs)
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "this test is very slow in debug mode")]
    fn test_validate_many_inputs_block() {
        let block_file = File::open("./testdata/block_367891/raw.zst").unwrap();
        let stxos_file = File::open("./testdata/block_367891/spent_utxos.zst").unwrap();
        let (block, inputs) = decode_block_and_inputs(block_file, stxos_file);

        assert_eq!(
            block.block_hash(),
            bhash!("000000000000000012ea0ca9579299ec120e3f57e7c309216884872592b29970"),
        );

        // Check whether the block validation passes or not
        let chain = setup_test_chain(Network::Bitcoin, AssumeValidArg::Disabled);
        chain
            .validate_block_no_acc(&block, 367891, inputs)
            .expect("Block must be valid");
    }

    #[test]
    fn test_validate_full_block() {
        let block_file = File::open("./testdata/block_866342/raw.zst").unwrap();
        let stxos_file = File::open("./testdata/block_866342/spent_utxos.zst").unwrap();
        let (block, inputs) = decode_block_and_inputs(block_file, stxos_file);

        assert_eq!(
            block.block_hash(),
            bhash!("000000000000000000014ce9ba7c6760053c3c82ce6ab43d60afb101d3c8f1f1"),
        );

        // Check whether the block validation passes or not
        let chain = setup_test_chain(Network::Bitcoin, AssumeValidArg::Disabled);
        chain
            .validate_block_no_acc(&block, 866342, inputs)
            .expect("Block must be valid");
    }

    #[test]
    fn accept_mainnet_headers() {
        // Accepts the first 10235 mainnet headers
        let file = include_bytes!("../../testdata/headers.zst");
        let uncompressed: Vec<u8> = zstd::decode_all(Cursor::new(file)).unwrap();
        let mut buffer = uncompressed.as_slice();

        let chain = setup_test_chain(Network::Bitcoin, AssumeValidArg::Hardcoded);
        while let Ok(header) = BlockHeader::consensus_decode(&mut buffer) {
            chain.accept_header(header).unwrap();
        }
    }

    #[test]
    fn accept_first_signet_headers() {
        // Accepts the first 2016 signet headers
        let file = include_bytes!("../../testdata/signet_headers.zst");
        let uncompressed: Vec<u8> = zstd::decode_all(Cursor::new(file)).unwrap();
        let mut buffer = uncompressed.as_slice();

        let chain = setup_test_chain(Network::Signet, AssumeValidArg::Hardcoded);
        while let Ok(header) = BlockHeader::consensus_decode(&mut buffer) {
            chain.accept_header(header).unwrap();
        }
    }

    #[test]
    fn test_calc_next_work_required() {
        let first_block: BlockHeader = deserialize_hex("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a008f4d5fae77031e8ad22203").unwrap();
        let last_block: BlockHeader = deserialize_hex("00000020dec6741f7dc5df6661bcb2d3ec2fceb14bd0e6def3db80da904ed1eeb8000000d1f308132e6a72852c04b059e92928ea891ae6d513cd3e67436f908c804ec7be51df535fae77031e4d00f800").unwrap();

        let next_target = Consensus::calc_next_work_required(
            &last_block,
            &first_block,
            ChainParams::try_from(Network::Signet).unwrap(),
        );

        assert_eq!(0x1e012fa7, next_target.to_compact_lossy().to_consensus());
    }

    #[test]
    fn test_reorg() {
        let chain = setup_test_chain(Network::Regtest, AssumeValidArg::Hardcoded);
        let json_blocks = include_str!("../../testdata/test_reorg.json");
        let blocks: Vec<Vec<&str>> = serde_json::from_str(json_blocks).unwrap();

        // Connect first 10 blocks
        for block in blocks[0].iter() {
            let block: Block = deserialize_hex(block).unwrap();
            chain.accept_header(block.header).unwrap();
            chain
                .connect_block(&block, Proof::default(), HashMap::new(), Vec::new())
                .unwrap();
        }

        let expected = (
            10,
            bhash!("6e9c49a19038f7db8d13f6c2e70566385536ea11975528b557799e08a014e784"),
        );
        assert_eq!(chain.get_best_block().unwrap(), expected);

        // Then accept a fork chain with 16 blocks
        for fork in blocks[1].iter() {
            let block: Block = deserialize_hex(fork).unwrap();
            chain.accept_header(block.header).unwrap();
        }

        let expected = (
            16,
            bhash!("4572ac401b94915dde6c4957b706abdb13b5824b000cad7f6065ebd9aea6dad1"),
        );
        assert_eq!(chain.get_best_block().unwrap(), expected);

        for i in 1..=chain.get_height().unwrap() {
            let accepted = chain.get_block_hash(i).unwrap();

            if let Ok(DiskBlockHeader::HeadersOnly(..)) = chain.get_disk_block_header(&accepted) {
                continue;
            }
            panic!("Block {i} is not in the store");
        }
    }

    #[test]
    fn test_chainstate_functions() {
        let file = include_bytes!("../../testdata/signet_headers.zst");
        let uncompressed: Vec<u8> = zstd::decode_all(Cursor::new(file)).unwrap();
        let mut buffer = uncompressed.as_slice();

        let chain = setup_test_chain(Network::Signet, AssumeValidArg::Hardcoded);
        let mut headers: Vec<BlockHeader> = Vec::new();
        while let Ok(header) = BlockHeader::consensus_decode(&mut buffer) {
            headers.push(header);
        }

        headers.remove(0);

        // push_headers
        assert_ok!(chain.push_headers(headers.clone(), 1));

        // get_block_header_by_height
        assert_eq!(chain.get_block_header_by_height(1), headers[0]);

        // reindex_chain
        assert_eq!(chain.reindex_chain().depth, 2015);

        // get_block_locator_for_tip
        assert!(!chain
            .get_block_locator_for_tip(read_lock!(chain).best_block.best_block)
            .unwrap()
            .is_empty());

        // get_block_locator
        assert!(!chain.get_block_locator().unwrap().is_empty());

        // invalidate_block
        let random_height = rand::thread_rng().gen_range(1..=2014);

        chain
            .invalidate_block(headers[random_height].prev_blockhash)
            .unwrap();

        assert_eq!(chain.get_height().unwrap() as usize, random_height - 1);

        // update_tip
        chain.update_tip(headers[1].prev_blockhash, 1);
        assert_eq!(
            read_lock!(chain).best_block.best_block,
            headers[1].prev_blockhash
        );
    }
}
