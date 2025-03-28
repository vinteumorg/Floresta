//! This module provides a builder pattern for constructing ChainState instances with various
//! optional configurations.
//!
//! It includes:
//! - Chain parameters
//! - Chainstore backend
//! - Initial block download status
//! - Assumed valid blocks for validation optimization
//! - UTREEXO accumulator state
//! - Current chain tip and header
use bitcoin::block::Header as BlockHeader;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use rustreexo::accumulator::stump::Stump;

use super::chain_state::BestChain;
use super::chain_state::ChainState;
use super::chainparams::ChainParams;
use super::ChainStore;

#[derive(Clone, Debug)]
/// This enum is used to represent errors that can occur during the construction of a ChainState instance.
pub enum BlockchainBuilderError {
    /// Indicates that the chainstore is missing.
    MissingChainstore,
    /// Indicates that the chain parameters are missing.
    MissingChainParams,
}
#[derive(Clone, Debug, Default)]
/// Represents a builder for constructing a ChainState instance.
pub struct ChainStateBuilder<PersistedState: ChainStore> {
    /// The accumulator stump.
    acc: Option<Stump>,
    /// The chain store.
    chainstore: Option<PersistedState>,
    /// Indicates whether the builder is in initial block download mode.
    ibd: bool,
    /// The chain parameters.
    chain_params: Option<ChainParams>,
    /// The block hash that is assumed to be valid.
    assume_valid: Option<BlockHash>,
    /// The current chain tip.
    tip: Option<(BlockHash, u32)>,
    /// The first block header.
    first: Option<BlockHeader>,
}

impl<T: ChainStore> ChainStateBuilder<T> {
    pub fn new() -> Self {
        ChainStateBuilder {
            acc: None,
            chainstore: None,
            ibd: true,
            chain_params: None,
            assume_valid: None,
            tip: None,
            first: None,
        }
    }
    pub fn build(self) -> Result<ChainState<T>, BlockchainBuilderError> {
        if self.chainstore.is_none() {
            return Err(BlockchainBuilderError::MissingChainstore);
        }
        if self.chain_params.is_none() {
            return Err(BlockchainBuilderError::MissingChainParams);
        }
        if let Some(first) = self.first {
            self.chainstore
                .as_ref()
                .unwrap()
                .save_header(&crate::DiskBlockHeader::FullyValid(
                    first,
                    self.tip.unwrap().1,
                ))
                .unwrap();
            self.chainstore
                .as_ref()
                .unwrap()
                .update_block_index(self.tip.unwrap().1, self.tip.unwrap().0)
                .unwrap();
        }
        Ok(ChainState::from(self))
    }
    pub fn with_chainstore(mut self, chainstore: T) -> Self {
        self.chainstore = Some(chainstore);
        self
    }

    pub fn toggle_ibd(mut self, ibd: bool) -> Self {
        self.ibd = ibd;
        self
    }
    pub fn with_chain_params(mut self, chain_params: ChainParams) -> Self {
        self.chain_params = Some(chain_params);
        self
    }
    pub fn with_assume_valid(mut self, assume_valid: BlockHash) -> Self {
        self.assume_valid = Some(assume_valid);
        self
    }
    pub fn assume_utreexo(mut self, acc: Stump) -> Self {
        self.acc = Some(acc);
        self
    }
    pub fn with_tip(mut self, tip: (BlockHash, u32), header: BlockHeader) -> Self {
        self.tip = Some(tip);
        self.first = Some(header);
        self
    }
    pub fn acc(&self) -> Stump {
        self.acc.clone().unwrap_or_default()
    }
    pub fn chainstore(&mut self) -> T {
        self.chainstore.take().unwrap()
    }
    pub fn ibd(&self) -> bool {
        self.ibd
    }
    pub fn chain_params(&self) -> ChainParams {
        self.chain_params.clone().unwrap()
    }
    pub fn best_block(&self) -> BestChain {
        let block = self.tip.unwrap_or((BlockHash::all_zeros(), 0));
        BestChain::from(block)
    }
    pub fn assume_valid(&self) -> Option<BlockHash> {
        self.assume_valid
    }
}
