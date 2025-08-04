//! This module defines the [ChainStore] trait, which provides the Floresta node API
//! for persisting and retrieving blockchain data (headers, block hashes linked to a
//! height, the best chain data, and the accumulator for each block).
//!
//! It also defines two important types for our storage format:
//! - [DiskBlockHeader]: A block header linked to its validation-state metadata
//! - [BestChain]: Tracks the current best chain, last valid block, and fork tips

use bitcoin::block::Header as BlockHeader;
use bitcoin::consensus::Decodable;
use bitcoin::consensus::Encodable;
use bitcoin::BlockHash;

use crate::prelude::*;
use crate::BlockchainError;
use crate::DatabaseError;

/// A trait defining methods for interacting with our chain database. These methods will be used by
/// the [ChainState](super::chain_state::ChainState) to save and retrieve data about the blockchain,
/// likely on disk.
///
/// Right now, you can use the [FlatChainStore](super::flat_chain_store::FlatChainStore) or
/// [KvChainStore](super::kv_chainstore::KvChainStore) implementations. The former is the store that
/// we use at production, while the latter is a simpler key-value store.
///
/// This trait requires an associated error type that implements [DatabaseError]; a marker trait
/// satisfied by any `T: std::error::Error + std::fmt::Display`. This is useful to abstract the
/// database implementation from the blockchain.
pub trait ChainStore {
    type Error: DatabaseError;

    /// Saves the accumulator state for a given block height.
    fn save_roots_for_block(&mut self, roots: Vec<u8>, height: u32) -> Result<(), Self::Error>;

    /// Loads the state of our accumulator for a given block height.
    ///
    /// This is the state of the resulting accumulator after we process the block at `height`. If you
    /// need the accumulator used to validate a block at height `n`, you should get the accumulator
    /// from block `n - 1`.
    fn load_roots_for_block(&mut self, height: u32) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Loads the blockchain height
    fn load_height(&self) -> Result<Option<BestChain>, Self::Error>;

    /// Saves the blockchain height.
    fn save_height(&mut self, height: &BestChain) -> Result<(), Self::Error>;

    /// Get a block header from our database. See [DiskBlockHeader] for more info about
    /// the data we save.
    fn get_header(&self, block_hash: &BlockHash) -> Result<Option<DiskBlockHeader>, Self::Error>;

    /// Get a block header by its height in our database.
    fn get_header_by_height(&self, height: u32) -> Result<Option<DiskBlockHeader>, Self::Error>;

    /// Saves a block header to our database. See [DiskBlockHeader] for more info about
    /// the data we save.
    fn save_header(&mut self, header: &DiskBlockHeader) -> Result<(), Self::Error>;

    /// Returns the block hash for a given height.
    fn get_block_hash(&self, height: u32) -> Result<Option<BlockHash>, Self::Error>;

    /// Flushes write buffers to disk, this is called periodically by the [ChainState](crate::ChainState),
    /// so in case of a crash, we don't lose too much data. If the database doesn't support
    /// write buffers, this method can be a no-op.
    fn flush(&mut self) -> Result<(), Self::Error>;

    /// Associates a block hash with a given height, so we can retrieve it later.
    fn update_block_index(&mut self, height: u32, hash: BlockHash) -> Result<(), Self::Error>;

    /// Checks if our database didn't get corrupted, and if it has, it returns
    /// an error.
    ///
    /// If you're using a database that already checks for integrity by itself,
    /// this can safely be a no-op.
    fn check_integrity(&self) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq)]
/// This enum is used to store a block header in the database. It contains the header along with
/// metadata about the validation state of the block, and, if applicable, also its height.
pub enum DiskBlockHeader {
    /// Represents a fully validated block header in the current best chain.
    FullyValid(BlockHeader, u32),

    /// Represents an assumed valid block header.
    AssumedValid(BlockHeader, u32),

    /// Represents an orphan block header.
    Orphan(BlockHeader),

    /// Represents a block header in the current best chain whose block is pending validation.
    HeadersOnly(BlockHeader, u32),

    /// Represents a block header in a fork.
    InFork(BlockHeader, u32),

    /// Represents an invalid chain block header.
    InvalidChain(BlockHeader),
}

impl DiskBlockHeader {
    /// Computes the block hash.
    pub fn block_hash(&self) -> BlockHash {
        self.deref().block_hash()
    }

    /// Gets the block height or returns `None` if the block is orphaned or on an invalid chain.
    pub fn height(&self) -> Option<u32> {
        match self {
            DiskBlockHeader::InFork(_, height) => Some(*height),
            DiskBlockHeader::FullyValid(_, height) => Some(*height),
            DiskBlockHeader::HeadersOnly(_, height) => Some(*height),
            DiskBlockHeader::AssumedValid(_, height) => Some(*height),
            // These two cases don't store the block height
            DiskBlockHeader::Orphan(_) => None,
            DiskBlockHeader::InvalidChain(_) => None,
        }
    }

    /// Gets the block height or returns `BlockchainError::OrphanOrInvalidBlock` if the block is
    /// orphaned or on an invalid chain (the height is not stored).
    pub fn try_height(&self) -> Result<u32, BlockchainError> {
        self.height().ok_or(BlockchainError::OrphanOrInvalidBlock)
    }
}

// `DiskBlockHeader` dereferences to the inner header type.
impl Deref for DiskBlockHeader {
    type Target = BlockHeader;
    fn deref(&self) -> &Self::Target {
        match self {
            DiskBlockHeader::FullyValid(header, _) => header,
            DiskBlockHeader::Orphan(header) => header,
            DiskBlockHeader::HeadersOnly(header, _) => header,
            DiskBlockHeader::InFork(header, _) => header,
            DiskBlockHeader::InvalidChain(header) => header,
            DiskBlockHeader::AssumedValid(header, _) => header,
        }
    }
}

impl Decodable for DiskBlockHeader {
    /// Decodes a `DiskBlockHeader` from a reader.
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> core::result::Result<Self, bitcoin::consensus::encode::Error> {
        let tag = u8::consensus_decode(reader)?;
        let header = BlockHeader::consensus_decode(reader)?;

        match tag {
            0x00 => {
                let height = u32::consensus_decode(reader)?;
                Ok(Self::FullyValid(header, height))
            }
            0x01 => Ok(Self::Orphan(header)),
            0x02 => {
                let height = u32::consensus_decode(reader)?;
                Ok(Self::HeadersOnly(header, height))
            }
            0x03 => {
                let height = u32::consensus_decode(reader)?;

                Ok(Self::InFork(header, height))
            }
            0x04 => Ok(Self::InvalidChain(header)),
            0x05 => {
                let height = u32::consensus_decode(reader)?;
                Ok(Self::AssumedValid(header, height))
            }
            _ => unreachable!(),
        }
    }
}

impl Encodable for DiskBlockHeader {
    /// Encodes a `DiskBlockHeader` to a writer using the consensus encoding.
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> bitcoin::io::Result<usize> {
        let mut len = 80 + 1; // Header + tag
        match self {
            DiskBlockHeader::FullyValid(header, height) => {
                0x00_u8.consensus_encode(writer)?;
                header.consensus_encode(writer)?;
                height.consensus_encode(writer)?;
                len += 4;
            }
            DiskBlockHeader::Orphan(header) => {
                0x01_u8.consensus_encode(writer)?;
                header.consensus_encode(writer)?;
            }
            DiskBlockHeader::HeadersOnly(header, height) => {
                0x02_u8.consensus_encode(writer)?;
                header.consensus_encode(writer)?;
                height.consensus_encode(writer)?;
                len += 4;
            }
            DiskBlockHeader::InFork(header, height) => {
                0x03_u8.consensus_encode(writer)?;
                header.consensus_encode(writer)?;
                height.consensus_encode(writer)?;
                len += 4;
            }
            DiskBlockHeader::InvalidChain(header) => {
                0x04_u8.consensus_encode(writer)?;
                header.consensus_encode(writer)?;
            }
            DiskBlockHeader::AssumedValid(header, height) => {
                0x05_u8.consensus_encode(writer)?;
                header.consensus_encode(writer)?;
                height.consensus_encode(writer)?;
                len += 4;
            }
        };
        Ok(len)
    }
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
    /// or have too little work if compared to our best one
    pub alternative_tips: Vec<BlockHash>,
}

impl BestChain {
    pub(super) fn new_block(&mut self, block_hash: BlockHash, height: u32) {
        self.best_block = block_hash;
        self.depth = height;
    }

    pub(super) fn valid_block(&mut self, block_hash: BlockHash) {
        self.validation_index = block_hash;
    }
}

impl From<(BlockHash, u32)> for BestChain {
    fn from((best_block, depth): (BlockHash, u32)) -> Self {
        Self {
            best_block,
            depth,
            validation_index: best_block,
            alternative_tips: Vec::new(),
        }
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
        len += self.alternative_tips.consensus_encode(writer)?;
        Ok(len)
    }
}

impl Decodable for BestChain {
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let best_block = BlockHash::consensus_decode(reader)?;
        let depth = u32::consensus_decode(reader)?;
        let validation_index = BlockHash::consensus_decode(reader)?;

        let alternative_tips = <Vec<BlockHash>>::consensus_decode(reader)?;
        Ok(Self {
            alternative_tips,
            best_block,
            depth,
            validation_index,
        })
    }
}
