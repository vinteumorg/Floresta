use bitcoin::block::Header as BlockHeader;
use bitcoin::consensus::Decodable;
use bitcoin::consensus::Encodable;
use bitcoin::BlockHash;

use crate::prelude::*;
use crate::BlockchainError;

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

/// `DiskBlockHeader` dereferences to the inner header type.
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

/// Decodable is a trait from bitcoin::consensus::encode that allows decoding of a type from a reader in a consistent manner.
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
