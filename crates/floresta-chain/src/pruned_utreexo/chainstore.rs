//! This is a basic kv database that stores all metadata about our blockchain and utreexo
//! state.

use bitcoin::block::Header as BlockHeader;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::serialize;
use bitcoin::consensus::Decodable;
use bitcoin::consensus::Encodable;
use bitcoin::BlockHash;
use kv::Batch;
use kv::Bucket;
use spin::RwLock;

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
use kv::Config;
use kv::Integer;
use kv::Store;

use super::chain_state::BestChain;
use super::ChainStore;

/// As for now we use a KV (key/value) database to store the chain data.
/// This struct provides a way to interact with the chain data stored in the KV store.
/// It uses buckets to store and retrieve data concerning headers, indexes, and metadata.
///
/// It temporarily caches headers and indexes using a HashMap, which are later persisted.
pub struct KvChainStore<'a> {
    _store: Store,
    headers: Bucket<'a, Vec<u8>, Vec<u8>>,
    index: Bucket<'a, Integer, Vec<u8>>,
    meta: Bucket<'a, &'a str, Vec<u8>>,
    headers_cache: RwLock<HashMap<BlockHash, DiskBlockHeader>>,
    index_cache: RwLock<HashMap<u32, BlockHash>>,
}

impl<'a> KvChainStore<'a> {
    /// Creates a new [KvChainStore] instance in the specified directory path.
    pub fn new(datadir: String) -> Result<KvChainStore<'a>, kv::Error> {
        // Configure the database
        let cfg = Config::new(datadir + "/chain_data").cache_capacity(100_000_000);

        // Open the key/value store
        let store = Store::new(cfg)?;

        Ok(KvChainStore {
            headers: store.bucket(Some("headers"))?,
            index: store.bucket(Some("index"))?,
            meta: store.bucket(None)?,
            _store: store,
            headers_cache: RwLock::new(HashMap::new()),
            index_cache: RwLock::new(HashMap::new()),
        })
    }
}

impl ChainStore for KvChainStore<'_> {
    type Error = kv::Error;

    /// Loads the utreexo roots from the metadata bucket.
    fn load_roots(&self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.meta.get(&"roots")
    }

    /// For this [ChainStore], since [sled] already checks integrity implicitly, this is a no-op.
    ///
    /// [sled]: https://docs.rs/sled/latest/sled/enum.Error.html#variant.Corruption
    fn check_integrity(&self) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Saves the current utreexo roots to the metadata bucket.
    fn save_roots(&mut self, roots: Vec<u8>) -> Result<(), Self::Error> {
        self.meta.set(&"roots", &roots)?;
        Ok(())
    }

    /// Loads the best chain data from the metadata bucket.
    fn load_height(&self) -> Result<Option<BestChain>, Self::Error> {
        if let Some(b) = self.meta.get(&"height")? {
            let height = deserialize(&b).expect("infallible: came from `serialize(height)`");
            return Ok(Some(height));
        }

        Ok(None)
    }

    /// Saves the best chain data to the metadata bucket.
    fn save_height(&mut self, height: &BestChain) -> Result<(), Self::Error> {
        let height = serialize(height);
        self.meta.set(&"height", &height)?;
        Ok(())
    }

    /// Gets the block header using the provided block hash. If it is on cache, it returns it directly, otherwise
    /// it fetches it from the database.
    fn get_header(&self, block_hash: &BlockHash) -> Result<Option<DiskBlockHeader>, Self::Error> {
        match self.headers_cache.read().get(block_hash) {
            Some(header) => Ok(Some(*header)),
            None => {
                let block_hash = serialize(&block_hash);
                Ok(self
                    .headers
                    .get(&block_hash)?
                    .and_then(|b| deserialize(&b).ok()))
            }
        }
    }

    /// Flushes the cache to the database.
    fn flush(&mut self) -> Result<(), Self::Error> {
        // save all headers in batch
        let mut batch = Batch::new();
        for header in self.headers_cache.read().iter() {
            let ser_header = serialize(header.1);
            let block_hash = serialize(&header.1.block_hash());
            batch.set(&block_hash, &ser_header)?;
        }
        self.headers.batch(batch)?;
        self.headers_cache.write().clear();

        // save all index in batch
        let mut batch = Batch::new();
        for (height, hash) in self.index_cache.read().iter() {
            let ser_hash = serialize(hash);
            batch.set(&Integer::from(*height), &ser_hash)?;
        }
        self.index.batch(batch)?;
        self.index_cache.write().clear();

        // Flush the header bucket
        self.headers.flush()?;
        // Flush the block index
        self.index.flush()?;
        // Flush the default bucket with meta-info
        self.meta.flush()?;
        Ok(())
    }

    /// Saves a header to the database.
    fn save_header(&mut self, header: &DiskBlockHeader) -> Result<(), Self::Error> {
        self.headers_cache
            .write()
            .insert(header.block_hash(), *header);
        Ok(())
    }

    /// Gets a block hash from the database using the provided height.
    /// If it's not found in the cache, it will be fetched from the database.
    fn get_block_hash(&self, height: u32) -> Result<Option<BlockHash>, Self::Error> {
        match self.index_cache.read().get(&height).cloned() {
            Some(hash) => Ok(Some(hash)),
            None => Ok(self
                .index
                .get(&Integer::from(height))?
                .and_then(|b| deserialize(&b).ok())),
        }
    }

    /// Updates the block index with the provided height and hash.
    fn update_block_index(&mut self, height: u32, hash: BlockHash) -> Result<(), Self::Error> {
        self.index_cache.write().insert(height, hash);
        Ok(())
    }
}
