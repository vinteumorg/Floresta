//! This is a basic kv database that stores all metadata about our blockchain and utreexo
//! state.

use bitcoin::consensus::deserialize;
use bitcoin::consensus::serialize;
use bitcoin::BlockHash;
use floresta_common::prelude::*;
use kv::Batch;
use kv::Bucket;
use kv::Config;
use kv::Integer;
use kv::Store;
use spin::RwLock;

use crate::BestChain;
use crate::ChainStore;
use crate::DiskBlockHeader;

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
    roots: Bucket<'a, &'a str, Vec<u8>>,
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
            roots: store.bucket(Some("roots"))?,
            meta: store.bucket(None)?,
            _store: store,
            headers_cache: RwLock::new(HashMap::new()),
            index_cache: RwLock::new(HashMap::new()),
        })
    }
}

impl ChainStore for KvChainStore<'_> {
    type Error = kv::Error;

    /// For this [ChainStore], since [sled] already checks integrity implicitly, this is a no-op.
    ///
    /// [sled]: https://docs.rs/sled/latest/sled/enum.Error.html#variant.Corruption
    fn check_integrity(&self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn get_size(&self) -> Result<u32, Self::Error> {
        let headers_size = self.headers.len() as u32;
        let roots_size = self.roots.len() as u32;
        let index_size = self.index.len() as u32;
        let store_size = self._store.size_on_disk()? as u32;

        Ok(headers_size + roots_size + index_size + store_size)
    }

    /// Loads the utreexo roots for a given block.
    fn load_roots_for_block(&mut self, height: u32) -> Result<Option<Vec<u8>>, Self::Error> {
        let key = format!("roots_{height}");
        if let Some(roots) = self.roots.get(&key.as_str())? {
            return Ok(Some(roots));
        }

        Ok(None)
    }

    /// Saves the utreexo roots for a given block.
    fn save_roots_for_block(&mut self, roots: Vec<u8>, height: u32) -> Result<(), Self::Error> {
        let key = format!("roots_{height}");
        self.roots.set(&key.as_str(), &roots)?;

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

    /// Gets the block header using the provided block hash. If it is on cache, it returns it
    /// directly, otherwise it fetches it from the database.
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

    // Fetches the block header using the provided height. If it is on cache, it returns it
    // directly, otherwise it fetches it from the database.
    fn get_header_by_height(&self, height: u32) -> Result<Option<DiskBlockHeader>, Self::Error> {
        let hash = self.get_block_hash(height)?;
        match hash {
            Some(hash) => self.get_header(&hash),
            None => Ok(None),
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
        // Flush the roots bucket
        self.roots.flush()?;
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
