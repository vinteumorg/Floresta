use std::path::PathBuf;

use bitcoin::util::bip158::BlockFilter;
use kv::{Bucket, Integer, Config};

use crate::BlockFilterStore;

/// Stores the block filters insinde a kv database
pub struct KvFilterStore<'a> {
    bucket: Bucket<'a, Integer, Vec<u8>>,
}

impl KvFilterStore<'_> {
    /// Creates a new [KvFilterStore] that stores it's content in `datadir`.
    ///
    /// If the path does't exist it'll be created. This store uses compression by default, if you
    /// want to make more granular configuration over the underlying Kv database, use `with_config`
    /// instead.
    pub fn new(datadir: &PathBuf) -> Self {
        let store = kv::Store::new(kv::Config {
            path: datadir.to_owned(),
            temporary: false,
            use_compression: true,
            flush_every_ms: None,
            cache_capacity: None,
            segment_size: None,
        }).expect("Could not open store");

        let bucket = store.bucket(Some("cfilters")).unwrap();
        KvFilterStore { bucket }

    }
    /// Creates a new [KvFilterStore] that stores it's content with a given config
    pub fn with_config(config: Config) -> Self {
        let store = kv::Store::new(config).expect("Could not open database");
        let bucket = store.bucket(Some("cffilters")).unwrap();
        KvFilterStore { bucket }
    }
}

impl BlockFilterStore for KvFilterStore<'_> {
    fn get_filter(&self, block_height: u64) -> Option<bitcoin::util::bip158::BlockFilter> {
        let value = self
            .bucket
            .get(&Integer::from(block_height))
            .ok()
            .flatten()?;
        Some(BlockFilter::new(&value))
    }
    fn put_filter(&self, block_height: u64, block_filter: bitcoin::util::bip158::BlockFilter) {
        self.bucket
            .set(&Integer::from(block_height), &block_filter.content)
            .expect("Bucket should be open");
    }
}
