use bitcoin::bip158::BlockFilter;
use bitcoin::BlockHash;
use floresta_chain::pruned_utreexo::BlockchainInterface;

use crate::IteratableFilterStore;
use crate::IteratableFilterStoreError;

#[derive(Debug)]
pub struct NetworkFilters<Storage: IteratableFilterStore> {
    filters: Storage,
}

impl<Storage: IteratableFilterStore> NetworkFilters<Storage> {
    pub fn new(filters: Storage) -> Self {
        if filters.get_height().is_err() {
            filters.set_height(0).unwrap();
        }

        Self { filters }
    }

    pub fn match_any(
        &self,
        query: Vec<&[u8]>,
        start_height: Option<usize>,
        chain: impl BlockchainInterface,
    ) -> Result<Vec<BlockHash>, IteratableFilterStoreError> {
        let mut blocks = Vec::new();
        let iter = query.into_iter();
        for (height, filter) in self.filters.iter(start_height)? {
            let hash = chain.get_block_hash(height).unwrap();
            if filter.match_any(&hash, &mut iter.clone()).unwrap() {
                blocks.push(hash);
            }
        }
        Ok(blocks)
    }

    pub fn push_filter(
        &self,
        filter: BlockFilter,
        height: u32,
    ) -> Result<(), IteratableFilterStoreError> {
        self.filters.put_filter(filter, height)
    }

    pub fn get_height(&self) -> Result<u32, IteratableFilterStoreError> {
        self.filters.get_height()
    }

    pub fn save_height(&self, height: u32) -> Result<(), IteratableFilterStoreError> {
        self.filters.set_height(height)
    }
}
