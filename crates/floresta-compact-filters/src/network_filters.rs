use bitcoin::BlockHash;
use floresta_chain::pruned_utreexo::BlockchainInterface;

use crate::BlockFilterStore;

#[derive(Debug)]
pub struct NetworkFilters<Storage: BlockFilterStore + Send + Sync> {
    filters: Storage,
}

impl<Storage: BlockFilterStore + Send + Sync> NetworkFilters<Storage> {
    pub fn new(filters: Storage) -> Self {
        Self { filters }
    }

    pub fn get_filter(&self, height: u32) -> Option<crate::BlockFilter> {
        self.filters.get_filter(height)
    }

    pub fn match_any(
        &self,
        query: Vec<&[u8]>,
        start_height: u32,
        end_height: u32,
        chain: impl BlockchainInterface,
    ) -> Vec<BlockHash> {
        let mut blocks = Vec::new();
        let iter = query.into_iter();
        for (height, filter) in self.filters.iter()? {
            if height >= end_height {
                break;
            }
            let hash = chain.get_block_hash(height).unwrap();
            if filter.match_any(&hash, &mut iter.clone()).unwrap() {
                blocks.push(hash);
            }
        }

        blocks
    }

    pub fn push_filter(&self, height: u32, filter: crate::BlockFilter) {
        self.filters.put_filter(height, filter);
        self.filters.put_height(height);
    }

    pub fn get_height(&self) -> u32 {
        self.filters.get_height().unwrap_or(0)
    }

    pub fn save_height(&self, height: u32) {
        self.filters.put_height(height);
    }
}
