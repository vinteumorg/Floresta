use crate::blockchain::{
    chain_state::ChainState, chainstore::KvChainStore, error::BlockchainError, BlockchainInterface,
    BlockchainProviderInterface,
};
use async_std::channel::Sender;
use bitcoin::{network::utreexo::UtreexoBlock, Block, BlockHash};
use btcd_rpc::client::BTCDClient;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use super::node::NodeNotification;

pub struct BlockDownload {
    inflight: HashMap<BlockHash, u32>,
    queued: HashMap<u32, UtreexoBlock>,
    current_verified: u32,
    last_request: Instant,
    chain: Arc<ChainState<KvChainStore>>,
    rpc: Arc<BTCDClient>,
    last_requested: u32,
    node_tx: Sender<NodeNotification>,
    handle_block: &'static dyn Fn(&ChainState<KvChainStore>, &Arc<BTCDClient>, UtreexoBlock) -> (),
}
impl BlockDownload {
    pub fn push(&mut self, blocks: Vec<BlockHash>) {
        for header in blocks.into_iter() {
            self.inflight.insert(header, self.last_requested as u32);
            self.last_requested += 1;
        }
    }
    pub fn new(
        chain: Arc<ChainState<KvChainStore>>,
        rpc: Arc<BTCDClient>,
        node_tx: Sender<NodeNotification>,
        handle_block: &'static dyn Fn(
            &ChainState<KvChainStore>,
            &Arc<BTCDClient>,
            UtreexoBlock,
        ) -> (),
    ) -> BlockDownload {
        BlockDownload {
            inflight: HashMap::new(),
            queued: HashMap::new(),
            current_verified: 0,
            chain,
            handle_block,
            rpc,
            last_requested: 0,
            node_tx,
            last_request: Instant::now(),
        }
    }
    pub async fn get_more_blocks(&mut self) -> Result<(), BlockchainError> {
        let block = self.last_requested + 1;
        let mut blocks = vec![];
        if self.chain.get_best_block().unwrap().0 == self.chain.get_validation_index().unwrap() {
            return Ok(());
        }
        for height in block..block + 1000 {
            if let Ok(block) = self.chain.get_block_hash(height) {
                blocks.push(block);
            } else {
                break;
            }
        }
        self.push(blocks.clone());
        self.node_tx
            .send(NodeNotification::FromBlockDownloader(
                BlockDownloaderMessages::AskForBlocks(blocks),
            ))
            .await;
        Ok(())
    }
    pub async fn downloaded(&mut self, block: UtreexoBlock) {
        if !self.chain.is_in_idb() {
            self.chain.accept_header(block.block.header);
            (self.handle_block)(&self.chain, &self.rpc, block);
            return;
        }
        let height = self
            .inflight
            .remove(&block.block.block_hash());
        if let Some(height) = height {
            if height == self.current_verified {
                (self.handle_block)(&self.chain, &self.rpc, block);
                self.current_verified += 1;
                if let Some(next) = self.queued.remove(&(height + 1)) {
                    self.downloaded(next);
                }
            } else {
                self.queued.insert(height, block);
            }
        }
        if self.inflight.len() <= 1_000
            && self.last_requested < (self.chain.get_best_block().unwrap().0 - 1_000)
        {
            self.get_more_blocks().await;
        }
    }
    pub async fn handle_timeout(&mut self) {
        if self.last_request.elapsed() >= Duration::from_secs(1) {
            self.last_requested = self.current_verified;
            self.get_more_blocks().await;
        }
        async_std::task::sleep(Duration::from_secs(1)).await
    }
}

pub enum BlockDownloaderMessages {
    AskForBlocks(Vec<BlockHash>),
}
