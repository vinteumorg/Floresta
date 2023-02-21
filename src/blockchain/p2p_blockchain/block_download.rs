//! This module is used during Initial Block Download to keep track of which blocks have
//! we downloaded, requested or are still pending. We keep an internal cache of inflight
//! blocks, and the instant we requested it. If it have elapsed some time after the request
//! we assume it timed out and request again.
//! Since we ask blocks for multiple peer, they might come in the wrong order, if we get a
//! block that we don't have it's ancestors yet, we hold it until we have all ancestors.

use super::node::NodeNotification;
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
/// Keeps track of blocks we have to download during Initial Block Download, so we can
/// download blocks from multiple peers
pub struct BlockDownload {
    /// All blocks we have requested, maps blocks to a unique id, this id might be equal
    /// to the actual height, but it's an internal order for blocks, we try to download
    /// blocks exactly in this order.
    inflight: HashMap<BlockHash, u32>,
    /// A block we got, but we didn't get it's ancestors yet
    queued: HashMap<u32, UtreexoBlock>,
    /// The id for the last block we downloaded and processed
    current_verified: u32,
    /// The instant of our last request
    last_request: Instant,
    /// Our chainstate, used to determine which blocks should we download
    chain: Arc<ChainState<KvChainStore>>,
    /// TODO: Remove
    rpc: Arc<BTCDClient>,
    /// The id of the last block we requested
    last_requested: u32,
    /// We use this channel to ask things to the node
    node_tx: Sender<NodeNotification>,
    /// A callback function that should be called every time we have a new block.
    /// It's assured that this callback will be called with blocks ordered.
    handle_block: &'static dyn Fn(&ChainState<KvChainStore>, &Arc<BTCDClient>, UtreexoBlock) -> (),
}

impl BlockDownload {
    /// Adds a new block to be downloaded
    pub fn push(&mut self, blocks: Vec<BlockHash>) {
        for header in blocks.into_iter() {
            self.inflight.insert(header, self.last_requested as u32);
            self.last_requested += 1;
        }
    }
    /// Creates a new downloader
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
    /// Determine which blocks we should download and asks the node for it
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
    /// A callback issued every time a new block arrives from our peers. It checks if
    /// the block we got is the next one in our current tip. If so, process it. Queue it
    /// otherwise.
    pub async fn downloaded(&mut self, block: UtreexoBlock) {
        // If not in IBD, skip bellow logic, as we only have to download one block
        if !self.chain.is_in_idb() {
            self.chain.accept_header(block.block.header);
            (self.handle_block)(&self.chain, &self.rpc, block);
            return;
        }
        // This block is no longer inflight
        let height = self.inflight.remove(&block.block.block_hash());
        if let Some(height) = height {
            // This block is the next one in our tip, process it
            if height == self.current_verified {
                (self.handle_block)(&self.chain, &self.rpc, block);
                self.current_verified += 1;
                if let Some(next) = self.queued.remove(&(height + 1)) {
                    self.downloaded(next);
                }
            } else {
                // There are missing ancestors, hold it for now
                self.queued.insert(height, block);
            }
        }
        // If we got the majority of blocks we were waiting for, ask for more blocks
        if self.inflight.len() <= 1_000
            && self.last_requested < (self.chain.get_best_block().unwrap().0 - 1_000)
        {
            self.get_more_blocks().await;
        }
    }
    /// Checks whether the blocks we asked timed our or not
    pub async fn handle_timeout(&mut self) {
        if self.last_request.elapsed() >= Duration::from_secs(1) {
            self.last_requested = self.current_verified;
            self.get_more_blocks().await;
        }
        async_std::task::sleep(Duration::from_secs(1)).await
    }
}

/// Messages we send to the node
#[derive(Debug)]
pub enum BlockDownloaderMessages {
    AskForBlocks(Vec<BlockHash>),
}
