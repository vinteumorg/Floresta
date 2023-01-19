use crate::blockchain::{
    chain_state::ChainState, chainstore::KvChainStore, error::BlockchainError, BlockchainInterface,
    BlockchainProviderInterface,
};
use async_std::channel::Sender;
use bitcoin::{Block, BlockHash};
use btcd_rpc::client::BTCDClient;
use std::{collections::HashMap, sync::Arc, time::Instant};

use super::NodeNotification;

#[derive(Debug, PartialEq)]
enum RequestedBlockStatus {
    Requested,
    TimedOut,
    Done,
}
#[derive(Debug, PartialEq)]
pub struct RequestedBlock {
    block_hash: BlockHash,
    requested_time: Instant,
    peer: u32,
    status: RequestedBlockStatus,
}

impl PartialOrd for RequestedBlock {
    fn ge(&self, other: &Self) -> bool {
        self.requested_time >= other.requested_time
    }
    fn gt(&self, other: &Self) -> bool {
        self.requested_time > other.requested_time
    }
    fn le(&self, other: &Self) -> bool {
        self.requested_time <= other.requested_time
    }
    fn lt(&self, other: &Self) -> bool {
        self.requested_time < other.requested_time
    }
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match self.requested_time.partial_cmp(&other.requested_time) {
            Some(core::cmp::Ordering::Equal) => {}
            ord => return ord,
        }
        match self.peer.partial_cmp(&other.peer) {
            Some(core::cmp::Ordering::Equal) => {}
            ord => return ord,
        }
        Some(std::cmp::Ordering::Equal)
    }
}
pub struct BlockDownload {
    inflight: HashMap<BlockHash, u32>,
    queued: HashMap<u32, Block>,
    current_verified: u32,
    chain: Arc<ChainState<KvChainStore>>,
    rpc: Arc<BTCDClient>,
    last_requested: u32,
    node_tx: Sender<NodeNotification>,
    handle_block: &'static dyn Fn(&ChainState<KvChainStore>, &Arc<BTCDClient>, Block) -> (),
}
impl BlockDownload {
    pub fn push(&mut self, blocks: Vec<BlockHash>) {
        self.last_requested = self.last_requested + blocks.len() as u32;
        for (i, header) in blocks.into_iter().enumerate() {
            self.inflight.insert(header, i as u32);
        }
    }
    pub fn new(
        chain: Arc<ChainState<KvChainStore>>,
        rpc: Arc<BTCDClient>,
        node_tx: Sender<NodeNotification>,
        handle_block: &'static dyn Fn(&ChainState<KvChainStore>, &Arc<BTCDClient>, Block) -> (),
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
        }
    }
    pub async fn get_more_blocks(&mut self) -> Result<(), BlockchainError> {
        let block = self.last_requested + 1;
        let mut blocks = vec![];

        for height in block..block + 1000 {
            blocks.push(self.chain.get_block_hash(height)?);
        }
        self.push(blocks.clone());
        self.node_tx
            .send(NodeNotification::AskForBlocks(blocks))
            .await;
        Ok(())
    }
    pub async fn downloaded(&mut self, block: Block) {
        let height = self.inflight.remove(&block.block_hash());
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
        if self.inflight.len() <= 1_000 {
            self.get_more_blocks().await;
        }
    }
}
