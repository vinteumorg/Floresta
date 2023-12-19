use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use bitcoin::p2p::utreexo::UtreexoBlock;
use bitcoin::BlockHash;

use super::node::RescanStatus;
use super::node_interface::NodeInterface;

pub trait NodeContext {
    const REQUEST_TIMEOUT: u64;
    /// Max number of simultaneous connections we initiates we are willing to hold
    const MAX_OUTGOING_PEERS: usize = 10;
    /// We ask for peers every ASK_FOR_PEERS_INTERVAL seconds
    const ASK_FOR_PEERS_INTERVAL: u64 = 60 * 60; // One hour
    /// Save our database of peers every PEER_DB_DUMP_INTERVAL seconds
    const PEER_DB_DUMP_INTERVAL: u64 = 60 * 5; // 5 minutes
    /// Attempt to open a new connection (if needed) every TRY_NEW_CONNECTION seconds
    const TRY_NEW_CONNECTION: u64 = 10; // 10 seconds
    /// If ASSUME_STALE seconds passed since our last tip update, treat it as stale
    const ASSUME_STALE: u64 = 30 * 60; // 30 minutes
    /// While on IBD, if we've been without blocks for this long, ask for headers again
    const IBD_REQUEST_BLOCKS_AGAIN: u64 = 30; // 30 seconds
    /// How often we broadcast transactions
    const BROADCAST_DELAY: u64 = 30; // 30 seconds
    /// Max number of simultaneous inflight requests we allow
    const MAX_INFLIGHT_REQUESTS: usize = 1_000;
    /// Interval at which we open new feeler connections
    const FEELER_INTERVAL: u64 = 60 * 5; // 5 minutes
    /// Interval at which we rearrange our addresses
    const ADDRESS_REARRANGE_INTERVAL: u64 = 60 * 60; // 1 hour
    /// How long we ban a peer for
    const BAN_TIME: u64 = 60 * 60 * 24;
    /// How often we check if we haven't missed a block
    const BLOCK_CHECK_INTERVAL: u64 = 60 * 5; // 5 minutes
    /// How often we send our addresses to our peers
    const SEND_ADDRESSES_INTERVAL: u64 = 60 * 60; // 1 hour
}

#[derive(Debug, Clone)]
pub struct RunningNode {
    pub last_rescan_request: RescanStatus,
    pub last_feeler: Instant,
    pub last_address_rearrange: Instant,
    pub last_block_check: Instant,
    pub user_requests: Arc<NodeInterface>,
}
impl NodeContext for RunningNode {
    const REQUEST_TIMEOUT: u64 = 30;
}

#[derive(Debug, Default, Clone)]
pub struct IBDNode {
    pub blocks: HashMap<BlockHash, UtreexoBlock>,
}
impl NodeContext for IBDNode {
    const REQUEST_TIMEOUT: u64 = 30 * 60;
}
