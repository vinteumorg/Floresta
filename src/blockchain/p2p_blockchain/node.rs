//! Main file for this blockchain. A node is the central task that runs and handles important
//! events, such as new blocks, peer connection/disconnection, new addresses, etc.
//! A node should not care about peer-specific messages, peers'll handle things like pings.
use super::{
    address_man::{AddressMan, LocalAddress},
    mempool::Mempool,
    peer::{Peer, PeerMessages},
};
use crate::blockchain::{
    chain_state::ChainState, chainparams::get_chain_dns_seeds, chainstore::KvChainStore,
    error::BlockchainError, p2p_blockchain::address_man::AddressState, udata::proof_util,
    BlockchainInterface, BlockchainProviderInterface,
};
use async_std::{
    channel::{self, bounded, Receiver, Sender},
    future::timeout,
    sync::RwLock,
    task::{block_on, spawn},
};
use bitcoin::{
    hashes::{sha256, Hash},
    network::{
        constants::ServiceFlags,
        utreexo::{UData, UtreexoBlock},
    },
    BlockHash, BlockHeader, Network, OutPoint, Transaction, TxOut, Txid,
};
use log::{error, info, warn};
use rustreexo::accumulator::proof::Proof;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Max number of simultaneous connections we initiates we are willing to hold
const MAX_OUTGOING_PEERS: usize = 10;
/// We ask for peers every ASK_FOR_PEERS_INTERVAL seconds
const ASK_FOR_PEERS_INTERVAL: u64 = 60; // One minute
/// Save our database of peers every PEER_DB_DUMP_INTERVAL seconds
const PEER_DB_DUMP_INTERVAL: u64 = 60 * 5; // 5 minutes
/// Attempt to open a new connection (if needed) every TRY_NEW_CONNECTION seconds
const TRY_NEW_CONNECTION: u64 = 30; // 10 seconds
/// If ASSUME_STALE seconds passed since our last tip update, treat it as stale
const ASSUME_STALE: u64 = 30 * 60; // 30 minutes
/// While on IBD, if we've been without blocks for this long, ask for headers again
const IBD_REQUEST_BLOCKS_AGAIN: u64 = 10; // 10 seconds
/// How often we broadcast transactions
const BROADCAST_DELAY: u64 = 30; // 30 seconds
/// Wait up to this many seconds for a peer to respond to a request
const PEER_REQUEST_TIMEOUT: u64 = 30 * 60; // 30 minutes
/// Max number of simultaneous inflight requests we allow
const MAX_INFLIGHT_REQUESTS: usize = 10_000;
/// Interval at which we open new feeler connections
const FEELER_INTERVAL: u64 = 60 * 5; // 5 minutes
/// Interval at which we rearrange our addresses
const ADDRESS_REARRANGE_INTERVAL: u64 = 60 * 60; // 1 hour
/// How long we ban a peer for
const BAN_TIME: u64 = 60 * 60 * 24;
#[derive(Debug)]
pub enum NodeNotification {
    FromPeer(u32, PeerMessages),
}
#[derive(Debug, Clone, PartialEq)]
/// Sent from node to peers, usually to request something
pub enum NodeRequest {
    /// Get this block's data
    GetBlock(Vec<BlockHash>),
    /// Asks peer for headers
    GetHeaders(Vec<BlockHash>),
    /// Ask for other peers addresses
    GetAddresses,
    /// Asks this peer to shutdown
    Shutdown,
    /// Sends a transaction to peers
    BroadcastTransaction(Txid),
}

#[derive(Default, PartialEq)]
enum NodeState {
    #[default]
    WaitingPeer,
    DownloadHeaders,
    DownloadBlocks,
    Running,
}
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
enum InflightRequests {
    Headers,
    Blocks(BlockHash),
    Addresses,
}
struct LocalPeerView {
    state: PeerStatus,
    address_id: u32,
    channel: Sender<NodeRequest>,
    services: ServiceFlags,
    _last_message: Instant,
    feeler: bool,
}
/// The main node struct. It holds all the important information about the node, such as the
/// blockchain, the peers, the mempool, etc.
/// It also holds the channels to communicate with peers and the block downloader.
/// The node is the central task that runs and handles important events, such as new blocks,
/// peer connection/disconnection, new addresses, etc.
pub struct UtreexoNode {
    peer_id_count: u32,
    last_headers_request: Instant,
    last_tip_update: Instant,
    last_connection: Instant,
    last_get_address_request: Instant,
    last_peer_db_dump: Instant,
    last_broadcast: Instant,
    last_block_request: u32,
    last_feeler: Instant,
    last_address_rearrange: Instant,
    network: Network,
    utreexo_peers: Vec<u32>,
    peer_ids: Vec<u32>,
    blocks: HashMap<BlockHash, UtreexoBlock>,
    peers: HashMap<u32, LocalPeerView>,
    chain: Arc<ChainState<KvChainStore>>,
    inflight: HashMap<InflightRequests, (u32, Instant)>,
    _mempool: Arc<RwLock<Mempool>>,
    node_rx: Receiver<NodeNotification>,
    node_tx: Sender<NodeNotification>,
    state: NodeState,
    datadir: String,
    address_man: AddressMan,
}
#[derive(Debug, PartialEq)]
enum PeerStatus {
    Awaiting,
    Ready,
}
impl UtreexoNode {
    pub fn new(
        chain: Arc<ChainState<KvChainStore>>,
        mempool: Arc<RwLock<Mempool>>,
        network: Network,
        datadir: String,
    ) -> Self {
        let (node_tx, node_rx) = channel::unbounded();
        UtreexoNode {
            inflight: HashMap::new(),
            state: NodeState::WaitingPeer,
            peer_id_count: 0,
            peers: HashMap::new(),
            last_block_request: chain.get_validation_index().expect("Invalid chain"),
            chain,
            peer_ids: Vec::new(),
            utreexo_peers: Vec::new(),
            _mempool: mempool,
            network,
            node_rx,
            blocks: HashMap::new(),
            node_tx,
            address_man: AddressMan::default(),
            last_headers_request: Instant::now(),
            last_tip_update: Instant::now(),
            last_connection: Instant::now(),
            last_peer_db_dump: Instant::now(),
            last_broadcast: Instant::now(),
            last_feeler: Instant::now(),
            last_address_rearrange: Instant::now(),
            datadir,
            last_get_address_request: Instant::now(),
        }
    }
    fn get_default_port(&self) -> u16 {
        match self.network {
            Network::Bitcoin => 8333,
            Network::Testnet => 18333,
            Network::Signet => 38333,
            Network::Regtest => 18444,
        }
    }

    #[allow(clippy::type_complexity)]
    fn process_proof(
        udata: &UData,
        transactions: &[Transaction],
        chain: &ChainState<KvChainStore>,
        block_hash: &BlockHash,
    ) -> Result<(Proof, Vec<sha256::Hash>, HashMap<OutPoint, TxOut>), BlockchainError> {
        let targets = udata.proof.targets.iter().map(|target| target.0).collect();
        let hashes = udata
            .proof
            .hashes
            .iter()
            .map(|hash| sha256::Hash::from_inner(hash.into_inner()))
            .collect();
        let proof = Proof::new(targets, hashes);
        let hashes = vec![];
        let mut leaves_iter = udata.leaves.iter().cloned();
        let mut tx_iter = transactions.iter();

        let mut inputs = HashMap::new();
        tx_iter.next(); // Skip coinbase

        for tx in tx_iter {
            let txid = tx.txid();
            for (vout, out) in tx.output.iter().enumerate() {
                inputs.insert(
                    OutPoint {
                        txid,
                        vout: vout as u32,
                    },
                    out.clone(),
                );
            }

            for input in tx.input.iter() {
                if !inputs.contains_key(&input.previous_output) {
                    if let Some(leaf) = leaves_iter.next() {
                        let height = leaf.header_code >> 1;
                        let hash = chain.get_block_hash(height)?;
                        let leaf = proof_util::reconstruct_leaf_data(&leaf, input, hash)
                            .expect("Invalid proof");
                        // Coinbase can only be spent after a certain amount of confirmations
                        if leaf.header_code & 1 == 1
                            && !chain.is_coinbase_mature(height, *block_hash)?
                        {
                            return Err(BlockchainError::CoinbaseNotMatured);
                        }
                        inputs.insert(leaf.prevout, leaf.utxo);
                    }
                }
            }
        }

        Ok((proof, hashes, inputs))
    }
    pub async fn ibd_handle_headers(
        &mut self,
        headers: Vec<BlockHeader>,
    ) -> Result<(), BlockchainError> {
        if headers.is_empty() {
            // Start downloading blocks
            self.chain.flush()?;
            self.state = NodeState::DownloadBlocks;
            return Ok(());
        }
        self.last_headers_request = Instant::now();
        info!(
            "Downloading headers at: {} hash: {}",
            self.chain.get_best_block()?.0,
            headers[0].block_hash()
        );
        for header in headers {
            self.chain.accept_header(header)?;
        }
        let locator = self.chain.get_block_locator()?;
        let peer = self
            .send_to_random_peer(NodeRequest::GetHeaders(locator), ServiceFlags::NONE)
            .await?;
        self.inflight
            .insert(InflightRequests::Headers, (peer, Instant::now()));
        Ok(())
    }
    async fn send_to_peer(&self, peer_id: u32, req: NodeRequest) -> Result<(), BlockchainError> {
        if let Some(peer) = &self.peers.get(&peer_id) {
            peer.channel.send(req).await?;
            Ok(())
        } else {
            Err(BlockchainError::PeerNotFound)
        }
    }
    async fn check_for_timeout(&mut self) -> Result<(), BlockchainError> {
        let mut timed_out = vec![];
        for request in self.inflight.keys() {
            let (_, time) = self.inflight.get(request).unwrap();
            if time.elapsed() > Duration::from_secs(PEER_REQUEST_TIMEOUT) {
                timed_out.push(*request);
            }
        }
        let mut removed_peers = HashSet::new();
        let mut to_request = vec![];
        for request in timed_out {
            match request {
                InflightRequests::Blocks(block) => to_request.push(block),
                InflightRequests::Addresses => {
                    let locator = self.chain.get_block_locator()?;
                    self.send_to_random_peer(NodeRequest::GetHeaders(locator), ServiceFlags::NONE)
                        .await?;
                    self.last_get_address_request = Instant::now();
                }
                InflightRequests::Headers => {
                    self.send_to_random_peer(NodeRequest::GetAddresses, ServiceFlags::NONE)
                        .await?;
                    self.last_headers_request = Instant::now();
                }
            }

            let (peer, _) = self.inflight.remove(&request).unwrap();
            if !removed_peers.contains(&peer) {
                self.send_to_peer(peer, NodeRequest::Shutdown).await?;
                removed_peers.insert(peer);
            }
        }
        self.request_blocks(to_request).await?;
        Ok(())
    }
    #[inline]
    pub async fn send_to_random_peer(
        &self,
        req: NodeRequest,
        required_services: ServiceFlags,
    ) -> Result<u32, BlockchainError> {
        if self.peers.is_empty() {
            return Err(BlockchainError::NoPeersAvailable);
        }
        let idx = if required_services.has(ServiceFlags::NODE_UTREEXO) {
            if self.utreexo_peers.is_empty() {
                return Err(BlockchainError::NoPeersAvailable);
            }
            let idx = rand::random::<usize>() % self.utreexo_peers.len();
            *self
                .utreexo_peers
                .get(idx)
                .expect("node is in the interval 0..utreexo_peers.len(), but is not here?")
        } else {
            let idx = rand::random::<usize>() % self.peer_ids.len();
            *self
                .peer_ids
                .get(idx)
                .expect("node is in the interval 0..utreexo_peers.len(), but is not here?")
        };
        if let Some(peer) = self.peers.get(&idx) {
            peer.channel.send(req.clone()).await?;
        }
        Ok(idx)
    }
    pub async fn handle_notification(
        &mut self,
        notification: Result<NodeNotification, async_std::channel::RecvError>,
    ) -> Result<(), BlockchainError> {
        let notification = notification?;
        match notification {
            NodeNotification::FromPeer(peer, message) => match message {
                PeerMessages::NewBlock(_) => {
                    if !self.chain.is_in_idb()
                        && !self.inflight.contains_key(&InflightRequests::Headers)
                    {
                        let locator = self.chain.get_block_locator()?;

                        let peer = self
                            .send_to_random_peer(
                                NodeRequest::GetHeaders(locator),
                                ServiceFlags::NODE_UTREEXO,
                            )
                            .await?;
                        self.inflight
                            .insert(InflightRequests::Headers, (peer, Instant::now()));
                    }
                }
                PeerMessages::Block(block) => {
                    // Remove from inflight, since we just got it.
                    if self
                        .inflight
                        .remove(&InflightRequests::Blocks(block.block.block_hash()))
                        .is_none()
                    {
                        // We didn't request this block, so we should disconnect the peer.
                        if let Some(peer) = self.peers.get(&peer) {
                            self.address_man.update_set_state(
                                peer.address_id as usize,
                                AddressState::Banned(BAN_TIME),
                            );
                        }
                        self.send_to_peer(peer, NodeRequest::Shutdown).await?;
                        return Err(BlockchainError::PeerMisbehaving);
                    }

                    let mut mempool_delta = vec![];
                    // If we are on idb, we don't have anything in our mempool yet.
                    if !self.chain.is_in_idb() {
                        mempool_delta
                            .extend(self._mempool.write().await.consume_block(&block.block));
                    }

                    match self.handle_block(block) {
                        Ok(_) => {}
                        Err(e) => {
                            error!("Invalid block received by peer {} reason: {:?}", peer, e);
                            // Disconnect the peer and ban it.
                            if let Some(peer) = self.peers.get(&peer) {
                                self.address_man.update_set_state(
                                    peer.address_id as usize,
                                    AddressState::Banned(BAN_TIME),
                                );
                            }
                            self.send_to_peer(peer, NodeRequest::Shutdown).await?;

                            // Add the transactions back to the mempool.
                            for tx in mempool_delta {
                                self._mempool.write().await.accept_to_mempool(tx);
                            }
                            return Err(e);
                        }
                    }
                    self.last_tip_update = Instant::now();
                    if self.state == NodeState::DownloadBlocks
                        && self.inflight.len() < MAX_INFLIGHT_REQUESTS
                    {
                        let blocks = self.get_blocks_to_download()?;
                        self.request_blocks(blocks).await?;
                    }
                }
                PeerMessages::Headers(headers) => {
                    self.inflight.remove(&InflightRequests::Headers);
                    return self.ibd_handle_headers(headers).await;
                }
                PeerMessages::Ready(version) => {
                    if version.feeler {
                        self.send_to_peer(peer, NodeRequest::Shutdown).await?;
                        self.address_man.update_set_state(
                            version.address_id,
                            AddressState::Tried(
                                SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                            ),
                        );
                        self.address_man
                            .update_set_service_flag(version.address_id, version.services);
                        return Ok(());
                    }
                    info!(
                        "New peer id={} version={} blocks={}",
                        version.id, version.user_agent, version.blocks
                    );
                    if let Some(peer_data) = self.peers.get_mut(&peer) {
                        peer_data.state = PeerStatus::Ready;
                        peer_data.services = version.services;
                        self.address_man
                            .update_set_state(version.address_id, AddressState::Connected)
                            .update_set_service_flag(version.address_id, version.services);
                        if version.services.has(ServiceFlags::NODE_UTREEXO) {
                            self.utreexo_peers.push(peer);
                        }
                        self.peer_ids.push(peer);
                    }

                    if version.services.has(ServiceFlags::NODE_UTREEXO) {
                        if let NodeState::WaitingPeer = self.state {
                            try_and_log!(
                                self.send_to_random_peer(
                                    NodeRequest::GetHeaders(
                                        self.chain.get_block_locator().expect("Can get locators"),
                                    ),
                                    ServiceFlags::NONE
                                )
                                .await
                            );
                            self.state = NodeState::DownloadHeaders;
                        }
                    }
                }
                PeerMessages::Disconnected(idx) => {
                    if let Some(p) = self.peers.remove(&peer) {
                        p.channel.close();
                        if !p.feeler && p.state == PeerStatus::Ready {
                            info!("Peer disconnected: {}", peer);
                        }
                    }
                    self.peer_ids.retain(|&id| id != peer);
                    self.utreexo_peers.retain(|&id| id != peer);

                    self.address_man.update_set_state(
                        idx,
                        AddressState::Tried(
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                        ),
                    );
                }
                PeerMessages::Addr(addresses) => {
                    let addresses: Vec<_> =
                        addresses.iter().cloned().map(|addr| addr.into()).collect();
                    self.address_man.push_addresses(&addresses);
                }
            },
        }
        Ok(())
    }
    pub async fn init_peers(&mut self) -> Result<(), BlockchainError> {
        let anchors = self.address_man.start_addr_man(
            self.datadir.clone(),
            self.get_default_port(),
            self.network,
            &get_chain_dns_seeds(self.network),
        )?;
        for address in anchors {
            self.open_connection(false, address.id, address).await;
        }
        Ok(())
    }
    pub async fn run(mut self) {
        let kill_signal = Arc::new(RwLock::new(false));
        let _kill_signal = kill_signal.clone();
        ctrlc::set_handler(move || {
            info!("Shutting down");
            *block_on(_kill_signal.write()) = true;
        })
        .expect("Error setting Ctrl-C handler");

        try_and_log!(self.init_peers().await);
        try_and_log!(self.do_initial_block_download(&kill_signal).await);

        try_and_log!(
            self.send_to_random_peer(
                NodeRequest::GetHeaders(self.chain.get_block_locator().expect("Can get locators"),),
                ServiceFlags::NONE
            )
            .await
        );

        loop {
            while let Ok(notification) =
                timeout(Duration::from_millis(100), self.node_rx.recv()).await
            {
                try_and_log!(self.handle_notification(notification).await);
            }
            if *kill_signal.read().await {
                self.shutdown().await;
                break;
            }
            // Save our peers db
            periodic_job!(
                self.save_peers(),
                self.last_peer_db_dump,
                PEER_DB_DUMP_INTERVAL
            );
            // Rework our address database
            periodic_job!(
                self.address_man.rearrange_buckets(),
                self.last_address_rearrange,
                ADDRESS_REARRANGE_INTERVAL
            );
            // Aks our peers for new addresses
            periodic_job!(
                self.ask_for_addresses().await,
                self.last_get_address_request,
                ASK_FOR_PEERS_INTERVAL
            );
            // Check whether we are in a stale tip
            periodic_job!(
                self.check_for_stale_tip().await,
                self.last_tip_update,
                ASSUME_STALE
            );
            // Open new feeler connection periodically
            periodic_job!(
                self.open_feeler_connection().await,
                self.last_feeler,
                FEELER_INTERVAL
            );
            // Try broadcast transactions
            periodic_job!(
                self.handle_broadcast().await,
                self.last_broadcast,
                BROADCAST_DELAY
            );
            // Perhaps we need more connections
            periodic_job!(
                self.maybe_open_connection().await,
                self.last_connection,
                TRY_NEW_CONNECTION
            );
            try_and_log!(self.ask_block().await);
            try_and_log!(self.check_for_timeout().await);
        }
    }
    pub async fn shutdown(&mut self) {
        for peer in self.peer_ids.iter() {
            try_and_log!(self.send_to_peer(*peer, NodeRequest::Shutdown).await);
        }
        try_and_log!(self.save_peers());
        try_and_log!(self.chain.flush());
    }
    pub async fn ask_block(&mut self) -> Result<(), BlockchainError> {
        let blocks = self.get_blocks_to_download()?;
        self.request_blocks(blocks).await
    }
    pub async fn handle_broadcast(&self) -> Result<(), BlockchainError> {
        for (_, peer) in self.peers.iter() {
            if peer.services.has(ServiceFlags::NODE_UTREEXO) {
                continue;
            }

            let transactions = self.chain.get_unbroadcasted();

            for transaction in transactions {
                let txid = transaction.txid();
                self._mempool.write().await.accept_to_mempool(transaction);
                peer.channel
                    .send(NodeRequest::BroadcastTransaction(txid))
                    .await?;
            }
            let stale = self._mempool.write().await.get_stale();
            for tx in stale {
                peer.channel
                    .send(NodeRequest::BroadcastTransaction(tx))
                    .await?;
            }
        }
        Ok(())
    }
    pub async fn ask_for_addresses(&mut self) -> Result<(), BlockchainError> {
        let peer = self
            .send_to_random_peer(NodeRequest::GetAddresses, ServiceFlags::NONE)
            .await?;
        self.inflight
            .insert(InflightRequests::Addresses, (peer, Instant::now()));

        Ok(())
    }
    fn save_peers(&self) -> Result<(), BlockchainError> {
        Ok(self.address_man.dump_peers(&self.datadir)?)
    }
    fn get_blocks_to_download(&mut self) -> Result<Vec<BlockHash>, BlockchainError> {
        let mut blocks = vec![];
        let height = self.chain.get_height()?;
        for i in (self.last_block_request + 1)..=(self.last_block_request + 100) {
            if i > height {
                break;
            }
            self.last_block_request += 1;
            let hash = self.chain.get_block_hash(i)?;
            blocks.push(hash);
        }

        Ok(blocks)
    }
    pub async fn do_initial_block_download(
        &mut self,
        stop_signal: &Arc<RwLock<bool>>,
    ) -> Result<(), BlockchainError> {
        self.create_connection(false).await;
        loop {
            while let Ok(notification) =
                timeout(Duration::from_millis(10), self.node_rx.recv()).await
            {
                try_and_log!(self.handle_notification(notification).await);
                if *stop_signal.read().await {
                    break;
                }
            }

            periodic_job!(
                self.maybe_open_connection().await,
                self.last_connection,
                TRY_NEW_CONNECTION
            );
            if self.state == NodeState::WaitingPeer {
                continue;
            }
            if self.state == NodeState::DownloadBlocks
                && (self.inflight.len() + self.blocks.len()) < MAX_INFLIGHT_REQUESTS
            {
                let blocks = self.get_blocks_to_download()?;
                if blocks.is_empty() {
                    info!("Finished downloading blocks");
                    self.state = NodeState::Running;
                    self.chain.toggle_ibd(false);
                    break;
                }
                self.request_blocks(blocks).await?;
            }

            self.check_for_timeout().await?;

            periodic_job!(
                self.ibd_maybe_request_headers().await,
                self.last_headers_request,
                IBD_REQUEST_BLOCKS_AGAIN
            );
        }
        Ok(())
    }
    async fn ibd_maybe_request_headers(&mut self) -> Result<(), BlockchainError> {
        if self.state != NodeState::DownloadHeaders {
            return Ok(());
        }
        info!("Asking for headers");
        let locator = self
            .chain
            .get_block_locator()
            .expect("Could not create locator");
        self.send_to_random_peer(NodeRequest::GetHeaders(locator), ServiceFlags::NONE)
            .await?;
        self.last_headers_request = Instant::now();
        Ok(())
    }
    /// This function checks how many time has passed since our last tip update, if it's
    /// been more than 15 minutes, try to update it.
    async fn check_for_stale_tip(&mut self) -> Result<(), BlockchainError> {
        warn!("Potential stale tip detected, trying extra peers");
        self.create_connection(false).await;
        self.send_to_random_peer(
            NodeRequest::GetHeaders(self.chain.get_block_locator().unwrap()),
            ServiceFlags::NONE,
        )
        .await?;
        Ok(())
    }
    async fn maybe_open_connection(&mut self) -> Result<(), BlockchainError> {
        if self.peers.len() < MAX_OUTGOING_PEERS {
            self.create_connection(false).await;
        }
        Ok(())
    }
    async fn open_feeler_connection(&mut self) -> Result<(), BlockchainError> {
        self.create_connection(true).await;
        Ok(())
    }
    fn handle_block(&mut self, block: UtreexoBlock) -> Result<(), BlockchainError> {
        let height = self.chain.get_validation_index()? + 1;
        if self.chain.get_block_hash(height)? == block.block.block_hash() {
            let (proof, del_hashes, inputs) = Self::process_proof(
                &block.udata.unwrap(),
                &block.block.txdata,
                &self.chain,
                &block.block.block_hash(),
            )?;
            self.chain
                .connect_block(&block.block, proof, inputs, del_hashes)
                .map(|_| {
                    let new_height = self.chain.get_validation_index().unwrap() + 1;
                    assert_ne!(height, new_height);

                    let _ = self.chain.get_block_hash(new_height).and_then(|hash| {
                        // It may be the case that we have the next block queued up, if so, process it
                        if let Some(block) = self.blocks.remove(&hash) {
                            self.handle_block(block)?;
                        }
                        Ok(())
                    });
                })
                .or_else(|e| {
                    if let BlockchainError::BlockValidationError(_) = &e {
                        try_and_log!(self.chain.invalidate_block(block.block.block_hash()));
                    }
                    error!(
                        "Error while connecting block {}: {e:?}",
                        block.block.block_hash()
                    );
                    Ok(())
                })
        } else {
            self.blocks.insert(block.block.block_hash(), block);
            Ok(())
        }
    }
    async fn request_blocks(&mut self, blocks: Vec<BlockHash>) -> Result<(), BlockchainError> {
        let peer = self
            .send_to_random_peer(
                NodeRequest::GetBlock(blocks.clone()),
                ServiceFlags::NODE_UTREEXO,
            )
            .await?;
        for block in blocks.iter() {
            self.inflight
                .insert(InflightRequests::Blocks(*block), (peer, Instant::now()));
        }
        Ok(())
    }
    async fn create_connection(&mut self, feeler: bool) -> Option<()> {
        // We should try to keep at least two utreexo connections
        let required_services = if self.utreexo_peers.len() < 2 {
            ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::NODE_UTREEXO
        } else {
            ServiceFlags::NETWORK | ServiceFlags::WITNESS
        };
        let (peer_id, address) = self
            .address_man
            .get_address_to_connect(required_services, feeler)?;
        self.open_connection(feeler, peer_id, address).await;
        Some(())
    }
    async fn open_connection(&mut self, feeler: bool, peer_id: usize, address: LocalAddress) {
        let (requests_tx, requests_rx) = bounded(1024);
        spawn(Peer::create_outbound_connection(
            self.peer_id_count,
            (address.get_net_address(), address.get_port()),
            self._mempool.clone(),
            self.network,
            self.node_tx.clone(),
            requests_rx,
            peer_id,
            feeler,
        ));
        self.peers.insert(
            self.peer_id_count,
            LocalPeerView {
                state: PeerStatus::Awaiting,
                channel: requests_tx,
                services: ServiceFlags::NONE,
                _last_message: Instant::now(),
                feeler,
                address_id: peer_id as u32,
            },
        );

        self.peer_id_count += 1;
    }
}

macro_rules! try_and_log {
    ($what: expr) => {
        let result = $what;

        if let Err(error) = result {
            log::error!("{:?}", error);
        }
    };
}
macro_rules! periodic_job {
    ($what: expr, $timer: expr, $interval: ident) => {
        if $timer.elapsed() > Duration::from_secs($interval) {
            try_and_log!($what);
            $timer = Instant::now();
        }
    };
}
pub(crate) use periodic_job;
pub(crate) use try_and_log;
