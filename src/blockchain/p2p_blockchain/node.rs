//! Main file for this blockchain. A node is the central task that runs and handles important
//! events, such as new blocks, peer connection/disconnection, new addresses, etc.
//! A node should not care about peer-specific messages, peers'll handle things like pings.
use super::{
    address_man::{AddressMan, LocalAddress},
    mempool::Mempool,
    node_interface::{NodeInterface, NodeResponse, PeerInfo, UserRequest},
    peer::{Peer, PeerMessages, Version},
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
    task::spawn,
};
use bitcoin::{
    hashes::{sha256, Hash},
    network::{
        constants::ServiceFlags,
        message_blockdata::Inventory,
        utreexo::{UData, UtreexoBlock},
    },
    BlockHash, BlockHeader, Network, OutPoint, Transaction, TxOut, Txid,
};
use log::{error, info, trace, warn};
use oneshot::SendError;
use rustreexo::accumulator::proof::Proof;
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Max number of simultaneous connections we initiates we are willing to hold
const MAX_OUTGOING_PEERS: usize = 10;
/// We ask for peers every ASK_FOR_PEERS_INTERVAL seconds
const ASK_FOR_PEERS_INTERVAL: u64 = 60; // One minute
/// Save our database of peers every PEER_DB_DUMP_INTERVAL seconds
const PEER_DB_DUMP_INTERVAL: u64 = 60 * 5; // 5 minutes
/// Attempt to open a new connection (if needed) every TRY_NEW_CONNECTION seconds
const TRY_NEW_CONNECTION: u64 = 30; // 30 seconds
/// If ASSUME_STALE seconds passed since our last tip update, treat it as stale
const ASSUME_STALE: u64 = 30 * 60; // 30 minutes
/// While on IBD, if we've been without blocks for this long, ask for headers again
const IBD_REQUEST_BLOCKS_AGAIN: u64 = 10; // 10 seconds
/// How often we broadcast transactions
const BROADCAST_DELAY: u64 = 30; // 30 seconds
/// Wait up to this many seconds for a peer to respond to a request
const PEER_REQUEST_TIMEOUT: u64 = 30 * 60; // 30 minutes FIXME: This is too long
/// Max number of simultaneous inflight requests we allow
const MAX_INFLIGHT_REQUESTS: usize = 1_000;
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
#[derive(Debug, Clone, PartialEq, Hash)]
/// Sent from node to peers, usually to request something
pub enum NodeRequest {
    /// Get this block's data
    GetBlock((Vec<BlockHash>, bool)),
    /// Asks peer for headers
    GetHeaders(Vec<BlockHash>),
    /// Ask for other peers addresses
    GetAddresses,
    /// Asks this peer to shutdown
    Shutdown,
    /// Sends a transaction to peers
    BroadcastTransaction(Txid),
    /// Ask for an unconfirmed transaction
    MempoolTransaction(Txid),
}

#[derive(Default, PartialEq)]
enum NodeState {
    #[default]
    WaitingPeer,
    DownloadHeaders,
    DownloadBlocks,
    Running,
}
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
enum InflightRequests {
    Headers,
    Blocks(BlockHash),
    RescanBlock(BlockHash),
    Addresses,
    UserRequest(UserRequest),
    Connect(u32),
}
#[derive(Debug, Clone)]
pub struct LocalPeerView {
    state: PeerStatus,
    address_id: u32,
    channel: Sender<NodeRequest>,
    services: ServiceFlags,
    user_agent: String,
    address: IpAddr,
    port: u16,
    _last_message: Instant,
    feeler: bool,
    height: u32,
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum RescanStatus {
    InProgress(u32),
    Completed(Instant),
    None,
}
pub struct NodeCommon {
    peer_id_count: u32,
    last_headers_request: Instant,
    last_tip_update: Instant,
    last_connection: Instant,
    last_peer_db_dump: Instant,
    last_broadcast: Instant,
    last_block_request: u32,
    network: Network,
    last_get_address_request: Instant,
    utreexo_peers: Vec<u32>,
    peer_ids: Vec<u32>,
    peers: HashMap<u32, LocalPeerView>,
    chain: Arc<ChainState<KvChainStore>>,
    inflight: HashMap<InflightRequests, (u32, Instant)>,
    node_rx: Receiver<NodeNotification>,
    node_tx: Sender<NodeNotification>,
    state: NodeState,
    mempool: Arc<RwLock<Mempool>>,
    datadir: String,
    address_man: AddressMan,
}
/// The main node struct. It holds all the important information about the node, such as the
/// blockchain, the peers, the mempool, etc.
/// It also holds the channels to communicate with peers and the block downloader.
/// The node is the central task that runs and handles important events, such as new blocks,
/// peer connection/disconnection, new addresses, etc.
pub struct UtreexoNode<Context>(NodeCommon, Context);
impl<T> Deref for UtreexoNode<T> {
    fn deref(&self) -> &Self::Target {
        &self.0
    }
    type Target = NodeCommon;
}
impl<T> DerefMut for UtreexoNode<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
#[derive(Debug, PartialEq, Clone, Copy)]
enum PeerStatus {
    Awaiting,
    Ready,
    ShutingDown,
}
#[derive(Debug, Default, Clone)]
pub struct IBDNode {
    blocks: HashMap<BlockHash, UtreexoBlock>,
}

#[derive(Debug, Clone)]
pub struct RunningNode {
    last_rescan_request: RescanStatus,
    last_feeler: Instant,
    last_address_rearrange: Instant,
    user_requests: Arc<NodeInterface>,
}

impl Default for RunningNode {
    fn default() -> Self {
        RunningNode {
            last_rescan_request: RescanStatus::None,
            last_feeler: Instant::now(),
            last_address_rearrange: Instant::now(),
            user_requests: Arc::new(NodeInterface {
                requests: Mutex::new(vec![]),
            }),
        }
    }
}

impl<T: 'static + Default> UtreexoNode<T> {
    pub fn new(
        chain: Arc<ChainState<KvChainStore>>,
        mempool: Arc<RwLock<Mempool>>,
        network: Network,
        datadir: String,
    ) -> Self {
        let (node_tx, node_rx) = channel::unbounded();
        UtreexoNode(
            NodeCommon {
                inflight: HashMap::new(),
                state: NodeState::WaitingPeer,
                peer_id_count: 0,
                peers: HashMap::new(),
                last_block_request: chain.get_validation_index().expect("Invalid chain"),
                chain,
                peer_ids: Vec::new(),
                utreexo_peers: Vec::new(),
                mempool,
                network,
                node_rx,
                node_tx,
                address_man: AddressMan::default(),
                last_headers_request: Instant::now(),
                last_tip_update: Instant::now(),
                last_connection: Instant::now(),
                last_peer_db_dump: Instant::now(),
                last_broadcast: Instant::now(),
                last_get_address_request: Instant::now(),
                datadir,
            },
            T::default(),
        )
    }
    async fn handle_disconnection(&mut self, peer: u32, idx: usize) -> Result<(), BlockchainError> {
        if let Some(p) = self.peers.remove(&peer) {
            p.channel.close();
            if !p.feeler && p.state == PeerStatus::Ready {
                info!("Peer disconnected: {}", peer);
            }
        }
        self.peer_ids.retain(|&id| id != peer);
        self.utreexo_peers.retain(|&id| id != peer);

        if self.peer_ids.is_empty() || self.utreexo_peers.is_empty() {
            self.state = NodeState::WaitingPeer;
        }
        self.address_man.update_set_state(
            idx,
            AddressState::Tried(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
        );
        Ok(())
    }
    fn get_peer_info(&self, peer: &LocalPeerView) -> Option<PeerInfo> {
        Some(PeerInfo {
            address: format!("{}:{}", peer.address, peer.port),
            services: peer.services.to_string(),
            user_agent: peer.user_agent.clone(),
            initial_height: peer.height,
        })
    }
    async fn handle_peer_ready(
        &mut self,
        peer: u32,
        version: &Version,
    ) -> Result<(), BlockchainError> {
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
        self.inflight.remove(&InflightRequests::Connect(peer));

        if let Some(peer_data) = self.peers.get_mut(&peer) {
            // This peer doesn't have basic services, so we disconnect it
            if !version
                .services
                .has(ServiceFlags::NETWORK | ServiceFlags::WITNESS)
            {
                self.send_to_peer(peer, NodeRequest::Shutdown).await?;
                return Ok(());
            }
            peer_data.state = PeerStatus::Ready;
            peer_data.services = version.services;
            peer_data.user_agent = version.user_agent.clone();
            peer_data.height = version.blocks;
            self.address_man
                .update_set_state(version.address_id, AddressState::Connected)
                .update_set_service_flag(version.address_id, version.services);
            if version.services.has(ServiceFlags::NODE_UTREEXO) {
                self.utreexo_peers.push(peer);
            }
            self.peer_ids.push(peer);
        }
        Ok(())
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

    async fn send_to_peer(&self, peer_id: u32, req: NodeRequest) -> Result<(), BlockchainError> {
        if let Some(peer) = &self.peers.get(&peer_id) {
            if peer.state == PeerStatus::Ready {
                peer.channel.send(req).await?;
            }
        }
        Ok(())
    }
    async fn check_for_timeout(&mut self) -> Result<(), BlockchainError> {
        let mut timed_out = vec![];
        for request in self.inflight.keys() {
            let (_, time) = self.inflight.get(request).unwrap();
            if time.elapsed() > Duration::from_secs(PEER_REQUEST_TIMEOUT) {
                timed_out.push(request.clone());
            }
        }
        let mut removed_peers = HashSet::new();
        let mut to_request = vec![];
        for request in timed_out {
            let Some((peer, _)) = self.inflight.remove(&request) else {
                continue;
            };
            match request {
                InflightRequests::Blocks(block) | InflightRequests::RescanBlock(block) => {
                    to_request.push(block)
                }
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
                InflightRequests::UserRequest(_) => {}
                InflightRequests::Connect(_) => {
                    self.send_to_peer(peer, NodeRequest::Shutdown).await?
                }
            }

            if !removed_peers.contains(&peer) {
                if let Some(peer) = self.peers.get_mut(&peer) {
                    peer.state = PeerStatus::ShutingDown;
                }

                self.send_to_peer(peer, NodeRequest::Shutdown).await?;
                removed_peers.insert(peer);
            }
        }
        self.request_blocks(to_request).await?;
        Ok(())
    }
    #[inline]
    pub async fn send_to_random_peer(
        &mut self,
        req: NodeRequest,
        required_services: ServiceFlags,
    ) -> Result<u32, BlockchainError> {
        for _ in 0..10 {
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
                if self.peer_ids.is_empty() {
                    return Err(BlockchainError::NoPeersAvailable);
                }
                let idx = rand::random::<usize>() % self.peer_ids.len();
                *self
                    .peer_ids
                    .get(idx)
                    .expect("node is in the interval 0..utreexo_peers.len(), but is not here?")
            };
            if let Some(peer) = self.peers.get(&idx) {
                if peer.state != PeerStatus::Ready {
                    continue;
                }
                peer.channel.send(req.clone()).await?;
                return Ok(idx);
            }
        }
        Err(BlockchainError::NoPeersAvailable)
    }

    pub async fn init_peers(&mut self) -> Result<(), BlockchainError> {
        let datadir = self.datadir.clone();
        let port = self.get_default_port();
        let net = self.network;
        let seeds = get_chain_dns_seeds(self.network);
        let anchors = self
            .address_man
            .start_addr_man(datadir, port, net, &seeds)?;
        for address in anchors {
            self.open_connection(false, address.id, address).await;
        }
        Ok(())
    }

    pub async fn shutdown(&mut self) {
        info!("Shutting down node");
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
                self.mempool.write().await.accept_to_mempool(transaction);
                peer.channel
                    .send(NodeRequest::BroadcastTransaction(txid))
                    .await?;
            }
            let stale = self.mempool.write().await.get_stale();
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
        let tip = self.chain.get_height()?;

        for i in (self.last_block_request + 1)..=(self.last_block_request + 100) {
            if i > tip {
                break;
            }
            self.last_block_request += 1;
            let hash = self.chain.get_block_hash(i)?;
            blocks.push(hash);
        }

        Ok(blocks)
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

    async fn request_blocks(&mut self, blocks: Vec<BlockHash>) -> Result<(), BlockchainError> {
        if self.state == NodeState::WaitingPeer {
            return Ok(());
        }

        for block in blocks.iter() {
            // Don't ask for the same block again
            if self
                .inflight
                .contains_key(&InflightRequests::Blocks(*block))
            {
                continue;
            }
            let peer = self
                .send_to_random_peer(
                    NodeRequest::GetBlock((vec![*block], true)),
                    ServiceFlags::NODE_UTREEXO,
                )
                .await?;
            self.inflight
                .insert(InflightRequests::Blocks(*block), (peer, Instant::now()));
        }
        Ok(())
    }

    async fn create_connection(&mut self, feeler: bool) -> Option<()> {
        // We should try to keep at least one utreexo connections
        let required_services = if self.utreexo_peers.is_empty() {
            ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::NODE_UTREEXO
        } else {
            ServiceFlags::NETWORK | ServiceFlags::WITNESS
        };
        let (peer_id, address) = self
            .address_man
            .get_address_to_connect(required_services, feeler)?;
        self.address_man
            .update_set_state(peer_id, AddressState::Connected);
        // Don't connect to the same peer twice
        if self
            .0
            .peers
            .iter()
            .any(|peers| peers.1.address == address.get_net_address())
        {
            return None;
        }

        self.open_connection(feeler, peer_id, address).await;
        Some(())
    }
    async fn open_connection(&mut self, feeler: bool, peer_id: usize, address: LocalAddress) {
        let (requests_tx, requests_rx) = bounded(1024);
        spawn(Peer::create_outbound_connection(
            self.peer_id_count,
            (address.get_net_address(), address.get_port()),
            self.mempool.clone(),
            self.network,
            self.node_tx.clone(),
            requests_rx,
            peer_id,
            feeler,
        ));
        let peer_count: u32 = self.peer_id_count;

        self.inflight.insert(
            InflightRequests::Connect(peer_count),
            (peer_count, Instant::now()),
        );

        self.peers.insert(
            peer_count,
            LocalPeerView {
                address: address.get_net_address(),
                port: address.get_port(),
                user_agent: "".to_string(),
                state: PeerStatus::Awaiting,
                channel: requests_tx,
                services: ServiceFlags::NONE,
                _last_message: Instant::now(),
                feeler,
                address_id: peer_id as u32,
                height: 0,
            },
        );

        self.peer_id_count += 1;
    }
}
impl UtreexoNode<IBDNode> {
    async fn handle_block(
        chain: &Arc<ChainState<KvChainStore>>,
        block: UtreexoBlock,
    ) -> Result<(), BlockchainError> {
        let (proof, del_hashes, inputs) = Self::process_proof(
            &block.udata.unwrap(),
            &block.block.txdata,
            chain,
            &block.block.block_hash(),
        )?;
        try_and_log!(chain
            .connect_block(&block.block, proof, inputs, del_hashes)
            .map_err(|e| {
                if let BlockchainError::BlockValidationError(_) = &e {
                    try_and_log!(chain.invalidate_block(block.block.block_hash()));
                }
                error!(
                    "Error while connecting block {}: {e:?}",
                    block.block.block_hash()
                );
                e
            }));
        Ok(())
    }
    pub async fn handle_headers(
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
            "Downloading headers at height={} hash={}",
            self.chain.get_best_block()?.0 + 1,
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
    async fn maybe_request_headers(&mut self) -> Result<(), BlockchainError> {
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
    pub async fn run(&mut self, stop_signal: &Arc<RwLock<bool>>) -> Result<(), BlockchainError> {
        self.create_connection(false).await;
        loop {
            while let Ok(notification) =
                timeout(Duration::from_millis(10), self.node_rx.recv()).await
            {
                try_and_log!(self.handle_notification(notification).await);
            }
            if *stop_signal.read().await {
                break;
            }
            periodic_job!(
                self.maybe_open_connection().await,
                self.last_connection,
                TRY_NEW_CONNECTION
            );

            self.last_tip_update = Instant::now();

            // If we don't have any peers, then we can't do anything
            if self.state == NodeState::WaitingPeer {
                continue;
            }
            // We download blocks in parallel, sometimes we get them out of order, so we need to
            // process them in order. If we got all blocks but the first one, we can't process
            // them yet. Once we get it, we can process all blocks we have.
            if self.state == NodeState::DownloadBlocks {
                self.process_queued_blocks().await.or_else(|err| {
                    // This usually means we just processed all blocks, and we are done.
                    if matches!(err, BlockchainError::BlockNotPresent) {
                        info!("Finished downloading blocks");
                        self.chain.toggle_ibd(false);
                        Ok(())
                    } else {
                        Err(err)
                    }
                })?;
            }
            if !self.chain.is_in_idb() {
                break;
            }
            // If we are downloading blocks, we need to request more if we have space.
            let currently_inflight = self.0.inflight.len() + self.1.blocks.len();
            if self.state == NodeState::DownloadBlocks && currently_inflight < MAX_INFLIGHT_REQUESTS
            {
                let blocks = self.get_blocks_to_download()?;
                if blocks.is_empty() {
                    info!("Finished downloading blocks");
                    self.chain.toggle_ibd(false);

                    break;
                }
                self.request_blocks(blocks).await?;
            }

            self.check_for_timeout().await?;

            periodic_job!(
                self.maybe_request_headers().await,
                self.last_headers_request,
                IBD_REQUEST_BLOCKS_AGAIN
            );
        }
        Ok(())
    }
    async fn process_queued_blocks(&mut self) -> Result<(), BlockchainError> {
        let mut hash = self
            .chain
            .get_block_hash(self.chain.get_validation_index()? + 1)?;

        while let Some(block) = self.1.blocks.remove(&hash) {
            Self::handle_block(&self.chain, block).await?;
            hash = self
                .chain
                .get_block_hash(self.chain.get_validation_index()? + 1)?;
        }
        Ok(())
    }

    pub async fn handle_notification(
        &mut self,
        notification: Result<NodeNotification, async_std::channel::RecvError>,
    ) -> Result<(), BlockchainError> {
        match notification? {
            NodeNotification::FromPeer(peer, message) => match message {
                PeerMessages::NewBlock(block) => {
                    trace!("We got and inv with block {block} but we are on IBD, ignoring it");
                }
                PeerMessages::Block(block) => {
                    // Remove from inflight, since we just got it.
                    if self
                        .inflight
                        .remove(&InflightRequests::Blocks(block.block.block_hash()))
                        .is_none()
                    {
                        // We didn't request this block, so we should disconnect the peer.
                        if let Some(peer) = self.peers.get(&peer).cloned() {
                            self.address_man.update_set_state(
                                peer.address_id as usize,
                                AddressState::Banned(BAN_TIME),
                            );
                        }
                        error!(
                            "Peer {peer} sent us block {} which we didn't request",
                            block.block.block_hash()
                        );

                        self.send_to_peer(peer, NodeRequest::Shutdown).await?;
                        return Err(BlockchainError::PeerMisbehaving);
                    }
                    // We may receive blocks out of order, so we store them in a map until we
                    // receive all the previous ones.
                    let height = self.chain.get_validation_index()? + 1;
                    if self.0.chain.get_block_hash(height)? == block.block.block_hash() {
                        Self::handle_block(&self.chain, block).await?;
                    } else {
                        self.1.blocks.insert(block.block.block_hash(), block);
                    }

                    let currently_inflight = self.inflight.len() + self.1.blocks.len();
                    if self.state == NodeState::DownloadBlocks
                        && currently_inflight < MAX_INFLIGHT_REQUESTS
                    {
                        let blocks = self.get_blocks_to_download()?;
                        self.request_blocks(blocks).await?;
                    }
                }
                PeerMessages::Headers(headers) => {
                    self.inflight.remove(&InflightRequests::Headers);
                    return self.handle_headers(headers).await;
                }
                PeerMessages::Ready(version) => {
                    self.handle_peer_ready(peer, &version).await?;

                    if version.services.has(ServiceFlags::NODE_UTREEXO)
                        && matches!(self.state, NodeState::WaitingPeer)
                        && !self.inflight.contains_key(&InflightRequests::Headers)
                    {
                        try_and_log!(
                            self.send_to_peer(
                                peer,
                                NodeRequest::GetHeaders(
                                    self.chain.get_block_locator().expect("Can get locators"),
                                )
                            )
                            .await
                        );
                        self.state = NodeState::DownloadHeaders;
                    }
                }

                PeerMessages::Disconnected(idx) => {
                    self.handle_disconnection(peer, idx).await?;

                    if self.peer_ids.is_empty() || self.utreexo_peers.is_empty() {
                        self.state = NodeState::WaitingPeer;
                    }
                }
                PeerMessages::Addr(addresses) => {
                    let addresses: Vec<_> =
                        addresses.iter().cloned().map(|addr| addr.into()).collect();
                    self.address_man.push_addresses(&addresses);
                }
                _ => {}
            },
        }
        Ok(())
    }
}

impl UtreexoNode<RunningNode> {
    #[cfg(feature = "json-rpc")]
    /// Returns a handle to the node interface that we can use to request data from our
    /// node. This struct is thread safe, so we can use it from multiple threads and have
    /// multiple handles. It also doesn't require a mutable reference to the node, or any
    /// synchronization mechanism.
    pub fn get_handle(&self) -> Arc<NodeInterface> {
        self.1.user_requests.clone()
    }
    fn check_request_timeout(&mut self) -> Result<(), SendError<NodeResponse>> {
        let mutex = self.1.user_requests.requests.lock().unwrap();
        let mut to_remove = vec![];
        for req in mutex.iter() {
            if req.time.elapsed() > Duration::from_secs(10) {
                to_remove.push(req.req);
            }
        }
        drop(mutex);
        for request in to_remove {
            self.1.user_requests.send_answer(request, None);
        }

        Ok(())
    }
    async fn handle_user_request(&mut self) {
        let mut requests = vec![];

        for request in self.1.user_requests.requests.lock().unwrap().iter() {
            if !self
                .inflight
                .contains_key(&InflightRequests::UserRequest(request.req))
            {
                requests.push(request.req);
            }
        }
        self.perform_user_request(requests).await;
    }
    fn handle_get_peer_info(&self) {
        let mut peers = vec![];
        for peer in self.peers.values() {
            peers.push(self.get_peer_info(peer));
        }
        let peers = peers.into_iter().flatten().collect();
        self.1.user_requests.send_answer(
            UserRequest::GetPeerInfo,
            Some(NodeResponse::GetPeerInfo(peers)),
        );
    }
    async fn perform_user_request(&mut self, user_req: Vec<UserRequest>) {
        for user_req in user_req {
            let req = match user_req {
                UserRequest::Block(block) => NodeRequest::GetBlock((vec![block], false)),
                UserRequest::UtreexoBlock(block) => NodeRequest::GetBlock((vec![block], true)),
                UserRequest::MempoolTransaction(txid) => NodeRequest::MempoolTransaction(txid),
                UserRequest::GetPeerInfo => {
                    self.handle_get_peer_info();
                    continue;
                }
            };
            let peer = self.send_to_random_peer(req, ServiceFlags::NONE).await;
            if let Ok(peer) = peer {
                self.inflight.insert(
                    InflightRequests::UserRequest(user_req),
                    (peer, Instant::now()),
                );
            }
        }
    }
    pub async fn run(mut self, kill_signal: &Arc<RwLock<bool>>) {
        try_and_log!(self.init_peers().await);

        // Use this node state to Initial Block download
        let mut ibd = UtreexoNode(self.0, IBDNode::default());
        try_and_log!(UtreexoNode::<IBDNode>::run(&mut ibd, kill_signal).await);
        // Then take the final state and run the node
        self = UtreexoNode(ibd.0, self.1);

        let _ = self
            .send_to_random_peer(
                NodeRequest::GetHeaders(self.chain.get_block_locator().expect("Can get locators")),
                ServiceFlags::NONE,
            )
            .await;

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
            // Jobs that don't need a connected peer

            // Save our peers db
            periodic_job!(
                self.save_peers(),
                self.last_peer_db_dump,
                PEER_DB_DUMP_INTERVAL
            );
            // Rework our address database
            periodic_job!(
                self.address_man.rearrange_buckets(),
                self.1.last_address_rearrange,
                ADDRESS_REARRANGE_INTERVAL
            );
            // Perhaps we need more connections
            periodic_job!(
                self.maybe_open_connection().await,
                self.last_connection,
                TRY_NEW_CONNECTION
            );
            try_and_log!(self.check_request_timeout());
            self.handle_user_request().await;

            // Those jobs bellow needs a connected peer to work
            if self.state == NodeState::WaitingPeer {
                continue;
            }
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
                self.1.last_feeler,
                FEELER_INTERVAL
            );
            // Try broadcast transactions
            periodic_job!(
                self.handle_broadcast().await,
                self.last_broadcast,
                BROADCAST_DELAY
            );
            try_and_log!(self.ask_block().await);
            try_and_log!(self.check_for_timeout().await);
            try_and_log!(self.request_rescan_block().await);
        }
    }
    async fn request_rescan_block(&mut self) -> Result<(), BlockchainError> {
        let tip = self.chain.get_height().unwrap();
        if self.inflight.len() + 10 > MAX_INFLIGHT_REQUESTS {
            return Ok(());
        }
        // We use a grace period to avoid looping at the end of rescan
        if let RescanStatus::Completed(time) = self.1.last_rescan_request {
            if time.elapsed() > Duration::from_secs(60) {
                self.1.last_rescan_request = RescanStatus::None;
            }
        }
        if self.1.last_rescan_request == RescanStatus::None
            && self.chain.get_rescan_index().is_some()
        {
            self.1.last_rescan_request =
                RescanStatus::InProgress(self.chain.get_rescan_index().unwrap());
        }
        if let RescanStatus::InProgress(height) = self.1.last_rescan_request {
            for i in (height + 1)..=(height + 10) {
                if i > tip {
                    self.1.last_rescan_request = RescanStatus::Completed(Instant::now());
                    break;
                }
                self.1.last_rescan_request = RescanStatus::InProgress(i);
                let hash = self.chain.get_block_hash(i)?;
                let peer = self
                    .send_to_random_peer(
                        NodeRequest::GetBlock((vec![hash], false)),
                        ServiceFlags::NONE,
                    )
                    .await?;
                self.inflight
                    .insert(InflightRequests::RescanBlock(hash), (peer, Instant::now()));
            }
        }

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
    async fn handle_new_block(&mut self) -> Result<(), BlockchainError> {
        if self.inflight.contains_key(&InflightRequests::Headers) {
            return Ok(());
        }
        let locator = self.0.chain.get_block_locator().unwrap();

        let peer = self
            .send_to_random_peer(NodeRequest::GetHeaders(locator), ServiceFlags::NONE)
            .await?;
        self.inflight
            .insert(InflightRequests::Headers, (peer, Instant::now()));

        Ok(())
    }
    async fn handle_block_data(
        &mut self,
        block: UtreexoBlock,
        peer: u32,
    ) -> Result<(), BlockchainError> {
        if self
            .inflight
            .remove(&InflightRequests::RescanBlock(block.block.block_hash()))
            .is_some()
        {
            self.request_rescan_block().await?;
            return self.chain.process_rescan_block(&block.block);
        }
        if self
            .inflight
            .remove(&InflightRequests::UserRequest(UserRequest::Block(
                block.block.block_hash(),
            )))
            .is_some()
        {
            if block.udata.is_some() {
                self.1.user_requests.send_answer(
                    UserRequest::UtreexoBlock(block.block.block_hash()),
                    Some(NodeResponse::UtreexoBlock(block)),
                );
                return Ok(());
            }
            self.1.user_requests.send_answer(
                UserRequest::Block(block.block.block_hash()),
                Some(NodeResponse::Block(block.block)),
            );
            return Ok(());
        }
        // Remove from inflight, since we just got it.
        if self
            .inflight
            .remove(&InflightRequests::Blocks(block.block.block_hash()))
            .is_none()
        {
            // We didn't request this block, so we should disconnect the peer.
            if let Some(peer) = self.peers.get(&peer).cloned() {
                self.address_man
                    .update_set_state(peer.address_id as usize, AddressState::Banned(BAN_TIME));
            }
            error!(
                "Peer {peer} sent us block {} which we didn't request",
                block.block.block_hash()
            );
            self.send_to_peer(peer, NodeRequest::Shutdown).await?;
            return Err(BlockchainError::PeerMisbehaving);
        }
        let mempool_delta = self.mempool.write().await.consume_block(&block.block);

        let (proof, del_hashes, inputs) = Self::process_proof(
            &block.udata.unwrap(),
            &block.block.txdata,
            &self.chain,
            &block.block.block_hash(),
        )?;

        if let Err(e) = self
            .chain
            .connect_block(&block.block, proof, inputs, del_hashes)
        {
            error!("Invalid block received by peer {} reason: {:?}", peer, e);
            try_and_log!(self.chain.invalidate_block(block.block.block_hash()));

            error!(
                "Error while connecting block {}: {e:?}",
                block.block.block_hash()
            );
            // Disconnect the peer and ban it.
            if let Some(peer) = self.peers.get(&peer).cloned() {
                self.address_man
                    .update_set_state(peer.address_id as usize, AddressState::Banned(BAN_TIME));
            }
            self.send_to_peer(peer, NodeRequest::Shutdown).await?;

            // Add the transactions back to the mempool.
            for tx in mempool_delta {
                self.mempool.write().await.accept_to_mempool(tx);
            }
            return Err(e);
        }
        self.last_tip_update = Instant::now();
        Ok(())
    }
    pub async fn handle_notification(
        &mut self,
        notification: Result<NodeNotification, async_std::channel::RecvError>,
    ) -> Result<(), BlockchainError> {
        match notification? {
            NodeNotification::FromPeer(peer, message) => match message {
                PeerMessages::NewBlock(block) => {
                    trace!("We got an inv with block {block} requesting it");
                    self.handle_new_block().await?;
                }
                PeerMessages::Block(block) => {
                    trace!(
                        "Got data for block {} from peer {peer}",
                        block.block.block_hash()
                    );
                    self.handle_block_data(block, peer).await?;
                }
                PeerMessages::Headers(headers) => {
                    self.inflight.remove(&InflightRequests::Headers);
                    for header in headers.iter() {
                        self.chain.accept_header(*header)?;
                    }
                    let hashes = headers.iter().map(|header| header.block_hash()).collect();
                    self.request_blocks(hashes).await?;
                }
                PeerMessages::Ready(version) => {
                    self.handle_peer_ready(peer, &version).await?;
                    if version.services.has(ServiceFlags::NODE_UTREEXO) {
                        self.state = NodeState::Running;
                    }
                }
                PeerMessages::Disconnected(idx) => {
                    self.handle_disconnection(peer, idx).await?;
                }
                PeerMessages::Addr(addresses) => {
                    let addresses: Vec<_> =
                        addresses.iter().cloned().map(|addr| addr.into()).collect();
                    self.address_man.push_addresses(&addresses);
                }
                PeerMessages::NotFound(inv) => match inv {
                    Inventory::Error => {}
                    Inventory::Block(block)
                    | Inventory::WitnessBlock(block)
                    | Inventory::UtreexoBlock(block)
                    | Inventory::UtreexoWitnessBlock(block)
                    | Inventory::CompactBlock(block) => {
                        self.1
                            .user_requests
                            .send_answer(UserRequest::Block(block), None);
                    }

                    Inventory::WitnessTransaction(tx) | Inventory::Transaction(tx) => {
                        self.1
                            .user_requests
                            .send_answer(UserRequest::MempoolTransaction(tx), None);
                    }
                    _ => {}
                },
                PeerMessages::Transaction(tx) => {
                    self.1.user_requests.send_answer(
                        UserRequest::MempoolTransaction(tx.txid()),
                        Some(NodeResponse::MempoolTransaction(tx)),
                    );
                }
            },
        }
        Ok(())
    }
}

/// Run a task and log any errors that might occur.
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
