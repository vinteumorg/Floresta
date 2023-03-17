//! Main file for this blockchain. A node is the central task that runs and handles important
//! events, such as new blocks, peer connection/disconnection, new addresses, etc.
//! A node should not care about peer-specific messages, peers'll handle things like pings.
use super::{
    address_man::{AddressMan, LocalAddress},
    block_download::{BlockDownload, BlockDownloaderMessages},
    mempool::Mempool,
    peer::{Peer, PeerMessages},
};
use crate::blockchain::{
    chain_state::ChainState,
    chainstore::KvChainStore,
    error::BlockchainError,
    p2p_blockchain::address_man::{AddressState, DiskLocalAddress},
    udata::proof_util,
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
        utreexo::{UData, UtreexoBlock},
    },
    BlockHash, BlockHeader, Network, OutPoint, Transaction, TxOut,
};
use log::{error, info, warn};
use rustreexo::accumulator::proof::Proof;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

/// Max number of simultaneous connections we initiates we are willing to hold
const MAX_OUTGOING_PEERS: usize = 10;
/// We ask for peers every ASK_FOR_PEERS_INTERVAL seconds
const ASK_FOR_PEERS_INTERVAL: u64 = 60 * 1; // One minute
/// Save our database of peers every PEER_DB_DUMP_INTERVAL seconds
const PEER_DB_DUMP_INTERVAL: u64 = 60 * 20; // 20 minutes
/// Attempt to open a new connection (if needed) every TRY_NEW_CONNECTION seconds
const TRY_NEW_CONNECTION: u64 = 30; // 10 seconds
/// If ASSUME_STALE seconds passed since our last tip update, treat it as stale
const ASSUME_STALE: u64 = 15 * 60; // 15 minutes
/// While on IBD, if we've been without blocks for this long, ask for headers again
const IBD_REQUEST_BLOCKS_AGAIN: u64 = 10; // 10 seconds

#[derive(Debug)]
pub enum NodeNotification {
    FromPeer(u32, PeerMessages),
    FromBlockDownloader(BlockDownloaderMessages),
}
#[derive(Debug, Clone, PartialEq)]
#[allow(unused)]
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
}

#[derive(Default, PartialEq)]
enum NodeState {
    #[default]
    WaitingPeer,
    DownloadHeaders,
    DownloadBlocks,
    Running,
}
pub struct UtreexoNode {
    peer_id_count: u32,
    last_headers_request: Instant,
    last_tip_update: Instant,
    last_connection: Instant,
    last_get_address_request: Instant,
    last_peer_db_dump: Instant,
    network: Network,
    utreexo_peers: Vec<u32>,
    peers: HashMap<u32, (PeerStatus, u32, Sender<NodeRequest>)>,
    chain: Arc<ChainState<KvChainStore>>,
    _mempool: Arc<RwLock<Mempool>>,
    node_rx: Receiver<NodeNotification>,
    node_tx: Sender<NodeNotification>,
    state: NodeState,
    datadir: String,
    download_man: BlockDownload,
    address_man: AddressMan,
}
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
        let height = chain.get_validation_index().unwrap();
        let node = UtreexoNode {
            download_man: BlockDownload::new(
                chain.clone(),
                node_tx.clone(),
                &Self::handle_block,
                height,
            ),
            state: NodeState::default(),
            peer_id_count: 0,
            peers: HashMap::new(),
            chain,
            utreexo_peers: Vec::new(),
            _mempool: mempool,
            network,
            node_rx,
            node_tx,
            address_man: AddressMan::default(),
            last_headers_request: Instant::now(),
            last_tip_update: Instant::now(),
            last_connection: Instant::now(),
            last_peer_db_dump: Instant::now(),
            datadir,
            last_get_address_request: Instant::now(),
        };
        node
    }

    fn start_addr_man(&mut self) {
        let local_db = std::fs::read_to_string(self.datadir.to_owned() + "/peers.json");
        let peers = if let Ok(peers) = local_db {
            info!("Peers database found, using it");

            serde_json::from_str::<Vec<DiskLocalAddress>>(&peers)
        } else {
            info!("No peers available, using fixed peers");

            let addresses = include_str!("fixed_peers.json");
            serde_json::from_str(addresses)
        };
        if let Ok(peers) = peers {
            let peers = peers
                .iter()
                .cloned()
                .map(|addr| Into::<LocalAddress>::into(addr))
                .collect::<Vec<_>>();
            self.address_man.push_addresses(&peers);
        }
    }

    fn process_proof(
        udata: &UData,
        transactions: &[Transaction],
        chain: &ChainState<KvChainStore>,
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
                        let leaf = proof_util::reconstruct_leaf_data(&leaf, &input, hash)
                            .expect("Invalid proof");

                        inputs.insert(leaf.prevout, leaf.utxo);
                    }
                }
            }
        }

        Ok((proof, hashes, inputs))
    }
    pub async fn handle_headers(
        &mut self,
        headers: Vec<BlockHeader>,
    ) -> Result<(), BlockchainError> {
        if headers.is_empty() {
            // Start downloading blocks
            self.state = NodeState::DownloadBlocks;
            self.download_man.get_more_blocks().await?;
            return Ok(());
        }
        self.last_headers_request = Instant::now();
        info!(
            "Downloading headers at: {} hash: {}",
            self.chain.get_best_block().unwrap().0,
            headers[0].block_hash()
        );
        for header in headers {
            self.chain.accept_header(header)?;
        }
        let locator = self
            .chain
            .get_block_locator()
            .expect("Could not create locator");
        self.send_to_random_peer(NodeRequest::GetHeaders(locator), ServiceFlags::NONE)
            .await?;
        Ok(())
    }
    #[inline]
    pub async fn send_to_random_peer(
        &self,
        req: NodeRequest,
        required_services: ServiceFlags,
    ) -> Result<(), BlockchainError> {
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
            rand::random::<u32>() % self.peers.len() as u32
        };

        let peer = self
            .peers
            .get(&idx)
            .expect("node is in the interval 0..peers.len(), but is not here?");
        peer.2.send(req).await?;
        Ok(())
    }
    pub async fn handle_notification(
        &mut self,
        notification: Result<NodeNotification, async_std::channel::RecvError>,
    ) -> Result<(), BlockchainError> {
        let notification = notification?;
        match notification {
            NodeNotification::FromPeer(peer, message) => match message {
                PeerMessages::NewBlock(hash) => {
                    if !self.chain.is_in_idb() {
                        self.send_to_random_peer(
                            NodeRequest::GetBlock(vec![hash]),
                            ServiceFlags::NODE_UTREEXO,
                        )
                        .await?;
                    }
                }
                PeerMessages::Block(block) => {
                    if self.chain.is_in_idb() {
                        self.download_man.downloaded(block).await;
                    } else {
                        if self
                            .chain
                            .get_block_header(&block.block.block_hash())
                            .is_err()
                        {
                            self.chain.accept_header(block.block.header)?;
                        }
                        Self::handle_block(&self.chain, block);
                    }
                    self.last_tip_update = Instant::now();
                }
                PeerMessages::Headers(headers) => self.handle_headers(headers).await?,
                PeerMessages::Ready(version) => {
                    info!(
                        "New peer id={} version={} blocks={}",
                        version.id, version.user_agent, version.blocks
                    );
                    if let Some(peer) = self.peers.get_mut(&peer) {
                        peer.0 = PeerStatus::Ready;
                        self.address_man
                            .update_set_state(version.address_id, AddressState::Connected);
                        self.address_man
                            .update_set_service_flag(version.address_id, version.services);
                        if version.services.has(ServiceFlags::NODE_UTREEXO) {
                            self.utreexo_peers.push(peer.1);
                        }
                    }
                    if let NodeState::WaitingPeer = self.state {
                        if version.services.has(ServiceFlags::NODE_UTREEXO) {
                            info!("Requesting headers");
                            self.send_to_random_peer(
                                NodeRequest::GetHeaders(self.chain.get_block_locator().unwrap()),
                                ServiceFlags::NONE,
                            )
                            .await?;
                            self.state = NodeState::DownloadHeaders;
                        }
                    }
                }
                PeerMessages::Disconnected(idx) => {
                    self.peers.remove(&peer);
                    self.address_man.update_set_state(idx, AddressState::Tried);
                }
                PeerMessages::Addr(addresses) => {
                    let addresses: Vec<_> =
                        addresses.iter().cloned().map(|addr| addr.into()).collect();
                    self.address_man.push_addresses(&addresses);
                }
            },
            NodeNotification::FromBlockDownloader(blocks) => match blocks {
                BlockDownloaderMessages::AskForBlocks(headers) => {
                    self.ibd_request_blocks(headers).await?;
                }
            },
        }
        Ok(())
    }

    pub async fn run(mut self) -> ! {
        self.start_addr_man();
        self.create_connection().await;
        try_and_log!(self.do_initial_block_download().await);
        try_and_log!(
            self.send_to_random_peer(
                NodeRequest::GetHeaders(self.chain.get_block_locator().expect("Can get locators"),),
                ServiceFlags::NONE
            )
            .await
        );

        loop {
            while let Ok(notification) =
                async_std::future::timeout(Duration::from_millis(100), self.node_rx.recv()).await
            {
                try_and_log!(self.handle_notification(notification).await);
            }
            // Save our peers db
            periodic_job!(
                self.save_peers(),
                self.last_peer_db_dump,
                PEER_DB_DUMP_INTERVAL
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
            // Perhaps we need more connections
            periodic_job!(
                self.maybe_open_connection().await,
                self.last_connection,
                TRY_NEW_CONNECTION
            );
        }
    }
    pub async fn ask_for_addresses(&self) -> Result<(), BlockchainError> {
        Ok(self
            .send_to_random_peer(NodeRequest::GetAddresses, ServiceFlags::NONE)
            .await?)
    }
    fn save_peers(&self) -> Result<(), BlockchainError> {
        Ok(self.address_man.dump_peers(&self.datadir)?)
    }
    pub async fn do_initial_block_download(&mut self) -> Result<(), BlockchainError> {
        loop {
            while let Ok(notification) = timeout(Duration::from_secs(1), self.node_rx.recv()).await
            {
                try_and_log!(self.handle_notification(notification).await);
            }
            if let NodeState::DownloadBlocks = self.state {
                self.download_man.handle_timeout().await;
            } else {
                periodic_job!(
                    self.ibd_maybe_request_headers().await,
                    self.last_headers_request,
                    IBD_REQUEST_BLOCKS_AGAIN
                );
            }

            periodic_job!(
                self.maybe_open_connection().await,
                self.last_connection,
                TRY_NEW_CONNECTION
            );
            if !self.chain.is_in_idb() {
                self.state = NodeState::Running;
                break;
            }
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
        self.create_connection().await;
        self.send_to_random_peer(
            NodeRequest::GetHeaders(self.chain.get_block_locator().unwrap()),
            ServiceFlags::NONE,
        )
        .await
    }
    async fn maybe_open_connection(&mut self) -> Result<(), BlockchainError> {
        if self.peers.len() < MAX_OUTGOING_PEERS {
            self.create_connection().await;
        }
        Ok(())
    }
    fn handle_block(chain: &ChainState<KvChainStore>, block: UtreexoBlock) {
        let (proof, del_hashes, inputs) =
            Self::process_proof(&block.udata.unwrap(), &block.block.txdata, chain)
                .expect("Could not fetch proof");

        if let Err(e) = chain.connect_block(&block.block, proof, inputs, del_hashes) {
            error!(
                "Error while connecting block {}: {e:?}",
                block.block.block_hash()
            );
        }
    }
    async fn ibd_request_blocks(
        &mut self,
        next_blocks: Vec<BlockHash>,
    ) -> Result<(), BlockchainError> {
        if self.chain.get_best_block().unwrap().0 == self.chain.get_validation_index().unwrap()
            && self.chain.is_in_idb()
        {
            self.chain.toggle_ibd(false);
            info!("Leaving ibd");
            return Ok(());
        }
        self.send_to_random_peer(
            NodeRequest::GetBlock(next_blocks),
            ServiceFlags::NODE_UTREEXO,
        )
        .await?;
        Ok(())
    }
    async fn create_connection(&mut self) {
        // We should try to keep at least two utreexo connections
        let required_services = if self.utreexo_peers.len() < 2 {
            ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::NODE_UTREEXO
        } else {
            ServiceFlags::NETWORK | ServiceFlags::WITNESS
        };
        if let Some((peer_id, address)) = self.address_man.get_address_to_connect(required_services)
        {
            let (requests_tx, requests_rx) = bounded(1024);
            spawn(Peer::create_outbound_connection(
                self.peer_id_count,
                (address.get_net_address(), address.get_port()),
                self.network,
                self.node_tx.clone(),
                requests_rx,
                peer_id,
            ));
            self.peers.insert(
                self.peer_id_count,
                (PeerStatus::Awaiting, self.peer_id_count, requests_tx),
            );
            self.peer_id_count += 1;
        }
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
