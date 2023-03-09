//! Main file for this blockchain. A node is the central task that runs and handles important
//! events, such as new blocks, peer connection/disconnection, new addresses, etc.
//! A node should not care about peer-specific messages, peers'll handle things like pings.
use super::{
    address_man::AddressMan,
    block_download::{BlockDownload, BlockDownloaderMessages},
    mempool::Mempool,
    peer::{Peer, PeerMessages},
};
use crate::blockchain::{
    chain_state::ChainState, chainstore::KvChainStore, error::BlockchainError,
    p2p_blockchain::address_man::AddressState, udata::proof_util, BlockchainInterface,
    BlockchainProviderInterface,
};
use async_std::{
    channel::{self, bounded, Receiver, Sender},
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
    /// Asks this peer to shutdown
    Shutdown,
}

#[derive(Default)]
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
    network: Network,
    peers: Vec<(PeerStatus, u32, Sender<NodeRequest>)>,
    chain: Arc<ChainState<KvChainStore>>,
    _mempool: Arc<RwLock<Mempool>>,
    node_rx: Receiver<NodeNotification>,
    node_tx: Sender<NodeNotification>,
    state: NodeState,
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
            peers: Vec::new(),
            chain,
            _mempool: mempool,
            network,
            node_rx,
            node_tx,
            address_man: AddressMan::default(),
            last_headers_request: Instant::now(),
            last_tip_update: Instant::now(),
            last_connection: Instant::now(),
        };
        node
    }

    fn start_addr_man(&mut self) {
        let addresses = include_str!("fixed_peers.json");
        let addresses: Vec<&str> = serde_json::from_str(addresses).unwrap();
        let addresses = addresses
            .into_iter()
            .map(|addr| addr.try_into().expect("Invalid fixed peer"))
            .collect::<Vec<_>>();
        self.address_man.push_addresses(&addresses);
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
                if !transactions
                    .iter()
                    .any(|tx| tx.txid() == input.previous_output.txid)
                {
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
        self.send_to_random_peer(NodeRequest::GetHeaders(locator))
            .await?;
        Ok(())
    }
    #[inline]
    pub async fn send_to_random_peer(&self, req: NodeRequest) -> Result<(), BlockchainError> {
        if self.peers.is_empty() {
            return Err(BlockchainError::NoPeersAvailable);
        }
        for _ in 0..10 {
            let idx = rand::random::<usize>() % self.peers.len();
            if let PeerStatus::Ready = self
                .peers
                .get(idx)
                .expect("node is in the interval 0..peers.len(), but is not here?")
                .0
            {
                let peer = self
                    .peers
                    .get(idx)
                    .expect("node is in the interval 0..peers.len(), but is not here?");
                peer.2.send(req).await?;
                return Ok(());
            }
        }
        return Err(BlockchainError::RequestTimeout);
    }
    pub async fn handle_notification(
        &mut self,
        notification: NodeNotification,
    ) -> Result<(), BlockchainError> {
        match notification {
            NodeNotification::FromPeer(peer, message) => match message {
                PeerMessages::NewBlock(hash) => {
                    if !self.chain.is_in_idb() {
                        self.send_to_random_peer(NodeRequest::GetBlock(vec![hash]))
                            .await?;
                    }
                    Ok(())
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
                    Ok(())
                }
                PeerMessages::Headers(headers) => self.handle_headers(headers).await,
                PeerMessages::Ready(version) => {
                    info!(
                        "New peer id={} version={} blocks={}",
                        version.id, version.user_agent, version.blocks
                    );
                    if let Some(peer) = self.peers.get_mut(peer as usize) {
                        peer.0 = PeerStatus::Ready;
                        self.address_man
                            .update_set_state(version.address_id, AddressState::Connected);
                    }
                    if let NodeState::WaitingPeer = self.state {
                        info!("Requesting headers");
                        self.send_to_random_peer(NodeRequest::GetHeaders(
                            self.chain.get_block_locator().unwrap(),
                        ))
                        .await?;
                        self.state = NodeState::DownloadHeaders;
                    }

                    Ok(())
                }
                PeerMessages::Disconnected(idx) => {
                    warn!("Peer lost id={peer}");
                    let peer = self.peers.iter().position(|(_, id, _)| peer == *id);
                    if let Some(peer) = peer {
                        self.peers.remove(peer);
                        self.address_man.update_set_state(idx, AddressState::Tried);
                    }
                    Ok(())
                }
                PeerMessages::Addr(addresses) => {
                    let addresses: Vec<_> =
                        addresses.iter().cloned().map(|addr| addr.into()).collect();
                    self.address_man.push_addresses(&addresses);
                    Ok(())
                }
            },
            NodeNotification::FromBlockDownloader(blocks) => match blocks {
                BlockDownloaderMessages::AskForBlocks(headers) => {
                    self.ibd_request_blocks(headers).await?;
                    Ok(())
                }
            },
        }
    }

    pub async fn run(mut self) -> ! {
        self.start_addr_man();
        self.create_connection().await;
        try_and_log!(self.do_initial_block_download().await);
        try_and_log!(
            self.send_to_random_peer(NodeRequest::GetHeaders(
                self.chain.get_block_locator().expect("Can get locators"),
            ))
            .await
        );

        loop {
            while let Ok(notification) =
                async_std::future::timeout(Duration::from_secs(1), self.node_rx.recv()).await
            {
                if let Ok(notification) = notification {
                    try_and_log!(self.handle_notification(notification).await);
                }
            }
            self.check_for_stale_tip().await;
            self.maybe_open_connection().await;
        }
    }
    pub async fn do_initial_block_download(&mut self) -> Result<(), BlockchainError> {
        loop {
            while let Ok(notification) =
                async_std::future::timeout(Duration::from_secs(1), self.node_rx.recv()).await
            {
                if let Ok(notification) = notification {
                    try_and_log!(self.handle_notification(notification).await);
                }
            }
            if let NodeState::DownloadBlocks = self.state {
                self.download_man.handle_timeout().await;
            } else {
                self.ibd_maybe_request_headers().await?;
            }
            self.maybe_open_connection().await;
            if !self.chain.is_in_idb() {
                self.state = NodeState::Running;
                break;
            }
        }
        Ok(())
    }
    async fn ibd_maybe_request_headers(&mut self) -> Result<(), BlockchainError> {
        if (self.last_headers_request + Duration::from_secs(10)) < Instant::now() {
            info!("Asking for headers");
            let locator = self
                .chain
                .get_block_locator()
                .expect("Could not create locator");
            self.send_to_random_peer(NodeRequest::GetHeaders(locator))
                .await?;
            self.last_headers_request = Instant::now();
        }
        Ok(())
    }
    /// This function checks how many time has passed since our last tip update, if it's
    /// been more than 15 minutes, try to update it.
    async fn check_for_stale_tip(&mut self) {
        if (self.last_tip_update + Duration::from_secs(15 * 60)) < Instant::now() {
            warn!("Potential stale tip detected, trying extra peers");
            self.create_connection().await;
            try_and_log!(
                self.send_to_random_peer(NodeRequest::GetHeaders(
                    self.chain.get_block_locator().unwrap(),
                ))
                .await
            );
        }
    }
    async fn maybe_open_connection(&mut self) {
        if self.last_connection.elapsed() > Duration::from_secs(10)
            && self.peers.len() < MAX_OUTGOING_PEERS
        {
            self.create_connection().await;
        }
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
        self.send_to_random_peer(NodeRequest::GetBlock(next_blocks))
            .await?;
        Ok(())
    }
    async fn create_connection(&mut self) {
        if let Some((peer_id, address)) = self
            .address_man
            .get_address_to_connect(ServiceFlags::NETWORK | ServiceFlags::WITNESS)
        {
            let (requests_tx, requests_rx) = bounded(1024);
            let peer = Peer::create_outbound_connection(
                self.peer_id_count,
                (address.get_net_address(), address.get_port()),
                self.network,
                self.node_tx.clone(),
                requests_rx,
                peer_id,
            )
            .await;
            if let Ok(peer) = peer {
                spawn(peer.read_loop());
                self.peers
                    .push((PeerStatus::Awaiting, self.peer_id_count, requests_tx));
                self.peer_id_count += 1;
                return;
            } else {
                error!(
                    "Error connecting to peer {:?}: {:?}",
                    address.get_net_address(),
                    peer.unwrap_err()
                );
            }
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
pub(crate) use try_and_log;
