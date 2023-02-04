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
    chain_state::ChainState, chainstore::KvChainStore, error::BlockchainError, udata::LeafData,
    BlockchainInterface, BlockchainProviderInterface,
};
use async_std::{
    channel::{self, bounded, Receiver, Sender},
    sync::RwLock,
    task::spawn,
};
use bitcoin::{
    consensus::deserialize_partial,
    hashes::{hex::FromHex, sha256},
    network::{address::AddrV2, constants::ServiceFlags},
    Block, BlockHash, BlockHeader, Network, OutPoint,
};
use btcd_rpc::{
    client::{BTCDClient, BtcdRpc},
    json_types::blockchain::GetUtreexoProofResult,
};
use log::{error, info, warn};
use rustreexo::accumulator::proof::Proof;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::{Duration, Instant},
};

/// Max number of simultaneous connections we initiates we are willing to hold
const MAX_OUTGOING_PEERS: usize = 10;

pub enum NodeNotification {
    FromPeer(u32, PeerMessages),
    FromPingManager,
    FromBlockDownloader(BlockDownloaderMessages),
}
#[derive(Debug, Clone, PartialEq)]
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
#[allow(unused)]
pub struct UtreexoNode {
    peer_id_count: u32,
    network: Network,
    peers: Vec<(PeerStatus, u32, Sender<NodeRequest>)>,
    chain: Arc<ChainState<KvChainStore>>,
    mempool: Arc<RwLock<Mempool>>,
    node_rx: Receiver<NodeNotification>,
    node_tx: Sender<NodeNotification>,
    rpc: Arc<BTCDClient>,
    header_backlog: Vec<BlockHeader>,
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
        rpc: Arc<BTCDClient>,
    ) -> Self {
        let (node_tx, node_rx) = channel::unbounded();
        let node = UtreexoNode {
            download_man: BlockDownload::new(
                chain.clone(),
                rpc.clone(),
                node_tx.clone(),
                &Self::handle_block,
            ),
            header_backlog: vec![],
            state: NodeState::default(),
            peer_id_count: 0,
            peers: Vec::new(),
            chain,
            mempool,
            network,
            node_rx,
            node_tx,
            rpc,
            address_man: AddressMan::default(),
        };
        node
    }
    pub fn get_proof<T: BtcdRpc>(
        rpc: &T,
        hash: &String,
    ) -> Result<(Proof, Vec<sha256::Hash>, Vec<LeafData>), BlockchainError> {
        let proof = rpc.getutreexoproof(hash.to_string(), true)?.get_verbose();
        Self::process_proof(proof)
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
        proof: GetUtreexoProofResult,
    ) -> Result<(Proof, Vec<sha256::Hash>, Vec<LeafData>), BlockchainError> {
        let preimages: Vec<_> = proof
            .target_preimages
            .iter()
            .map(|preimage| {
                deserialize_partial::<LeafData>(&Vec::from_hex(preimage).unwrap())
                    .unwrap()
                    .0
            })
            .collect();

        let proof_hashes: Vec<_> = proof
            .proofhashes
            .iter()
            .map(|hash| sha256::Hash::from_hex(hash).unwrap())
            .collect();

        let targets = proof.prooftargets;
        let targethashes: Vec<_> = proof
            .targethashes
            .iter()
            .map(|hash| sha256::Hash::from_hex(hash).unwrap())
            .collect();
        let proof = Proof::new(targets, proof_hashes);

        Ok((proof, targethashes, preimages))
    }
    pub async fn handle_headers(
        &mut self,
        headers: Vec<BlockHeader>,
    ) -> Result<(), BlockchainError> {
        if headers.is_empty() {
            self.download_man.get_more_blocks().await?;
            return Ok(());
        }
        info!("Downloading headers at: {}", headers[0].block_hash());
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
                PeerMessages::NewCompactBlock(hash) => {
                    self.send_to_random_peer(NodeRequest::GetBlock(vec![hash]))
                        .await
                }
                PeerMessages::Block(block) => {
                    self.download_man.downloaded(block).await;
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
                    }
                    if let NodeState::WaitingPeer = self.state {
                        info!("Requesting headers");
                        self.state = NodeState::DownloadHeaders;
                    }
                    self.send_to_random_peer(NodeRequest::GetHeaders(
                        self.chain.get_block_locator().unwrap(),
                    ))
                    .await?;
                    Ok(())
                }
                PeerMessages::Disconnected => {
                    warn!("Peer lost id={peer}");
                    let peer = self.peers.iter().position(|(_, id, _)| peer == *id);
                    if let Some(peer) = peer {
                        self.peers.remove(peer);
                    }
                    Ok(())
                }
                PeerMessages::RequestTimeout => {
                    if let Some((_, id, peer)) = self.peers.get(peer as usize) {
                        warn!("Peer {id} timed out request. Disconnecting");
                        peer.send(NodeRequest::Shutdown).await?;
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
            NodeNotification::FromPingManager => todo!(),
            NodeNotification::FromBlockDownloader(blocks) => match blocks {
                BlockDownloaderMessages::AskForBlocks(headers) => {
                    self.ibd_request_blocks(headers).await?;
                    Ok(())
                }
            },
        }
    }

    pub async fn run(mut self) {
        self.start_addr_man();
        self.create_connection().await;

        loop {
            while let Ok(notification) =
                async_std::future::timeout(Duration::from_secs(1), self.node_rx.recv()).await
            {
                if let Ok(notification) = notification {
                    let _ = self.handle_notification(notification).await;
                }
            }
            self.maybe_open_connection().await;
            self.download_man.handle_timeout().await;
        }
    }
    async fn maybe_open_connection(&mut self) {
        if self.peers.len() < MAX_OUTGOING_PEERS {
            self.create_connection().await;
        }
    }
    fn handle_block(chain: &ChainState<KvChainStore>, rpc: &Arc<BTCDClient>, block: Block) {
        let (proof, del_hashes, leaf_data) =
            Self::get_proof(&**rpc, &block.block_hash().to_string())
                .expect("Could not fetch proof");
        let mut inputs = HashMap::new();
        for tx in block.txdata.iter() {
            for (vout, out) in tx.output.iter().enumerate() {
                inputs.insert(
                    OutPoint {
                        txid: tx.txid(),
                        vout: vout as u32,
                    },
                    out.clone(),
                );
            }
        }
        for leaf in leaf_data {
            inputs.insert(leaf.prevout, leaf.utxo);
        }
        chain
            .connect_block(&block, proof, inputs, del_hashes)
            .unwrap();
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
            .await
    }
    async fn create_connection(&mut self) {
        if let Some(address) = self
            .address_man
            .get_address_to_connect(ServiceFlags::NETWORK | ServiceFlags::WITNESS)
        {
            let (requests_tx, requests_rx) = bounded(1024);
            let peer = Peer::create_outbound_connection(
                self.chain.clone(),
                self.peer_id_count,
                (address.get_net_address(), address.get_port()),
                self.mempool.clone(),
                self.network,
                self.node_tx.clone(),
                requests_rx,
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
