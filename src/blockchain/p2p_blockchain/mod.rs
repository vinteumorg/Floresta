#![allow(unused)]
use self::{block_download::BlockDownload, peer::Peer};
use super::{
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
    Block, BlockHash, BlockHeader, Network, OutPoint,
};
use btcd_rpc::{
    client::{BTCDClient, BtcdRpc},
    json_types::blockchain::GetUtreexoProofResult,
};
use log::info;
use rustreexo::accumulator::proof::Proof;
use std::{collections::HashMap, sync::Arc};

mod block_download;
mod peer;
mod protocol;
mod stream_reader;

/// Messages passed from different modules to the main node to process. They should minimal
/// and only if it requires global states, everything else should be handled by the module
/// itself.
pub enum NodeNotification {
    /// This means our peer timed out, and we should disconnect it
    PingTimeout(u64),
    /// It's been a while since we last ping this peer, so send a ping to make sure they
    /// are still there
    TryPing(u64),
    /// A new block just arrived, we should ask for it and update our chain
    NewBlock(BlockHash),
    /// Also a new block, but our connection is a compact blocks one, so we should handle
    /// a compact blocs communication, not a explicit block request
    NewCompactBlock(BlockHash),
    /// We got a full block from our peer, presumptively we asked for it
    Block(Block),
    /// A response to a `getheaders` request
    Headers(Vec<BlockHeader>),
    /// Peer notify its readiness
    Ready,
    /// Remote peer disconnected
    Disconnected,
}
/// Sent from node to peers, usually to request something
pub enum NodeRequest {
    /// Get this block's data
    GetBlock(Vec<BlockHash>),
    /// Asks peer for headers
    GetHeaders(Vec<BlockHash>),
}
pub struct Mempool;
impl Mempool {
    pub fn accept_to_mempool(&self) {}
}
#[derive(Default)]
enum NodeState {
    #[default]
    DownloadHeaders,
    DownloadBlocks,
    Running,
}
#[allow(unused)]
pub struct UtreexoNode {
    peer_id_count: u32,
    network: Network,
    peers: HashMap<u32, Sender<NodeRequest>>,
    chain: Arc<ChainState<KvChainStore>>,
    mempool: Arc<RwLock<Mempool>>,
    node_rx: Receiver<NodeNotification>,
    node_tx: Sender<NodeNotification>,
    rpc: Arc<BTCDClient>,
    header_backlog: Vec<BlockHeader>,
    state: NodeState,
    download_man: BlockDownload,
}

impl UtreexoNode {
    pub fn new(
        chain: Arc<ChainState<KvChainStore>>,
        mempool: Arc<RwLock<Mempool>>,
        network: Network,
        rpc: Arc<BTCDClient>,
    ) -> Self {
        let (node_tx, node_rx) = channel::bounded(1024);
        let node = UtreexoNode {
            download_man: BlockDownload::new(chain.clone(), rpc.clone(), &Self::handle_block),
            header_backlog: vec![],
            state: NodeState::DownloadHeaders,
            peer_id_count: 0,
            peers: HashMap::new(),
            chain,
            mempool,
            network,
            node_rx,
            node_tx,
            rpc,
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
    pub async fn handle_headers(&mut self, headers: Vec<BlockHeader>) {
        if headers.is_empty() {
            self.ibd_request_blocks().await;
            return;
        }
        println!("Downloading headers at: {}", headers[0].block_hash());
        for header in headers {
            self.chain.accept_header(header);
        }
        let locator = self
            .chain
            .get_block_locator()
            .expect("Could not create locator");
        self.send_to_random_peer((NodeRequest::GetHeaders(locator)))
            .await;
    }
    #[inline]
    pub async fn send_to_random_peer(&self, req: NodeRequest) {
        if self.peers.is_empty() {
            return;
        }
        let idx = rand::random::<u32>() % self.peers.len() as u32;
        let peer = self.peers.get(&idx).expect("Peer should be here");
        peer.send(req).await;
    }
    pub async fn run(mut self) {
        // self.create_connection("45.33.47.11:38333").await;
        self.create_connection("178.128.221.177:38333").await;
        loop {
            while let Ok(notification) = self.node_rx.recv().await {
                match notification {
                    NodeNotification::PingTimeout(_) => todo!(),
                    NodeNotification::TryPing(_) => todo!(),
                    NodeNotification::NewBlock(hash) => {
                        self.send_to_random_peer(NodeRequest::GetBlock(vec![hash]))
                            .await;
                    }
                    NodeNotification::NewCompactBlock(hash) => {
                        self.send_to_random_peer(NodeRequest::GetBlock(vec![hash]))
                            .await;
                    }
                    NodeNotification::Block(block) => {
                        if self.download_man.downloaded(block) {
                            self.ibd_request_blocks().await;
                        }
                    }
                    NodeNotification::Headers(headers) => {
                        self.handle_headers(headers).await;
                    }
                    NodeNotification::Ready => {
                        self.send_to_random_peer(NodeRequest::GetHeaders(
                            self.chain.get_block_locator().unwrap(),
                        ))
                        .await;
                    }
                    NodeNotification::Disconnected => {
                        println!("Peer lost");
                        return;
                    }
                }
            }
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
    async fn ibd_request_blocks(&mut self) {
        if self.chain.get_best_block().unwrap().0 == self.chain.get_validation_index().unwrap() {
            self.chain.toggle_ibd(false);
            info!("Leaving ibd");
            return;
        }
        info!(
            "Downloading blocks at {}",
            self.chain.get_validation_index().unwrap()
        );
        if let Ok(next_blocks) = self.chain.get_next_block() {
            self.download_man.push(next_blocks.clone());
            self.send_to_random_peer(NodeRequest::GetBlock(next_blocks))
                .await;
        }
    }
    async fn create_connection(&mut self, peer: &str) {
        let (requests_tx, requests_rx) = bounded(1024);
        let peer = Peer::create_outbound_connection(
            self.chain.clone(),
            self.peer_id_count,
            peer,
            self.mempool.clone(),
            self.network,
            self.node_tx.clone(),
            requests_rx,
        )
        .await;

        if let Ok(peer) = peer {
            spawn(peer.read_loop());
            self.peers.insert(self.peer_id_count, requests_tx);
        }
        self.peer_id_count += 1;
    }
}
