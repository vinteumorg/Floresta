#![allow(unused)]

use self::peer::Peer;
use super::{
    chain_state::ChainState, chainstore::KvChainStore, error::BlockchainError, udata::LeafData,
    BlockchainInterface, BlockchainProviderInterface,
};
use async_std::{
    channel::{self, bounded, Receiver, Sender},
    sync::RwLock,
    task::{sleep, spawn},
};
use bitcoin::{
    consensus::deserialize_partial,
    hashes::{hex::FromHex, sha256},
    Block, BlockHash, BlockHeader, Network, OutPoint,
};
use btcd_rpc::{
    client::{BTCDClient, BTCDConfigs, BtcdRpc},
    json_types::blockchain::GetUtreexoProofResult,
};
use rustreexo::accumulator::proof::Proof;
use std::{
    collections::HashMap,
    net::{SocketAddr, SocketAddrV4},
    process::exit,
    sync::Arc,
    time::Duration,
};

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
    Disconnected
}
/// Sent from node to peers, usually to request something
pub enum NodeRequest {
    /// Get this block's data
    GetBlock(BlockHash),
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
}

impl UtreexoNode {
    pub fn new(
        chain: Arc<ChainState<KvChainStore>>,
        mempool: Arc<RwLock<Mempool>>,
        network: Network,
        rpc: Arc<BTCDClient>,
    ) -> Self {
        let (node_tx, node_rx) = channel::bounded(1024);
        UtreexoNode {
            chain,
            mempool,
            network,
            node_rx,
            node_tx,
            peer_id_count: 0,
            peers: HashMap::new(),
            rpc,
            header_backlog: vec![],
            state: NodeState::DownloadHeaders,
        }
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
            self.state = NodeState::DownloadBlocks;
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
        let peer = self.peers.get(&0).expect("No peers");
        peer.send(NodeRequest::GetHeaders(locator)).await;
    }
    pub async fn run(mut self) {
        let seed_node = "127.0.0.1:38333";
        self.create_connection(seed_node).await;
        loop {
            while let Ok(notification) = self.node_rx.recv().await {
                match notification {
                    NodeNotification::PingTimeout(_) => todo!(),
                    NodeNotification::TryPing(_) => todo!(),
                    NodeNotification::NewBlock(hash) => {
                        let peer = self.peers.get(&0).unwrap();
                        peer.send(NodeRequest::GetBlock(hash)).await;
                    }
                    NodeNotification::NewCompactBlock(hash) => {
                        let peer = self.peers.get(&0).unwrap();
                        peer.send(NodeRequest::GetBlock(hash)).await;
                    }
                    NodeNotification::Block(block) => {
                        self.handle_block(&block);
                    }
                    NodeNotification::Headers(headers) => {
                        self.handle_headers(headers).await;
                    }
                    NodeNotification::Ready => {
                        self.peers
                            .get(&0)
                            .unwrap()
                            .send(NodeRequest::GetHeaders(
                                self.chain.get_block_locator().unwrap(),
                            ))
                            .await;
                    }
                    NodeNotification::Disconnected => {
                        println!("Peer lost");
                        return ;
                    }
                }
            }
        }
    }
    fn handle_block(&self, block: &Block) {
        let (proof, del_hashes, leaf_data) =
            Self::get_proof(&*self.rpc, &block.block_hash().to_string())
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
        self.chain.connect_block(&block, proof, inputs, del_hashes);
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
        } else {
            exit(0);
        }
        self.peer_id_count += 1;
    }
}
