use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::Read;
use std::str::FromStr;
use std::time::Instant;

use bitcoin::block::Header;
use bitcoin::consensus::deserialize_partial;
use bitcoin::consensus::Decodable;
use bitcoin::hex::FromHex;
use bitcoin::p2p::ServiceFlags;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::Network;
use floresta_common::bhash;
use floresta_common::service_flags;
use floresta_common::service_flags::UTREEXO;
use serde::Deserialize;
use serde::Serialize;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task;
use zstd;

use crate::node::LocalPeerView;
use crate::node::NodeNotification;
use crate::node::NodeRequest;
use crate::node::PeerStatus;
use crate::p2p_wire::block_proof::UtreexoProof;
use crate::p2p_wire::node::ConnectionKind;
use crate::p2p_wire::peer::PeerMessages;
use crate::p2p_wire::peer::Version;
use crate::p2p_wire::transport::TransportProtocol;
use crate::UtreexoNodeConfig;

/// A list of headers, used to represent the collection of headers.
pub type HeaderList = Vec<Header>;

/// A map that associates block hashes with their corresponding `UtreexoBlock` objects.
/// This is useful for efficiently looking up blocks by their hash.
pub type BlockHashMap = HashMap<BlockHash, Block>;

/// A map of block hashes to raw block data (represented as bytes vector).
pub type BlockDataMap = HashMap<BlockHash, Vec<u8>>;

/// A collection of essential data related to blocks and headers.
pub struct Essentials {
    pub headers: HeaderList,
    pub blocks: BlockHashMap,
    pub invalid_block: Block,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UtreexoRoots {
    roots: Option<Vec<String>>,
    numleaves: usize,
}

#[derive(Deserialize, Debug, Clone)]
struct BlockFile {
    block: String,
}

#[derive(Debug)]
pub struct TestPeer {
    _headers: Vec<Header>,
    blocks: HashMap<BlockHash, Block>,
    _filters: HashMap<BlockHash, Vec<u8>>,
    node_tx: UnboundedSender<NodeNotification>,
    node_rx: UnboundedReceiver<NodeRequest>,
    peer_id: u32,
}

impl TestPeer {
    pub fn new(
        node_tx: UnboundedSender<NodeNotification>,
        headers: Vec<Header>,
        blocks: HashMap<BlockHash, Block>,
        filters: HashMap<BlockHash, Vec<u8>>,
        node_rx: UnboundedReceiver<NodeRequest>,
        peer_id: u32,
    ) -> Self {
        TestPeer {
            _headers: headers,
            blocks,
            _filters: filters,
            node_tx,
            node_rx,
            peer_id,
        }
    }

    pub async fn run(&mut self) {
        let version = Version {
            user_agent: "node_test".to_string(),
            protocol_version: 0,
            blocks: rand::random::<u32>() % 23,
            id: self.peer_id,
            address_id: rand::random::<usize>(),
            services: ServiceFlags::NETWORK
                | service_flags::UTREEXO.into()
                | ServiceFlags::WITNESS
                | ServiceFlags::COMPACT_FILTERS
                | ServiceFlags::from(1 << 25),
            kind: ConnectionKind::OutboundFullRelay(UTREEXO.into()),
            transport_protocol: TransportProtocol::V2,
        };

        self.node_tx
            .send(NodeNotification::FromPeer(
                self.peer_id,
                PeerMessages::Ready(version),
            ))
            .unwrap();

        loop {
            let req = self.node_rx.recv().await.unwrap();

            match req {
                NodeRequest::GetBlock(hashes) => {
                    for hash in hashes {
                        let block = self.blocks.get(&hash).unwrap().clone();
                        self.node_tx
                            .send(NodeNotification::FromPeer(
                                self.peer_id,
                                PeerMessages::Block(block),
                            ))
                            .unwrap();
                    }
                }
                NodeRequest::Shutdown => {
                    break;
                }
                NodeRequest::GetBlockProof((block_hash, _, _)) => {
                    let proof = UtreexoProof {
                        block_hash,
                        leaf_data: vec![],
                        targets: vec![],
                        proof_hashes: vec![],
                    };
                    self.node_tx
                        .send(NodeNotification::FromPeer(
                            self.peer_id,
                            PeerMessages::UtreexoProof(proof),
                        ))
                        .unwrap();
                }
                _ => {}
            }
        }

        self.node_tx
            .send(NodeNotification::FromPeer(
                self.peer_id,
                PeerMessages::Disconnected(self.peer_id as usize),
            ))
            .unwrap();
    }
}

pub fn create_peer(
    headers: Vec<Header>,
    blocks: HashMap<BlockHash, Block>,
    filters: HashMap<BlockHash, Vec<u8>>,
    node_sender: UnboundedSender<NodeNotification>,
    sender: UnboundedSender<NodeRequest>,
    node_rcv: UnboundedReceiver<NodeRequest>,
    peer_id: u32,
) -> LocalPeerView {
    let mut peer = TestPeer::new(node_sender, headers, blocks, filters, node_rcv, peer_id);
    task::spawn(async move {
        peer.run().await;
    });

    LocalPeerView {
        address: "127.0.0.1".parse().unwrap(),
        services: service_flags::UTREEXO.into(),
        user_agent: "/utreexo:0.1.0/".to_string(),
        height: 0,
        state: PeerStatus::Ready,
        channel: sender,
        port: 8333,
        kind: ConnectionKind::OutboundFullRelay(UTREEXO.into()),
        banscore: 0,
        address_id: 0,
        _last_message: Instant::now(),
        transport_protocol: TransportProtocol::V2,
    }
}

pub fn get_node_config(
    datadir: String,
    network: Network,
    pow_fraud_proofs: bool,
) -> UtreexoNodeConfig {
    UtreexoNodeConfig {
        disable_dns_seeds: false,
        network,
        pow_fraud_proofs,
        compact_filters: false,
        fixed_peer: None,
        max_banscore: 100,
        max_outbound: 8,
        max_inflight: 10,
        datadir,
        proxy: None,
        assume_utreexo: None,
        backfill: false,
        filter_start_height: None,
        user_agent: "node_test".to_string(),
        allow_v1_fallback: true,
    }
}

pub fn serialize(root: UtreexoRoots) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&(root.numleaves as u64).to_le_bytes());

    for root_hash in root.roots.unwrap() {
        let bytes = Vec::from_hex(&root_hash).unwrap();
        buffer.extend_from_slice(&bytes);
    }

    buffer
}

pub fn get_test_headers() -> Vec<Header> {
    let mut headers: Vec<Header> = Vec::new();

    let file = include_bytes!("../../../../floresta-chain/testdata/signet_headers.zst");
    let uncompressed: Vec<u8> = zstd::decode_all(std::io::Cursor::new(file)).unwrap();
    let mut buffer = uncompressed.as_slice();

    while let Ok(header) = Header::consensus_decode(&mut buffer) {
        headers.push(header);
    }

    headers
}

pub fn get_test_blocks() -> io::Result<HashMap<BlockHash, Block>> {
    let dir = "./src/p2p_wire/tests/test_data/blocks.json";
    let mut contents = String::new();
    File::open(dir)?.read_to_string(&mut contents)?;

    let blocks: Vec<BlockFile> = serde_json::from_str(&contents).unwrap();
    let mut u_blocks = HashMap::new();

    for block_str in blocks {
        let ser_block = Vec::from_hex(&block_str.block).unwrap();
        let block: Block = deserialize_partial(&ser_block).unwrap().0;
        u_blocks.insert(block.block_hash(), block);
    }

    Ok(u_blocks)
}

pub fn get_test_filters() -> io::Result<HashMap<BlockHash, Vec<u8>>> {
    let mut contents = String::new();
    File::open("./src/p2p_wire/tests/test_data/roots.json")
        .unwrap()
        .read_to_string(&mut contents)
        .unwrap();
    let roots: Vec<UtreexoRoots> = serde_json::from_str(&contents).unwrap();
    let headers = get_test_headers();
    let mut filters = HashMap::new();

    for root in roots.into_iter() {
        let buffer = serialize(root.clone());

        // Insert the serialised Utreexo-Root along with its corresponding BlockHash in the HashMap
        filters.insert(headers[root.numleaves].block_hash(), buffer);
    }
    Ok(filters)
}

pub fn generate_invalid_block() -> Block {
    let invalid_block_str = "00000020daf3b60d374b19476461f97540498dcfa2eb7016238ec6b1d022f82fb60100007a7ae65b53cb988c2ec92d2384996713821d5645ffe61c9acea60da75cd5edfa1a944d5fae77031e9dbb050001010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025751feffffff0200f2052a01000000160014ef2dceae02e35f8137de76768ae3345d99ca68860000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa2490047304402202b3f946d6447f9bf17d00f3696cede7ee70b785495e5498274ee682a493befd5022045fc0bcf9331073168b5d35507175f9f374a8eba2336873885d12aada67ea5f60100012000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    let block = Vec::from_hex(invalid_block_str).unwrap();
    let block: Block = deserialize_partial(&block).unwrap().0;

    block
}

pub fn get_essentials() -> Essentials {
    let headers = get_test_headers();
    let blocks = get_test_blocks().unwrap();
    let _filters = get_test_filters().unwrap();
    let invalid_block = generate_invalid_block();

    // BlockHash of chain_tip: 0000035f0e5513b26bba7cead874fdf06241a934e4bc4cf7a0381c60e4cdd2bb (119)
    let _tip_hash = bhash!("0000035f0e5513b26bba7cead874fdf06241a934e4bc4cf7a0381c60e4cdd2bb");

    Essentials {
        headers,
        blocks,
        invalid_block,
    }
}
