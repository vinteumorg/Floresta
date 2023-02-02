#![allow(unused)]
use self::peer_utils::make_pong;
use super::{
    mempool::Mempool,
    node::{NodeNotification, NodeRequest},
    stream_reader::StreamReader,
};
use crate::blockchain::{
    chain_state::ChainState, chainstore::KvChainStore, error::BlockchainError, udata::LeafData,
    BlockchainInterface, BlockchainProviderInterface,
};
use async_std::{
    channel::{Receiver, Sender},
    io::{BufReader, Read, ReadExt, WriteExt},
    net::{TcpStream, ToSocketAddrs},
    stream::{Stream, StreamExt},
    sync::RwLock,
};
use bitcoin::{
    consensus::{deserialize, deserialize_partial, serialize, Decodable},
    hashes::{hex::FromHex, sha256, Hash},
    network::{
        address::AddrV2,
        constants::ServiceFlags,
        message::{NetworkMessage, RawNetworkMessage, MAX_MSG_SIZE},
        message_blockdata::Inventory,
        message_network::VersionMessage,
    },
    Block, BlockHash, BlockHeader, Network, OutPoint, Txid,
};
use btcd_rpc::{
    client::{BTCDClient, BtcdRpc},
    json_types::blockchain::GetUtreexoProofResult,
};
use clap::builder::TypedValueParser;
use futures::select;
use futures::FutureExt;
use log::warn;
use rustreexo::accumulator::proof::Proof;
use std::{collections::HashMap, fmt::Debug, time::Duration};
use std::{sync::Arc, time::Instant};
#[derive(PartialEq)]
enum State {
    None,
    VersionSent,
    RemoteVerack,
    VersionReceived,
    Connected,
}
enum InflightRequests {
    Blocks((usize, usize)),
    Transaction(Txid),
    Address,
    Headers,
}

pub struct Peer {
    stream: TcpStream,
    network: Network,
    chain: Arc<ChainState<KvChainStore>>,
    mempool: Arc<RwLock<Mempool>>,
    blocks_only: bool,
    services: ServiceFlags,
    user_agent: String,
    current_best_block: i32,
    last_ping: Instant,
    id: u32,
    inflight: Vec<(Instant, InflightRequests)>,
    node_tx: Sender<NodeNotification>,
    state: State,
    send_headers: bool,
    node_requests: Receiver<NodeRequest>,
}
impl Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)?;
        write!(f, "{:?}", self.stream.peer_addr())?;
        Ok(())
    }
}
impl Peer {
    pub async fn read_loop(mut self) -> Result<(), BlockchainError> {
        let err = self.peer_loop_inner().await;
        self.send_to_node(PeerMessages::Disconnected).await;
        Ok(())
    }
    async fn peer_loop_inner(&mut self) -> Result<(), BlockchainError> {
        let read_stream = BufReader::new(self.stream.clone());
        let mut stream: StreamReader<_, RawNetworkMessage> =
            StreamReader::new(read_stream, self.network.magic());
        loop {
            select! {
                request = self.node_requests.recv().fuse() => {
                    if let Ok(request) = request {
                        self.handle_node_request(request).await;
                    }
                }
                peer_request = async_std::future::timeout(Duration::from_secs(1),  stream.next_message()).fuse() => {
                    if let Ok(peer_request) = peer_request {
                        self.handle_peer_message(peer_request?).await;
                    }
                }
            };
            self.handle_request_timeout();
        }
    }
    pub fn handle_request_timeout(&self) {
        for (time, _) in self.inflight.iter() {
            if *time + Duration::from_secs(5) > Instant::now() {
                self.send_to_node(PeerMessages::RequestTimeout);
            }
        }
    }
    pub async fn handle_node_request(&mut self, request: NodeRequest) {
        match request {
            NodeRequest::GetBlock(block_hashes) => {
                self.inflight.push((
                    Instant::now(),
                    InflightRequests::Blocks((block_hashes.len(), 0)),
                ));
                let mut inv = block_hashes
                    .iter()
                    .map(|block| Inventory::WitnessBlock(*block))
                    .collect();

                self.write(NetworkMessage::GetData(inv)).await;
            }
            NodeRequest::GetHeaders(locator) => {
                self.write(NetworkMessage::GetHeaders(
                    bitcoin::network::message_blockdata::GetHeadersMessage {
                        version: 0,
                        locator_hashes: locator,
                        stop_hash: BlockHash::all_zeros(),
                    },
                ))
                .await;
            }
            NodeRequest::Shutdown => {
                warn!("Disconnecting peer {}", self.id);
                self.stream.shutdown(std::net::Shutdown::Both);
            }
        }
    }
    pub async fn handle_peer_message(&mut self, message: RawNetworkMessage) {
        match message.payload {
            bitcoin::network::message::NetworkMessage::Version(version) => {
                self.handle_version(version).await;
                self.state = State::Connected;
                self.send_to_node(PeerMessages::Ready(Version {
                    user_agent: self.user_agent.clone(),
                    protocol_version: 0,
                    id: self.id,
                    blocks: self.current_best_block.unsigned_abs(),
                }))
                .await;
            }
            bitcoin::network::message::NetworkMessage::Verack => {
                self.state = State::RemoteVerack;
            }
            bitcoin::network::message::NetworkMessage::Addr(_) => {}
            bitcoin::network::message::NetworkMessage::Inv(inv) => {
                for inv_entry in inv {
                    match inv_entry {
                        bitcoin::network::message_blockdata::Inventory::Error => {}
                        bitcoin::network::message_blockdata::Inventory::Transaction(_) => {}
                        bitcoin::network::message_blockdata::Inventory::Block(block_hash) => {
                            self.send_to_node(PeerMessages::NewBlock(block_hash)).await;
                        }
                        bitcoin::network::message_blockdata::Inventory::CompactBlock(_) => {}
                        bitcoin::network::message_blockdata::Inventory::WTx(_) => todo!(),
                        bitcoin::network::message_blockdata::Inventory::WitnessTransaction(_) => {}
                        bitcoin::network::message_blockdata::Inventory::WitnessBlock(_) => {}
                        bitcoin::network::message_blockdata::Inventory::Unknown {
                            inv_type,
                            hash,
                        } => {}
                    }
                }
            }
            bitcoin::network::message::NetworkMessage::GetData(_) => todo!(),
            bitcoin::network::message::NetworkMessage::NotFound(_) => todo!(),
            bitcoin::network::message::NetworkMessage::GetBlocks(_) => todo!(),
            bitcoin::network::message::NetworkMessage::GetHeaders(_) => {
                self.write(NetworkMessage::Headers(vec![])).await;
            }
            bitcoin::network::message::NetworkMessage::MemPool => todo!(),
            bitcoin::network::message::NetworkMessage::Tx(_) => {
                // self.mempool.write().await.accept_to_mempool();
            }
            bitcoin::network::message::NetworkMessage::Block(block) => {
                for (idx, request) in self.inflight.iter_mut().enumerate() {
                    if let (req_time, InflightRequests::Blocks((count, done))) = request {
                        *request = (*req_time, InflightRequests::Blocks((*count, *done + 1)));
                    }
                }
                self.send_to_node(PeerMessages::Block(block)).await;
            }
            bitcoin::network::message::NetworkMessage::Headers(headers) => {
                self.inflight
                    .push((Instant::now(), InflightRequests::Headers));
                self.send_to_node(PeerMessages::Headers(headers)).await;
            }
            bitcoin::network::message::NetworkMessage::SendHeaders => {
                self.send_headers = true;
            }
            bitcoin::network::message::NetworkMessage::GetAddr => {}
            bitcoin::network::message::NetworkMessage::Ping(nonce) => {
                self.handle_ping(nonce).await;
            }
            bitcoin::network::message::NetworkMessage::FeeFilter(_) => {
                self.write(NetworkMessage::FeeFilter(1000)).await;
            }
            _ => {}
        }
    }
}
impl Peer {
    pub async fn write(&self, msg: NetworkMessage) -> Result<(), crate::error::Error> {
        let mut data = &mut RawNetworkMessage {
            magic: self.network.magic(),
            payload: msg,
        };
        let data = serialize(&data);
        (&self.stream).write_all(&data).await?;
        Ok(())
    }

    pub async fn create_outbound_connection<A: ToSocketAddrs>(
        chain: Arc<ChainState<KvChainStore>>,
        id: u32,
        address: A,
        mempool: Arc<RwLock<Mempool>>,
        network: Network,
        node_tx: Sender<NodeNotification>,
        node_requests: Receiver<NodeRequest>,
    ) -> Result<Peer, std::io::Error> {
        let stream = TcpStream::connect(address).await?;

        let mut peer = Peer {
            blocks_only: false,
            chain,
            current_best_block: -1,
            id,
            last_ping: Instant::now(),
            mempool,
            network,
            node_tx,
            services: ServiceFlags::NONE,
            stream,
            user_agent: "".into(),
            state: State::None,
            send_headers: false,
            node_requests,
            inflight: Vec::new(),
        };
        let version = peer_utils::build_version_message();
        // send a version
        peer.write(version).await;
        Ok(peer)
    }
    async fn handle_ping(&mut self, nonce: u64) {
        self.last_ping = Instant::now();
        let pong = make_pong(nonce);
        self.write(pong).await;
    }
    async fn handle_version(&mut self, version: VersionMessage) {
        self.user_agent = version.user_agent;
        self.blocks_only = !version.relay;
        self.current_best_block = version.start_height;
        self.services = version.services;
        let verack = NetworkMessage::Verack;
        self.write(verack).await;
    }
    async fn send_to_node(&self, message: PeerMessages) {
        let message = NodeNotification::FromPeer(self.id, message);
        self.node_tx.send(message).await;
    }
}

pub(super) mod peer_utils {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::{SystemTime, UNIX_EPOCH},
    };

    use bitcoin::{
        network::{
            address, constants,
            message::{self, NetworkMessage},
            message_network,
        },
        secp256k1::Secp256k1,
    };
    pub(super) fn make_pong(nonce: u64) -> NetworkMessage {
        NetworkMessage::Pong(nonce)
    }
    pub(super) fn build_version_message() -> message::NetworkMessage {
        // Building version message, see https://en.bitcoin.it/wiki/Protocol_documentation#version
        let my_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 38332);

        // "bitfield of features to be enabled for this connection"
        let services = constants::ServiceFlags::NETWORK;

        // "standard UNIX timestamp in seconds"
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time error")
            .as_secs();

        // "The network address of the node receiving this message"
        let addr_recv = address::Address::new(&my_address, constants::ServiceFlags::NONE);

        // "The network address of the node emitting this message"
        let addr_from = address::Address::new(&my_address, constants::ServiceFlags::NONE);

        // "Node random nonce, randomly generated every time a version packet is sent. This nonce is used to detect connections to self."
        let nonce: u64 = 1;

        // "User Agent (0x00 if string is 0 bytes long)"
        let user_agent = String::from("rust-example");

        // "The last block received by the emitting node"
        let start_height: i32 = 0;

        // Construct the message
        message::NetworkMessage::Version(message_network::VersionMessage {
            services,
            timestamp: timestamp as i64,
            receiver: addr_recv,
            sender: addr_from,
            nonce,
            user_agent,
            start_height,
            relay: false,
            version: 70014,
        })
    }
}
pub struct Version {
    pub user_agent: String,
    pub protocol_version: u32,
    pub blocks: u32,
    pub id: u32,
}
/// Messages passed from different modules to the main node to process. They should minimal
/// and only if it requires global states, everything else should be handled by the module
/// itself.
pub enum PeerMessages {
    /// A new block just arrived, we should ask for it and update our chain
    NewBlock(BlockHash),
    /// Also a new block, but our connection is a compact blocks one, so we should handle
    /// a compact blocs communication, not a explicit block request
    NewCompactBlock(BlockHash),
    /// We got a full block from our peer, presumptively we asked for it
    Block(Block),
    /// A response to a `getheaders` request
    Headers(Vec<BlockHeader>),
    /// We got some p2p addresses, add this to our local database
    Addr(Vec<AddrV2>),
    /// Peer notify its readiness
    Ready(Version),
    /// Remote peer disconnected
    Disconnected,
    /// A request timed out
    RequestTimeout,
}
