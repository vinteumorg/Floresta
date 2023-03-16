use self::peer_utils::make_pong;
use super::{
    node::{NodeNotification, NodeRequest},
    stream_reader::StreamReader,
};
use crate::blockchain::error::BlockchainError;
use async_std::{
    channel::{unbounded, Receiver, Sender},
    io::{BufReader, WriteExt},
    net::{TcpStream, ToSocketAddrs},
    task::spawn,
};
use bitcoin::{
    consensus::serialize,
    hashes::Hash,
    network::{
        address::AddrV2Message,
        constants::ServiceFlags,
        message::{NetworkMessage, RawNetworkMessage},
        message_blockdata::Inventory,
        message_network::VersionMessage,
        utreexo::UtreexoBlock,
    },
    BlockHash, BlockHeader, Network,
};
use futures::FutureExt;
use log::debug;
use std::{
    fmt::Debug,
    time::{Duration, Instant},
};

#[derive(PartialEq)]
enum State {
    None,
    RemoteVerack,
    Connected,
}
enum InflightRequests {
    Blocks((usize, usize)),
    Headers,
}

pub struct Peer {
    stream: TcpStream,
    network: Network,
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
    address_id: usize,
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
        debug!("{err:?}");
        self.send_to_node(PeerMessages::Disconnected(self.address_id))
            .await;
        Ok(())
    }
    async fn peer_loop_inner(&mut self) -> Result<(), BlockchainError> {
        // send a version
        let version = peer_utils::build_version_message();
        self.write(version).await?;

        let read_stream = BufReader::new(self.stream.clone());
        let (tx, rx) = unbounded();
        let stream: StreamReader<_, RawNetworkMessage> =
            StreamReader::new(read_stream, self.network.magic(), tx);
        let _ = spawn(stream.read_loop());
        loop {
            futures::select! {
                request = self.node_requests.recv().fuse() => {
                    if let Ok(request) = request {
                        self.handle_node_request(request).await?;
                    }
                }
                peer_request = async_std::future::timeout(Duration::from_secs(1), rx.recv()).fuse() => {
                    if let Ok(Ok(peer_request)) = peer_request {
                        self.handle_peer_message(peer_request?).await?;
                    }
                }
            };
        }
    }
    pub async fn handle_node_request(
        &mut self,
        request: NodeRequest,
    ) -> Result<(), BlockchainError> {
        match request {
            NodeRequest::GetBlock(block_hashes) => {
                self.inflight.push((
                    Instant::now(),
                    InflightRequests::Blocks((block_hashes.len(), 0)),
                ));
                let inv = block_hashes
                    .iter()
                    .map(|block| Inventory::UtreexoWitnessBlock(*block))
                    .collect();

                let _ = self.write(NetworkMessage::GetData(inv)).await;
            }
            NodeRequest::GetHeaders(locator) => {
                let _ = self
                    .write(NetworkMessage::GetHeaders(
                        bitcoin::network::message_blockdata::GetHeadersMessage {
                            version: 0,
                            locator_hashes: locator,
                            stop_hash: BlockHash::all_zeros(),
                        },
                    ))
                    .await;
            }
            NodeRequest::Shutdown => {
                let _ = self.stream.shutdown(std::net::Shutdown::Both);
            }
            NodeRequest::GetAddresses => {
                self.write(NetworkMessage::GetAddr).await?;
            }
        }
        Ok(())
    }
    pub async fn handle_peer_message(
        &mut self,
        message: RawNetworkMessage,
    ) -> Result<(), BlockchainError> {
        match message.payload {
            bitcoin::network::message::NetworkMessage::Version(version) => {
                self.handle_version(version).await?;
                self.state = State::Connected;
                self.send_to_node(PeerMessages::Ready(Version {
                    user_agent: self.user_agent.clone(),
                    protocol_version: 0,
                    id: self.id,
                    blocks: self.current_best_block.unsigned_abs(),
                    address_id: self.address_id,
                    services: self.services,
                }))
                .await;
            }
            bitcoin::network::message::NetworkMessage::Verack => {
                self.state = State::RemoteVerack;
            }
            bitcoin::network::message::NetworkMessage::Inv(inv) => {
                for inv_entry in inv {
                    match inv_entry {
                        bitcoin::network::message_blockdata::Inventory::Error => {}
                        bitcoin::network::message_blockdata::Inventory::Transaction(_) => {}
                        bitcoin::network::message_blockdata::Inventory::Block(block_hash)
                        | bitcoin::network::message_blockdata::Inventory::WitnessBlock(
                            block_hash,
                        )
                        | bitcoin::network::message_blockdata::Inventory::CompactBlock(
                            block_hash,
                        ) => {
                            self.send_to_node(PeerMessages::NewBlock(block_hash)).await;
                        }
                        bitcoin::network::message_blockdata::Inventory::WTx(_) => todo!(),
                        bitcoin::network::message_blockdata::Inventory::WitnessTransaction(_) => {}
                        _ => {}
                    }
                }
            }
            bitcoin::network::message::NetworkMessage::GetHeaders(_) => {
                self.write(NetworkMessage::Headers(vec![])).await?;
            }
            bitcoin::network::message::NetworkMessage::Block(block) => {
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
            bitcoin::network::message::NetworkMessage::Ping(nonce) => {
                self.handle_ping(nonce).await?;
            }
            bitcoin::network::message::NetworkMessage::FeeFilter(_) => {
                self.write(NetworkMessage::FeeFilter(1000)).await?;
            }
            bitcoin::network::message::NetworkMessage::AddrV2(addresses) => {
                self.send_to_node(PeerMessages::Addr(addresses)).await;
            }
            bitcoin::network::message::NetworkMessage::GetBlocks(_) => {
                self.write(NetworkMessage::Inv(vec![])).await?;
            }
            _ => {}
        }
        Ok(())
    }
}
impl Peer {
    pub async fn write(&self, msg: NetworkMessage) -> Result<(), BlockchainError> {
        let data = &mut RawNetworkMessage {
            magic: self.network.magic(),
            payload: msg,
        };
        let data = serialize(&data);
        (&self.stream).write_all(&data).await?;
        Ok(())
    }

    pub async fn create_outbound_connection<A: ToSocketAddrs>(
        id: u32,
        address: A,
        network: Network,
        node_tx: Sender<NodeNotification>,
        node_requests: Receiver<NodeRequest>,
        address_id: usize,
    ) {
        let stream = TcpStream::connect(address).await;
        if stream.is_err() {
            let _ = node_tx
                .send(NodeNotification::FromPeer(
                    id,
                    PeerMessages::Disconnected(id as usize),
                ))
                .await;
            return;
        }
        let peer = Peer {
            address_id,
            blocks_only: false,
            current_best_block: -1,
            id,
            last_ping: Instant::now(),
            network,
            node_tx,
            services: ServiceFlags::NONE,
            stream: stream.unwrap(),
            user_agent: "".into(),
            state: State::None,
            send_headers: false,
            node_requests,
            inflight: Vec::new(),
        };
        spawn(peer.read_loop());
    }
    async fn handle_ping(&mut self, nonce: u64) -> Result<(), BlockchainError> {
        self.last_ping = Instant::now();
        let pong = make_pong(nonce);
        self.write(pong).await
    }
    async fn handle_version(&mut self, version: VersionMessage) -> Result<(), BlockchainError> {
        self.user_agent = version.user_agent;
        self.blocks_only = !version.relay;
        self.current_best_block = version.start_height;
        self.services = version.services;
        let verack = NetworkMessage::Verack;
        self.write(verack).await
    }
    async fn send_to_node(&self, message: PeerMessages) {
        let message = NodeNotification::FromPeer(self.id, message);
        let _ = self.node_tx.send(message).await;
    }
}

pub(super) mod peer_utils {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::{SystemTime, UNIX_EPOCH},
    };

    use bitcoin::network::{
        address, constants,
        message::{self, NetworkMessage},
        message_network,
    };
    pub(super) fn make_pong(nonce: u64) -> NetworkMessage {
        NetworkMessage::Pong(nonce)
    }
    pub(super) fn build_version_message() -> message::NetworkMessage {
        use bitcoin::network::constants::ServiceFlags;
        // Building version message, see https://en.bitcoin.it/wiki/Protocol_documentation#version
        let my_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 38332);

        // "bitfield of features to be enabled for this connection"
        let services = ServiceFlags::NETWORK | ServiceFlags::NODE_UTREEXO | ServiceFlags::WITNESS;

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
        let user_agent = String::from("/rust-bitcoin:0.29.3/Floresta:0.2.1");

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
#[derive(Debug)]
pub struct Version {
    pub user_agent: String,
    pub protocol_version: u32,
    pub blocks: u32,
    pub id: u32,
    pub address_id: usize,
    pub services: ServiceFlags,
}
/// Messages passed from different modules to the main node to process. They should minimal
/// and only if it requires global states, everything else should be handled by the module
/// itself.
#[derive(Debug)]
pub enum PeerMessages {
    /// A new block just arrived, we should ask for it and update our chain
    NewBlock(BlockHash),
    /// We got a full block from our peer, presumptively we asked for it
    Block(UtreexoBlock),
    /// A response to a `getheaders` request
    Headers(Vec<BlockHeader>),
    /// We got some p2p addresses, add this to our local database
    Addr(Vec<AddrV2Message>),
    /// Peer notify its readiness
    Ready(Version),
    /// Remote peer disconnected
    Disconnected(usize),
}
