use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use async_std::channel::unbounded;
use async_std::channel::Receiver;
use async_std::channel::Sender;
use async_std::io::BufReader;
use async_std::net::TcpStream;
use async_std::net::ToSocketAddrs;
use async_std::sync::RwLock;
use async_std::task::spawn;
use bitcoin::block::Header as BlockHeader;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::p2p::address::AddrV2Message;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message::RawNetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::utreexo::UtreexoBlock;
use bitcoin::p2p::ServiceFlags;
use bitcoin::BlockHash;
use bitcoin::Network;
use bitcoin::Transaction;
use futures::AsyncRead;
use futures::AsyncWrite;
use futures::AsyncWriteExt;
use futures::FutureExt;
use log::error;
use log::warn;
use thiserror::Error;

use self::peer_utils::make_pong;
use super::mempool::Mempool;
use super::node::NodeNotification;
use super::node::NodeRequest;
use super::stream_reader::StreamReader;

/// If we send a ping, and our peer takes more than PING_TIMEOUT to
/// reply, disconnect.
const PING_TIMEOUT: u64 = 30;
/// If the last message we've got was more than XX, send out a ping
const SEND_PING_TIMEOUT: u64 = 60;

#[derive(Debug, PartialEq)]
enum State {
    None,
    SentVersion(Instant),
    SentVerack,
    Connected,
}
/// A trait defining how the transport we use should behave. Transport is anything
/// that allows to read/write from/into. Like a TcpStream or a Socks5 proxy
pub trait Transport:
    AsyncRead + AsyncWrite + Unpin + Clone + Sync + Send + AsyncWriteExt + 'static
{
    /// Asks the stream to shutdown, the final part of the disconnection process
    fn shutdown(&mut self) -> Result<()>;
}

impl Transport for TcpStream {
    fn shutdown(&mut self) -> Result<()> {
        Ok(TcpStream::shutdown(self, std::net::Shutdown::Both)?)
    }
}

pub struct Peer<T: Transport> {
    stream: T,
    mempool: Arc<RwLock<Mempool>>,
    network: Network,
    blocks_only: bool,
    services: ServiceFlags,
    user_agent: String,
    messages: u64,
    start_time: Instant,
    last_message: Instant,
    current_best_block: i32,
    last_ping: Option<Instant>,
    id: u32,
    node_tx: Sender<NodeNotification>,
    state: State,
    send_headers: bool,
    node_requests: Receiver<NodeRequest>,
    address_id: usize,
    feeler: bool,
    wants_addrv2: bool,
    shutdown: bool,
}
#[derive(Debug, Error)]
pub enum PeerError {
    #[error("Error while sending to peer")]
    Send,
    #[error("Error while reading from peer")]
    Read(#[from] std::io::Error),
    #[error("Error while parsing message")]
    Parse(#[from] bitcoin::consensus::encode::Error),
    #[error("Peer sent us a message that we aren't expecting")]
    UnexpectedMessage,
    #[error("Peer sent us a message that is too big")]
    MessageTooBig,
    #[error("Peer sent us a message with the wrong magic bits")]
    MagicBitsMismatch,
    #[error("Peer sent us too many message in a short period of time")]
    TooManyMessages,
    #[error("Peer timed a ping out")]
    Timeout,
}
impl Debug for Peer<TcpStream> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)?;
        write!(f, "{:?}", self.stream.peer_addr())?;
        Ok(())
    }
}

type Result<T> = std::result::Result<T, PeerError>;

impl<T: Transport> Peer<T> {
    pub async fn read_loop(mut self) -> Result<()> {
        let err = self.peer_loop_inner().await;

        if let Err(err) = err {
            warn!("Peer {} connection loop closed: {err:?}", self.id);
        }

        self.send_to_node(PeerMessages::Disconnected(self.address_id))
            .await;
        Ok(())
    }
    async fn peer_loop_inner(&mut self) -> Result<()> {
        // send a version
        let version = peer_utils::build_version_message();
        self.write(version).await?;
        self.state = State::SentVersion(Instant::now());
        let read_stream = BufReader::new(self.stream.clone());
        let (tx, rx) = unbounded();
        let magic = self.network.magic();
        let stream: StreamReader<_, RawNetworkMessage> = StreamReader::new(read_stream, magic, tx);
        spawn(stream.read_loop());
        loop {
            futures::select! {
                request = self.node_requests.recv().fuse() => {
                    if let Ok(request) = request {
                        self.handle_node_request(request).await?;
                    }
                }
                peer_request = async_std::future::timeout(Duration::from_secs(10), rx.recv()).fuse() => {
                    if let Ok(Ok(peer_request)) = peer_request {
                        self.handle_peer_message(peer_request?).await?;
                    }
                }
            };
            if self.shutdown {
                return Ok(());
            }
            // If we send a ping and our peer doesn't respond in time, disconnect
            if let Some(when) = self.last_ping {
                if when.elapsed().as_secs() > PING_TIMEOUT {
                    return Err(PeerError::Timeout);
                }
            }

            // Send a ping to check if this peer is still good
            let last_message = self.last_message.elapsed().as_secs();
            if last_message > SEND_PING_TIMEOUT {
                let nonce = rand::random();
                self.last_ping = Some(Instant::now());
                self.write(NetworkMessage::Ping(nonce)).await?;
            }

            // divide the number of messages by the number of seconds we've been connected,
            // if it's more than 100 msg/sec, this peer is sending us too many messages, and we should
            // disconnect.
            let msg_sec = self
                .messages
                .checked_div(Instant::now().duration_since(self.start_time).as_secs())
                .unwrap_or(0);

            if msg_sec > 10 {
                error!(
                    "Peer {} is sending us too many messages, disconnecting",
                    self.id
                );
                return Err(PeerError::TooManyMessages);
            }

            if let State::SentVersion(when) = self.state {
                if Instant::now().duration_since(when) > Duration::from_secs(10) {
                    return Err(PeerError::UnexpectedMessage);
                }
            }
        }
    }
    pub async fn handle_node_request(&mut self, request: NodeRequest) -> Result<()> {
        match request {
            NodeRequest::GetBlock((block_hashes, proof)) => {
                let inv = if proof {
                    block_hashes
                        .iter()
                        .map(|block| Inventory::UtreexoWitnessBlock(*block))
                        .collect()
                } else {
                    block_hashes
                        .iter()
                        .map(|block| Inventory::Block(*block))
                        .collect()
                };

                let _ = self.write(NetworkMessage::GetData(inv)).await;
            }
            NodeRequest::GetHeaders(locator) => {
                let _ = self
                    .write(NetworkMessage::GetHeaders(
                        bitcoin::p2p::message_blockdata::GetHeadersMessage {
                            version: 0,
                            locator_hashes: locator,
                            stop_hash: BlockHash::all_zeros(),
                        },
                    ))
                    .await;
            }
            NodeRequest::Shutdown => {
                self.shutdown = true;
                let _ = self.stream.shutdown();
            }
            NodeRequest::GetAddresses => {
                self.write(NetworkMessage::GetAddr).await?;
            }
            NodeRequest::BroadcastTransaction(tx) => {
                self.write(NetworkMessage::Inv(vec![Inventory::Transaction(tx)]))
                    .await?;
            }
            NodeRequest::MempoolTransaction(txid) => {
                self.write(NetworkMessage::GetData(vec![Inventory::Transaction(txid)]))
                    .await?;
            }
            NodeRequest::SendAddresses(addresses) => {
                self.write(NetworkMessage::AddrV2(addresses)).await?;
            }
        }
        Ok(())
    }
    pub async fn handle_peer_message(&mut self, message: RawNetworkMessage) -> Result<()> {
        self.last_message = Instant::now();

        match self.state {
            State::Connected => match message.payload().to_owned() {
                NetworkMessage::Inv(inv) => {
                    for inv_entry in inv {
                        match inv_entry {
                            Inventory::Error => {}
                            Inventory::Transaction(_) => {}
                            Inventory::Block(block_hash)
                            | Inventory::WitnessBlock(block_hash)
                            | Inventory::CompactBlock(block_hash) => {
                                self.send_to_node(PeerMessages::NewBlock(block_hash)).await;
                            }
                            _ => {}
                        }
                    }
                }
                NetworkMessage::GetHeaders(_) => {
                    self.write(NetworkMessage::Headers(Vec::new())).await?;
                }
                NetworkMessage::Block(block) => {
                    self.send_to_node(PeerMessages::Block(block)).await;
                }
                NetworkMessage::Headers(headers) => {
                    self.send_to_node(PeerMessages::Headers(headers)).await;
                }
                NetworkMessage::SendHeaders => {
                    self.send_headers = true;
                    self.write(NetworkMessage::SendHeaders).await?;
                }
                NetworkMessage::Ping(nonce) => {
                    self.handle_ping(nonce).await?;
                }
                NetworkMessage::FeeFilter(_) => {
                    self.write(NetworkMessage::FeeFilter(1000)).await?;
                }
                NetworkMessage::AddrV2(addresses) => {
                    self.send_to_node(PeerMessages::Addr(addresses)).await;
                }
                NetworkMessage::GetBlocks(_) => {
                    self.write(NetworkMessage::Inv(Vec::new())).await?;
                }
                NetworkMessage::GetAddr => {
                    self.write(NetworkMessage::AddrV2(Vec::new())).await?;
                }
                NetworkMessage::GetData(inv) => {
                    for inv_el in inv {
                        self.handle_get_data(inv_el).await?;
                    }
                }
                NetworkMessage::Tx(tx) => {
                    self.send_to_node(PeerMessages::Transaction(tx)).await;
                }
                NetworkMessage::NotFound(inv) => {
                    for inv_el in inv {
                        self.send_to_node(PeerMessages::NotFound(inv_el)).await;
                    }
                }
                NetworkMessage::SendAddrV2 => {
                    self.wants_addrv2 = true;
                    self.write(NetworkMessage::SendAddrV2).await?;
                }
                NetworkMessage::Pong(_) => {
                    self.last_ping = None;
                }
                NetworkMessage::Unknown { command, payload } => {
                    warn!("Unknown message: {} {:?}", command, payload);
                }
                // Explicitly ignore these messages, if something changes in the future
                // this would cause a compile error.
                NetworkMessage::Verack
                | NetworkMessage::Version(_)
                | NetworkMessage::WtxidRelay
                | NetworkMessage::Reject(_)
                | NetworkMessage::Alert(_)
                | NetworkMessage::BlockTxn(_)
                | NetworkMessage::CFCheckpt(_)
                | NetworkMessage::CFHeaders(_)
                | NetworkMessage::CFilter(_)
                | NetworkMessage::CmpctBlock(_)
                | NetworkMessage::FilterAdd(_)
                | NetworkMessage::FilterClear
                | NetworkMessage::FilterLoad(_)
                | NetworkMessage::GetBlockTxn(_)
                | NetworkMessage::GetCFCheckpt(_)
                | NetworkMessage::GetCFHeaders(_)
                | NetworkMessage::Addr(_)
                | NetworkMessage::GetCFilters(_)
                | NetworkMessage::MemPool
                | NetworkMessage::MerkleBlock(_)
                | NetworkMessage::SendCmpct(_) => {}
            },
            State::None | State::SentVersion(_) => match message.payload().to_owned() {
                bitcoin::p2p::message::NetworkMessage::Version(version) => {
                    self.handle_version(version).await?;
                    self.send_to_node(PeerMessages::Ready(Version {
                        user_agent: self.user_agent.clone(),
                        protocol_version: 0,
                        id: self.id,
                        blocks: self.current_best_block.unsigned_abs(),
                        address_id: self.address_id,
                        services: self.services,
                        feeler: self.feeler,
                    }))
                    .await;
                }
                _ => {
                    warn!(
                        "unexpected message: {:?} from peer {}",
                        message.payload(),
                        self.id
                    );
                    return Err(PeerError::UnexpectedMessage);
                }
            },
            State::SentVerack => match message.payload() {
                bitcoin::p2p::message::NetworkMessage::Verack => {
                    self.state = State::Connected;
                }
                bitcoin::p2p::message::NetworkMessage::SendAddrV2 => {
                    self.wants_addrv2 = true;
                }
                bitcoin::p2p::message::NetworkMessage::SendHeaders => {
                    self.send_headers = true;
                }
                bitcoin::p2p::message::NetworkMessage::WtxidRelay => {}
                _ => {
                    warn!(
                        "unexpected message: {:?} from peer {}",
                        message.payload(),
                        self.id
                    );
                    return Err(PeerError::UnexpectedMessage);
                }
            },
        }
        Ok(())
    }
}
impl<T: Transport> Peer<T> {
    pub async fn write(&mut self, msg: NetworkMessage) -> Result<()> {
        let data = &mut RawNetworkMessage::new(self.network.magic(), msg);
        let data = serialize(&data);
        self.stream.write_all(data.as_slice()).await?;
        Ok(())
    }
    pub async fn handle_get_data(&mut self, inv: Inventory) -> Result<()> {
        match inv {
            Inventory::WitnessTransaction(txid) => {
                let tx = self.mempool.read().await.get_from_mempool(&txid).cloned();
                if let Some(tx) = tx {
                    self.write(NetworkMessage::Tx(tx)).await?;
                }
            }
            Inventory::Transaction(txid) => {
                let tx = self.mempool.read().await.get_from_mempool(&txid).cloned();
                if let Some(tx) = tx {
                    self.write(NetworkMessage::Tx(tx)).await?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub fn create_peer_from_transport(
        stream: T,
        id: u32,
        mempool: Arc<RwLock<Mempool>>,
        network: Network,
        node_tx: Sender<NodeNotification>,
        node_requests: Receiver<NodeRequest>,
        address_id: usize,
        feeler: bool,
    ) {
        let peer = Peer {
            address_id,
            blocks_only: false,
            current_best_block: -1,
            id,
            mempool,
            last_ping: None,
            last_message: Instant::now(),
            network,
            node_tx,
            services: ServiceFlags::NONE,
            stream,
            messages: 0,
            start_time: Instant::now(),
            user_agent: "".into(),
            state: State::None,
            send_headers: false,
            node_requests,
            feeler,
            wants_addrv2: false,
            shutdown: false,
        };
        spawn(peer.read_loop());
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_outbound_connection<A: ToSocketAddrs + Debug>(
        id: u32,
        address: A,
        mempool: Arc<RwLock<Mempool>>,
        network: Network,
        node_tx: Sender<NodeNotification>,
        node_requests: Receiver<NodeRequest>,
        address_id: usize,
        feeler: bool,
    ) {
        let stream =
            async_std::future::timeout(Duration::from_secs(10), TcpStream::connect(address)).await;
        let Ok(Ok(stream)) = stream else {
            let _ = node_tx
                .send(NodeNotification::FromPeer(
                    id,
                    PeerMessages::Disconnected(id as usize),
                ))
                .await;
            return;
        };
        let peer = Peer {
            address_id,
            blocks_only: false,
            current_best_block: -1,
            id,
            mempool,
            last_ping: None,
            last_message: Instant::now(),
            network,
            node_tx,
            services: ServiceFlags::NONE,
            stream,
            messages: 0,
            start_time: Instant::now(),
            user_agent: "".into(),
            state: State::None,
            send_headers: false,
            node_requests,
            feeler,
            wants_addrv2: false,
            shutdown: false,
        };
        spawn(peer.read_loop());
    }
    async fn handle_ping(&mut self, nonce: u64) -> Result<()> {
        let pong = make_pong(nonce);
        self.write(pong).await
    }
    async fn handle_version(&mut self, version: VersionMessage) -> Result<()> {
        self.user_agent = version.user_agent;
        self.blocks_only = !version.relay;
        self.current_best_block = version.start_height;
        self.services = version.services;
        if version.version >= 70016 {
            self.write(NetworkMessage::SendAddrV2).await?;
        }
        self.state = State::SentVerack;
        let verack = NetworkMessage::Verack;
        self.state = State::SentVerack;
        self.write(verack).await
    }
    async fn send_to_node(&self, message: PeerMessages) {
        let message = NodeNotification::FromPeer(self.id, message);
        let _ = self.node_tx.send(message).await;
    }
}
pub(super) mod peer_utils {
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    use bitcoin::p2p::address;
    use bitcoin::p2p::message::NetworkMessage;
    use bitcoin::p2p::message::{self};
    use bitcoin::p2p::message_network;
    use floresta_common::constants::FLORESTA_VERSION;
    use floresta_common::constants::RUSTREEXO_VERSION;
    use floresta_common::constants::RUST_BITCOIN_VERSION;

    /// Protocol version we speak
    pub const PROTOCOL_VERSION: u32 = 70016;

    pub(super) fn make_pong(nonce: u64) -> NetworkMessage {
        NetworkMessage::Pong(nonce)
    }

    pub(crate) fn build_version_message() -> message::NetworkMessage {
        use bitcoin::p2p::ServiceFlags;

        // Building version message, see https://en.bitcoin.it/wiki/Protocol_documentation#version
        let my_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 38332);

        // "bitfield of features to be enabled for this connection"
        let services = ServiceFlags::NETWORK | ServiceFlags::from(1 << 24) | ServiceFlags::WITNESS;

        // "standard UNIX timestamp in seconds"
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time error")
            .as_secs();

        // "The network address of the node receiving this message"
        let addr_recv = address::Address::new(&my_address, ServiceFlags::NONE);

        // "The network address of the node emitting this message"
        let addr_from = address::Address::new(&my_address, ServiceFlags::NONE);

        // "Node random nonce, randomly generated every time a version packet is sent. This nonce is used to detect connections to self."
        let nonce: u64 = 1;

        // "User Agent (0x00 if string is 0 bytes long)"
        let user_agent = format!(
            "/rust-bitcoin:{}/rustreexo:{}/Floresta:{}/",
            RUST_BITCOIN_VERSION, RUSTREEXO_VERSION, FLORESTA_VERSION
        );

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
            version: PROTOCOL_VERSION,
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
    pub feeler: bool,
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
    /// Remote peer doesn't known the data we asked for
    NotFound(Inventory),
    /// Remote peer sent us a transaction
    Transaction(Transaction),
}
