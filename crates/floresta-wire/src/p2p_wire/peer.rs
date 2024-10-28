use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use bitcoin::bip158;
use bitcoin::block::Header as BlockHeader;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::deserialize_partial;
use bitcoin::consensus::serialize;
use bitcoin::consensus::Decodable;
use bitcoin::hashes::Hash;
use bitcoin::p2p::address::AddrV2Message;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message::RawNetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::Magic;
use bitcoin::p2p::ServiceFlags;
use bitcoin::BlockHash;
use bitcoin::Network;
use bitcoin::Transaction;
use floresta_chain::UtreexoBlock;
use futures::FutureExt;
use log::debug;
use log::error;
use log::warn;
use thiserror::Error;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::io::WriteHalf;
use tokio::net::TcpStream;
use tokio::spawn;
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::RwLock;

use self::peer_utils::make_pong;
use super::mempool::Mempool;
use super::node::NodeNotification;
use super::node::NodeRequest;
use crate::node::ConnectionKind;

/// If we send a ping, and our peer takes more than PING_TIMEOUT to
/// reply, disconnect.
const PING_TIMEOUT: u64 = 30;
/// If the last message we've got was more than XX, send out a ping
const SEND_PING_TIMEOUT: u64 = 60;
/// The inv element type for a utreexo block with witness data
const INV_UTREEXO_BLOCK: u32 = 0x40000002 | 1 << 24;

#[derive(Debug, PartialEq)]
enum State {
    None,
    SentVersion(Instant),
    SentVerack,
    Connected,
}

pub struct P2PMessageHeader {
    _magic: Magic,
    _command: [u8; 12],
    length: u32,
    _checksum: u32,
}

impl Decodable for P2PMessageHeader {
    fn consensus_decode<R: std::io::Read + ?Sized>(
        reader: &mut R,
    ) -> std::result::Result<Self, bitcoin::consensus::encode::Error> {
        let _magic = Magic::consensus_decode(reader)?;
        let _command = <[u8; 12]>::consensus_decode(reader)?;
        let length = u32::consensus_decode(reader)?;
        let _checksum = u32::consensus_decode(reader)?;
        Ok(Self {
            _checksum,
            _command,
            length,
            _magic,
        })
    }
}

// Define the actor
pub struct TcpStreamActor<T: AsyncRead + Unpin> {
    pub stream: T,
    pub sender: UnboundedSender<ReaderMessage>,
}

impl<T: AsyncRead + Unpin> TcpStreamActor<T> {
    async fn inner(&mut self) -> std::result::Result<(), PeerError> {
        loop {
            let mut data: Vec<u8> = vec![0; 24];

            // Read the header first, so learn the payload size
            self.stream.read_exact(&mut data).await?;
            let header: P2PMessageHeader = deserialize_partial(&data)?.0;

            // Network Message too big
            if header.length > (1024 * 1024 * 32) as u32 {
                return Err(PeerError::MessageTooBig);
            }

            data.resize(24 + header.length as usize, 0);

            // Read everything else
            self.stream.read_exact(&mut data[24..]).await?;

            // Intercept block messages
            if header._command[0..5] == [0x62, 0x6c, 0x6f, 0x63, 0x6b] {
                let mut block_data = vec![0; header.length as usize];
                block_data.copy_from_slice(&data[24..]);

                let message: UtreexoBlock = deserialize(&block_data)?;
                self.sender.send(ReaderMessage::Block(message))?;
            }

            let message: RawNetworkMessage = deserialize(&data)?;
            self.sender.send(ReaderMessage::Message(message))?;
        }
    }

    pub async fn run(mut self) -> Result<()> {
        let err = self.inner().await;
        if let Err(err) = err {
            self.sender.send(ReaderMessage::Error(err))?;
        }
        Ok(())
    }
}

// Function to create a new actor and a sender
pub fn create_tcp_stream_actor(
    stream: impl AsyncRead + Unpin,
) -> (
    UnboundedReceiver<ReaderMessage>,
    TcpStreamActor<impl AsyncRead + Unpin>,
) {
    let (actor_sender, actor_receiver) = unbounded_channel();
    let actor = TcpStreamActor {
        stream,
        sender: actor_sender,
    };
    (actor_receiver, actor)
}

pub struct Peer<T: AsyncWrite + Unpin> {
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
    node_tx: UnboundedSender<NodeNotification>,
    state: State,
    send_headers: bool,
    node_requests: UnboundedReceiver<NodeRequest>,
    address_id: usize,
    kind: ConnectionKind,
    wants_addrv2: bool,
    shutdown: bool,
    actor_receiver: UnboundedReceiver<ReaderMessage>, // Add the receiver for messages from TcpStreamActor
    writer: T,
    our_user_agent: String,
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
    #[error("channel error")]
    Channel,
}

pub enum ReaderMessage {
    Block(UtreexoBlock),
    Message(RawNetworkMessage),
    Error(PeerError),
}

impl From<tokio::sync::mpsc::error::SendError<ReaderMessage>> for PeerError {
    fn from(_: tokio::sync::mpsc::error::SendError<ReaderMessage>) -> Self {
        PeerError::Channel
    }
}

impl From<UtreexoBlock> for ReaderMessage {
    fn from(block: UtreexoBlock) -> Self {
        ReaderMessage::Block(block)
    }
}

impl From<RawNetworkMessage> for ReaderMessage {
    fn from(header: RawNetworkMessage) -> Self {
        ReaderMessage::Message(header)
    }
}

impl<T: AsyncWrite + Unpin> Debug for Peer<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)?;
        Ok(())
    }
}

type Result<T> = std::result::Result<T, PeerError>;

impl<T: AsyncWrite + Unpin> Peer<T> {
    pub async fn read_loop(mut self) -> Result<()> {
        let err = self.peer_loop_inner().await;
        if err.is_err() {
            error!("Peer {} connection loop closed: {err:?}", self.id);
        }
        self.send_to_node(PeerMessages::Disconnected(self.address_id))
            .await;
        // force the stream to shutdown to prevent leaking resources
        if let Err(shutdown_err) = self.writer.shutdown().await {
            debug!(
                "Failed to shutdown writer for Peer {}: {shutdown_err:?}",
                self.id
            );
        }

        if let Err(err) = err {
            debug!("Peer {} connection loop closed: {err:?}", self.id);
        }

        Ok(())
    }

    async fn peer_loop_inner(&mut self) -> Result<()> {
        // send a version
        let version = peer_utils::build_version_message(self.our_user_agent.clone());
        self.write(version).await?;
        self.state = State::SentVersion(Instant::now());
        loop {
            futures::select! {
                request = tokio::time::timeout(Duration::from_secs(10), self.node_requests.recv()).fuse() => {
                    match request {
                        Ok(None) => {
                            return Err(PeerError::Channel);
                        },
                        Ok(Some(request)) => {
                            self.handle_node_request(request).await?;
                        },
                        Err(_) => {
                            // Timeout, do nothing
                        }
                    }
                },
                message = self.actor_receiver.recv().fuse() => {
                    match message {
                        None => {
                            return Err(PeerError::Channel);
                        }
                        Some(ReaderMessage::Error(e)) => {
                            return Err(e);
                        }
                        Some(ReaderMessage::Block(block)) => {
                            self.send_to_node(PeerMessages::Block(block)).await;
                        }
                        Some(ReaderMessage::Message(msg)) => {
                            self.handle_peer_message(msg).await?;
                        }
                    }
                }
            }

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
                if self.last_ping.is_some() {
                    continue;
                }
                let nonce = rand::random();
                self.last_ping = Some(Instant::now());
                self.write(NetworkMessage::Ping(nonce)).await?;
            }

            // divide the number of messages by the number of seconds we've been connected,
            // if it's more than 10 msg/sec, this peer is sending us too many messages, and we should
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
        assert_eq!(self.state, State::Connected);
        debug!("Handling node request: {:?}", request);
        match request {
            NodeRequest::GetBlock((block_hashes, proof)) => {
                let inv = if proof {
                    block_hashes
                        .iter()
                        .map(|block| Inventory::Unknown {
                            inv_type: INV_UTREEXO_BLOCK,
                            hash: *block.as_byte_array(),
                        })
                        .collect()
                } else {
                    block_hashes
                        .iter()
                        .map(|block| Inventory::WitnessBlock(*block))
                        .collect()
                };

                let _ = self.write(NetworkMessage::GetData(inv)).await;
            }
            NodeRequest::GetUtreexoState((block_hash, height)) => {
                let get_filter = bitcoin::p2p::message_filter::GetCFilters {
                    filter_type: 1,
                    start_height: height,
                    stop_hash: block_hash,
                };

                let _ = self.write(NetworkMessage::GetCFilters(get_filter)).await;
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
                self.writer.shutdown().await?;
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
            NodeRequest::GetFilter((stop_hash, start_height)) => {
                let get_filter = bitcoin::p2p::message_filter::GetCFilters {
                    filter_type: 0,
                    start_height,
                    stop_hash,
                };

                self.write(NetworkMessage::GetCFilters(get_filter)).await?;
            }
        }
        Ok(())
    }
    pub async fn handle_peer_message(&mut self, message: RawNetworkMessage) -> Result<()> {
        self.last_message = Instant::now();
        debug!("Received {} from peer {}", message.command(), self.id);
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
                NetworkMessage::CFilter(filter_msg) => match filter_msg.filter_type {
                    0 => {
                        let filter = bip158::BlockFilter::new(&filter_msg.filter);

                        // FIXME
                        let filter = unsafe {
                            std::mem::transmute::<
                                bitcoin::bip158::BlockFilter,
                                floresta_compact_filters::BlockFilter,
                            >(filter)
                        };
                        self.send_to_node(PeerMessages::BlockFilter((
                            filter_msg.block_hash,
                            filter,
                        )))
                        .await;
                    }
                    1 => {
                        self.send_to_node(PeerMessages::UtreexoState(filter_msg.filter))
                            .await;
                    }
                    _ => {}
                },
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
                | NetworkMessage::SendCmpct(_)
                | NetworkMessage::Block(_) => {}
            },
            State::None | State::SentVersion(_) => match message.payload().to_owned() {
                bitcoin::p2p::message::NetworkMessage::Version(version) => {
                    self.handle_version(version).await?;
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
                    self.send_to_node(PeerMessages::Ready(Version {
                        user_agent: self.user_agent.clone(),
                        protocol_version: 0,
                        id: self.id,
                        blocks: self.current_best_block.unsigned_abs(),
                        address_id: self.address_id,
                        services: self.services,
                        kind: self.kind,
                    }))
                    .await;
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

impl<T: AsyncWrite + Unpin> Peer<T> {
    pub async fn write(&mut self, msg: NetworkMessage) -> Result<()> {
        debug!("Writing {} to peer {}", msg.command(), self.id);
        let data = &mut RawNetworkMessage::new(self.network.magic(), msg);
        let data = serialize(&data);
        self.writer.write_all(&data).await?;
        self.writer.flush().await?;
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
    pub async fn create_peer(
        id: u32,
        mempool: Arc<RwLock<Mempool>>,
        network: Network,
        node_tx: UnboundedSender<NodeNotification>,
        node_requests: UnboundedReceiver<NodeRequest>,
        address_id: usize,
        kind: ConnectionKind,
        actor_receiver: UnboundedReceiver<ReaderMessage>,
        writer: WriteHalf<TcpStream>,
        our_user_agent: String,
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
            messages: 0,
            start_time: Instant::now(),
            user_agent: "".into(),
            state: State::None,
            send_headers: false,
            node_requests,
            kind,
            wants_addrv2: false,
            shutdown: false,
            actor_receiver, // Add the receiver for messages from TcpStreamActor
            writer,
            our_user_agent,
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
        let _ = self.node_tx.send(message);
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

    /// Protocol version we speak
    pub const PROTOCOL_VERSION: u32 = 70016;

    pub(super) fn make_pong(nonce: u64) -> NetworkMessage {
        NetworkMessage::Pong(nonce)
    }

    pub(crate) fn build_version_message(user_agent: String) -> message::NetworkMessage {
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
    pub kind: ConnectionKind,
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
    UtreexoState(Vec<u8>),
    BlockFilter((BlockHash, floresta_compact_filters::BlockFilter)),
}
