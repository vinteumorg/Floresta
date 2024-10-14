//! Main file for this blockchain. A node is the central task that runs and handles important
//! events, such as new blocks, peer connection/disconnection, new addresses, etc.
//! A node should not care about peer-specific messages, peers'll handle things like pings.
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use bitcoin::p2p::address::AddrV2;
use bitcoin::p2p::address::AddrV2Message;
use bitcoin::p2p::ServiceFlags;
use bitcoin::BlockHash;
use bitcoin::Txid;
use floresta_chain::pruned_utreexo::chainparams::get_chain_dns_seeds;
use floresta_chain::pruned_utreexo::BlockchainInterface;
use floresta_chain::pruned_utreexo::UpdatableChainstate;
use floresta_chain::Network;
use floresta_chain::UtreexoBlock;
use floresta_common::service_flags;
use floresta_compact_filters::flat_filters_store::FlatFiltersStore;
use floresta_compact_filters::network_filters::NetworkFilters;
use log::debug;
use log::info;
use log::warn;
use serde::Deserialize;
use serde::Serialize;
use tokio::net::tcp::WriteHalf;
use tokio::net::TcpStream;
use tokio::spawn;
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::RwLock;
use tokio::time::timeout;

use super::address_man::AddressMan;
use super::address_man::AddressState;
use super::address_man::LocalAddress;
use super::error::WireError;
use super::mempool::Mempool;
use super::node_context::NodeContext;
use super::node_interface::NodeInterface;
use super::node_interface::PeerInfo;
use super::node_interface::UserRequest;
use super::peer::create_tcp_stream_actor;
use super::peer::Peer;
use super::peer::PeerMessages;
use super::peer::Version;
use super::running_node::RunningNode;
use super::socks::Socks5Addr;
use super::socks::Socks5Error;
use super::socks::Socks5StreamBuilder;
use super::UtreexoNodeConfig;
use crate::node_context::PeerId;

#[derive(Debug)]
pub enum NodeNotification {
    FromPeer(u32, PeerMessages),
}

#[derive(Debug, Clone, PartialEq, Hash)]
/// Sent from node to peers, usually to request something
pub enum NodeRequest {
    /// Get this block's data
    GetBlock((Vec<BlockHash>, bool)),
    /// Asks peer for headers
    GetHeaders(Vec<BlockHash>),
    /// Ask for other peers addresses
    GetAddresses,
    /// Asks this peer to shutdown
    Shutdown,
    /// Sends a transaction to peers
    BroadcastTransaction(Txid),
    /// Ask for an unconfirmed transaction
    MempoolTransaction(Txid),
    /// Sends know addresses to our peers
    SendAddresses(Vec<AddrV2Message>),
    GetUtreexoState((BlockHash, u32)),
    GetFilter((BlockHash, u32)),
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub(crate) enum InflightRequests {
    Headers,
    UtreexoState(PeerId),
    Blocks(BlockHash),
    UserRequest(UserRequest),
    Connect(u32),
    GetFilters,
}

#[derive(Debug, PartialEq, Clone, Copy, Deserialize, Serialize)]
pub enum ConnectionKind {
    Feeler,
    Regular,
    Extra,
}

#[derive(Debug, Clone)]
pub struct LocalPeerView {
    pub(crate) state: PeerStatus,
    pub(crate) address_id: u32,
    pub(crate) channel: UnboundedSender<NodeRequest>,
    pub(crate) services: ServiceFlags,
    pub(crate) user_agent: String,
    pub(crate) address: IpAddr,
    pub(crate) port: u16,
    pub(crate) _last_message: Instant,
    pub(crate) kind: ConnectionKind,
    pub(crate) height: u32,
    pub(crate) banscore: u32,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum RescanStatus {
    InProgress(u32),
    Completed(Instant),
    None,
}

impl Default for RunningNode {
    fn default() -> Self {
        RunningNode {
            last_feeler: Instant::now(),
            last_address_rearrange: Instant::now(),
            user_requests: Arc::new(NodeInterface {
                requests: Mutex::new(Vec::new()),
            }),
            last_invs: HashMap::default(),
            inflight_filters: BTreeMap::new(),
        }
    }
}

pub struct NodeCommon<Chain: BlockchainInterface + UpdatableChainstate> {
    pub(crate) peer_id_count: u32,
    pub(crate) last_headers_request: Instant,
    pub(crate) last_tip_update: Instant,
    pub(crate) last_connection: Instant,
    pub(crate) last_peer_db_dump: Instant,
    pub(crate) last_broadcast: Instant,
    pub(crate) last_send_addresses: Instant,
    pub(crate) last_block_request: u32,
    pub(crate) network: Network,
    pub(crate) last_get_address_request: Instant,
    pub(crate) peer_by_service: HashMap<ServiceFlags, Vec<u32>>,
    pub(crate) peer_ids: Vec<u32>,
    pub(crate) peers: HashMap<u32, LocalPeerView>,
    pub(crate) chain: Chain,
    pub(crate) blocks: HashMap<BlockHash, (PeerId, UtreexoBlock)>,
    pub(crate) inflight: HashMap<InflightRequests, (u32, Instant)>,
    pub(crate) node_rx: UnboundedReceiver<NodeNotification>,
    pub(crate) node_tx: UnboundedSender<NodeNotification>,
    pub(crate) mempool: Arc<RwLock<Mempool>>,
    pub(crate) datadir: String,
    pub(crate) address_man: AddressMan,
    pub(crate) max_banscore: u32,
    pub(crate) socks5: Option<Socks5StreamBuilder>,
    pub(crate) fixed_peer: Option<LocalAddress>,
    pub(crate) config: UtreexoNodeConfig,
    pub(crate) block_filters: Option<Arc<NetworkFilters<FlatFiltersStore>>>,
    pub(crate) last_filter: BlockHash,
}

pub struct UtreexoNode<Context, Chain: BlockchainInterface + UpdatableChainstate>(
    pub(crate) NodeCommon<Chain>,
    pub(crate) Context,
);

impl<Chain: BlockchainInterface + UpdatableChainstate, T> Deref for UtreexoNode<T, Chain> {
    fn deref(&self) -> &Self::Target {
        &self.0
    }
    type Target = NodeCommon<Chain>;
}

impl<T, Chain: BlockchainInterface + UpdatableChainstate> DerefMut for UtreexoNode<T, Chain> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Debug, PartialEq, Clone, Copy, Deserialize, Serialize)]
pub enum PeerStatus {
    Awaiting,
    Ready,
    Banned,
}

impl<T, Chain> UtreexoNode<T, Chain>
where
    T: 'static + Default + NodeContext,
    WireError: From<<Chain as BlockchainInterface>::Error>,
    Chain: BlockchainInterface + UpdatableChainstate + 'static,
{
    pub fn new(
        config: UtreexoNodeConfig,
        chain: Chain,
        mempool: Arc<RwLock<Mempool>>,
        block_filters: Option<Arc<NetworkFilters<FlatFiltersStore>>>,
    ) -> Self {
        let (node_tx, node_rx) = unbounded_channel();
        let socks5 = config.proxy.map(Socks5StreamBuilder::new);
        UtreexoNode(
            NodeCommon {
                last_filter: chain.get_block_hash(0).unwrap(),
                block_filters,
                inflight: HashMap::new(),
                peer_id_count: 0,
                peers: HashMap::new(),
                last_block_request: chain.get_validation_index().expect("Invalid chain"),
                chain,
                peer_ids: Vec::new(),
                peer_by_service: HashMap::new(),
                mempool,
                network: config.network.into(),
                node_rx,
                node_tx,
                address_man: AddressMan::default(),
                last_headers_request: Instant::now(),
                last_tip_update: Instant::now(),
                last_connection: Instant::now(),
                last_peer_db_dump: Instant::now(),
                last_broadcast: Instant::now(),
                blocks: HashMap::new(),
                last_get_address_request: Instant::now(),
                last_send_addresses: Instant::now(),
                datadir: config.datadir.clone(),
                socks5,
                max_banscore: config.max_banscore,
                fixed_peer: config.fixed_peer.clone(),
                config,
            },
            T::default(),
        )
    }

    pub(crate) fn get_peer_info(&self, peer: &u32) -> Option<PeerInfo> {
        let peer = self.peers.get(peer)?;
        Some(PeerInfo {
            state: peer.state,
            kind: peer.kind,
            address: format!("{}:{}", peer.address, peer.port),
            services: peer.services.to_string(),
            user_agent: peer.user_agent.clone(),
            initial_height: peer.height,
        })
    }
    pub(crate) async fn handle_disconnection(
        &mut self,
        peer: u32,
        idx: usize,
    ) -> Result<(), WireError> {
        if let Some(p) = self.peers.remove(&peer) {
            std::mem::drop(p.channel);
            if p.kind == ConnectionKind::Regular && p.state == PeerStatus::Ready {
                info!("Peer disconnected: {}", peer);
            }

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            match p.state {
                PeerStatus::Ready => {
                    self.address_man
                        .update_set_state(idx, AddressState::Tried(now));
                }
                PeerStatus::Awaiting => {
                    self.address_man
                        .update_set_state(idx, AddressState::Failed(now));
                }
                PeerStatus::Banned => {
                    self.address_man
                        .update_set_state(idx, AddressState::Banned(RunningNode::BAN_TIME));
                }
            }
        }

        self.peer_ids.retain(|&id| id != peer);
        for (_, v) in self.peer_by_service.iter_mut() {
            v.retain(|&id| id != peer);
        }

        let inflight = self
            .inflight
            .clone()
            .into_iter()
            .filter(|(_k, v)| v.0 == peer)
            .collect::<Vec<_>>();

        for req in inflight {
            self.inflight.remove(&req.0);
            self.redo_inflight_request(req.0.clone()).await?;
        }

        Ok(())
    }

    pub(crate) async fn redo_inflight_request(
        &mut self,
        req: InflightRequests,
    ) -> Result<(), WireError> {
        match req {
            InflightRequests::Blocks(block) => {
                let peer = self
                    .send_to_random_peer(
                        NodeRequest::GetBlock((vec![block], true)),
                        service_flags::UTREEXO.into(),
                    )
                    .await?;
                self.inflight
                    .insert(InflightRequests::Blocks(block), (peer, Instant::now()));
            }
            InflightRequests::Headers => {
                let peer = self
                    .send_to_random_peer(
                        NodeRequest::GetHeaders(vec![]),
                        service_flags::UTREEXO.into(),
                    )
                    .await?;
                self.inflight
                    .insert(InflightRequests::Headers, (peer, Instant::now()));
            }
            InflightRequests::UtreexoState(_) => {
                let peer = self
                    .send_to_random_peer(
                        NodeRequest::GetUtreexoState((self.chain.get_block_hash(0).unwrap(), 0)),
                        service_flags::UTREEXO.into(),
                    )
                    .await?;
                self.inflight
                    .insert(InflightRequests::UtreexoState(peer), (peer, Instant::now()));
            }
            InflightRequests::GetFilters => {
                let peer = self
                    .send_to_random_peer(
                        NodeRequest::GetFilter((self.chain.get_block_hash(0).unwrap(), 0)),
                        ServiceFlags::COMPACT_FILTERS,
                    )
                    .await?;
                self.inflight
                    .insert(InflightRequests::GetFilters, (peer, Instant::now()));
            }
            InflightRequests::Connect(_) | InflightRequests::UserRequest(_) => {
                // WE DON'T NEED TO DO ANYTHING HERE
            }
        }

        Ok(())
    }

    pub(crate) async fn handle_peer_ready(
        &mut self,
        peer: u32,
        version: &Version,
    ) -> Result<(), WireError> {
        self.inflight.remove(&InflightRequests::Connect(peer));
        if version.kind == ConnectionKind::Feeler {
            self.peers.entry(peer).and_modify(|p| {
                p.state = PeerStatus::Ready;
            });

            self.send_to_peer(peer, NodeRequest::Shutdown).await?;
            self.address_man
                .update_set_service_flag(version.address_id, version.services);
            return Ok(());
        }

        if version.kind == ConnectionKind::Extra {
            let locator = self.chain.get_block_locator()?;
            self.send_to_peer(peer, NodeRequest::GetHeaders(locator))
                .await?;
            self.inflight
                .insert(InflightRequests::Headers, (peer, Instant::now()));

            return Ok(());
        }

        info!(
            "New peer id={} version={} blocks={} services={}",
            version.id, version.user_agent, version.blocks, version.services
        );

        if let Some(peer_data) = self.0.peers.get_mut(&peer) {
            // This peer doesn't have basic services, so we disconnect it
            if !version
                .services
                .has(ServiceFlags::NETWORK | ServiceFlags::WITNESS)
            {
                self.send_to_peer(peer, NodeRequest::Shutdown).await?;
                self.address_man.update_set_state(
                    version.address_id,
                    AddressState::Tried(
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                    ),
                );
                self.address_man
                    .update_set_service_flag(version.address_id, version.services);
                return Ok(());
            }
            peer_data.state = PeerStatus::Ready;
            peer_data.services = version.services;
            peer_data.user_agent.clone_from(&version.user_agent);
            peer_data.height = version.blocks;

            if peer_data.services.has(service_flags::UTREEXO.into()) {
                self.0
                    .peer_by_service
                    .entry(service_flags::UTREEXO.into())
                    .or_default()
                    .push(peer);
            }

            if peer_data.services.has(ServiceFlags::COMPACT_FILTERS) {
                self.0
                    .peer_by_service
                    .entry(ServiceFlags::COMPACT_FILTERS)
                    .or_default()
                    .push(peer);
            }

            if peer_data.services.has(ServiceFlags::from(1 << 25)) {
                self.0
                    .peer_by_service
                    .entry(ServiceFlags::from(1 << 25))
                    .or_default()
                    .push(peer);
            }

            self.address_man
                .update_set_state(version.address_id, AddressState::Connected)
                .update_set_service_flag(version.address_id, version.services);

            self.peer_ids.push(peer);
        }
        Ok(())
    }

    pub(crate) fn get_default_port(&self) -> u16 {
        match self.network {
            Network::Bitcoin => 8333,
            Network::Testnet => 18333,
            Network::Signet => 38333,
            Network::Regtest => 18444,
        }
    }

    pub(crate) async fn send_to_peer(
        &self,
        peer_id: u32,
        req: NodeRequest,
    ) -> Result<(), WireError> {
        if let Some(peer) = &self.peers.get(&peer_id) {
            if peer.state == PeerStatus::Awaiting {
                return Ok(());
            }
            peer.channel.send(req)?;
        }
        Ok(())
    }

    /// Increses the "banscore" of a peer.
    ///
    /// This is a always increasing number that, if reaches our `max_banscore` setting,
    /// will cause our peer to be banned for one BANTIME.
    /// The amount of each increment is given by factor, and it's callibrated for each misbehaving
    /// action that a peer may incur in.
    pub(crate) async fn increase_banscore(
        &mut self,
        peer_id: u32,
        factor: u32,
    ) -> Result<(), WireError> {
        let Some(peer) = self.0.peers.get_mut(&peer_id) else {
            return Ok(());
        };

        peer.banscore += factor;

        // This peer is misbehaving too often, ban it
        let is_missbehaving = peer.banscore >= self.0.max_banscore;
        // extra peers should be banned immediately
        let is_extra = peer.kind == ConnectionKind::Extra;

        if is_missbehaving || is_extra {
            warn!("banning peer {} for misbehaving", peer_id);
            peer.channel.send(NodeRequest::Shutdown)?;
            peer.state = PeerStatus::Banned;
            return Ok(());
        }

        debug!("increasing banscore for peer {}", peer_id);

        Ok(())
    }

    pub(crate) fn has_utreexo_peers(&self) -> bool {
        !self
            .peer_by_service
            .get(&service_flags::UTREEXO.into())
            .unwrap_or(&Vec::new())
            .is_empty()
    }

    pub(crate) fn has_compact_filters_peer(&self) -> bool {
        self.peer_by_service
            .get(&ServiceFlags::COMPACT_FILTERS)
            .map(|peers| !peers.is_empty())
            .unwrap_or(false)
    }

    #[inline]
    pub(crate) async fn send_to_random_peer(
        &mut self,
        req: NodeRequest,
        required_service: ServiceFlags,
    ) -> Result<u32, WireError> {
        if self.peers.is_empty() {
            return Err(WireError::NoPeersAvailable);
        }

        let peers = match required_service {
            ServiceFlags::NONE => &self.peer_ids,
            _ => self
                .peer_by_service
                .get(&required_service)
                .ok_or(WireError::NoPeersAvailable)?,
        };

        if peers.is_empty() {
            return Err(WireError::NoPeersAvailable);
        }

        let rand = rand::random::<usize>() % peers.len();
        let peer = peers[rand];
        self.peers
            .get(&peer)
            .ok_or(WireError::NoPeersAvailable)?
            .channel
            .send(req)
            .map_err(WireError::ChannelSend)?;

        Ok(peer)
    }

    pub(crate) async fn init_peers(&mut self) -> Result<(), WireError> {
        let anchors = self.0.address_man.start_addr_man(
            self.datadir.clone(),
            self.get_default_port(),
            self.network,
            &get_chain_dns_seeds(self.network),
        )?;
        for address in anchors {
            self.open_connection(ConnectionKind::Regular, address.id, address)
                .await;
        }
        Ok(())
    }

    pub(crate) async fn shutdown(&mut self) {
        info!("Shutting down node");
        for peer in self.peer_ids.iter() {
            try_and_log!(self.send_to_peer(*peer, NodeRequest::Shutdown).await);
        }

        try_and_log!(self.save_peers());
        try_and_log!(self.chain.flush());
    }

    pub(crate) async fn handle_broadcast(&self) -> Result<(), WireError> {
        for (_, peer) in self.peers.iter() {
            if peer.services.has(ServiceFlags::from(1 << 24)) {
                continue;
            }

            let transactions = self.chain.get_unbroadcasted();

            for transaction in transactions {
                let txid = transaction.txid();
                self.mempool.write().await.accept_to_mempool(transaction);
                peer.channel
                    .send(NodeRequest::BroadcastTransaction(txid))
                    .map_err(WireError::ChannelSend)?;
            }
            let stale = self.mempool.write().await.get_stale();
            for tx in stale {
                peer.channel
                    .send(NodeRequest::BroadcastTransaction(tx))
                    .map_err(WireError::ChannelSend)?;
            }
        }
        Ok(())
    }

    pub(crate) async fn ask_for_addresses(&mut self) -> Result<(), WireError> {
        let _ = self
            .send_to_random_peer(NodeRequest::GetAddresses, ServiceFlags::NONE)
            .await?;
        Ok(())
    }

    pub(crate) fn save_peers(&self) -> Result<(), WireError> {
        self.address_man
            .dump_peers(&self.datadir)
            .map_err(WireError::Io)
    }

    pub(crate) async fn maybe_open_connection(&mut self) -> Result<(), WireError> {
        // If the user passes in a `--connect` cli argument, we only connect with
        // that particular peer.
        if self.fixed_peer.is_some() && !self.peers.is_empty() {
            return Ok(());
        }
        // if we need utreexo peers, we can bypass our max outgoing peers limit in case
        // we don't have any utreexo peers
        let bypass = self
            .1
            .get_required_services()
            .has(service_flags::UTREEXO.into())
            && !self.has_utreexo_peers();

        if self.peers.len() < T::MAX_OUTGOING_PEERS || bypass {
            self.create_connection(ConnectionKind::Regular).await;
        }

        Ok(())
    }

    pub(crate) async fn open_feeler_connection(&mut self) -> Result<(), WireError> {
        // No feeler if `-connect` is set
        if self.fixed_peer.is_some() {
            return Ok(());
        }
        self.create_connection(ConnectionKind::Feeler).await;
        Ok(())
    }

    pub(crate) async fn request_blocks(&mut self, blocks: Vec<BlockHash>) -> Result<(), WireError> {
        let blocks: Vec<_> = blocks
            .into_iter()
            .filter(|block| {
                !self
                    .inflight
                    .contains_key(&InflightRequests::Blocks(*block))
            })
            .collect();

        let peer = self
            .send_to_random_peer(
                NodeRequest::GetBlock((blocks.clone(), true)),
                service_flags::UTREEXO.into(),
            )
            .await?;

        for block in blocks.iter() {
            self.inflight
                .insert(InflightRequests::Blocks(*block), (peer, Instant::now()));
        }

        Ok(())
    }

    fn get_required_services(&self) -> ServiceFlags {
        let required_services = self.1.get_required_services();

        // chain selector should prefer peers that support UTREEXO filters, as
        // more peers with this service will improve our security for PoW
        // fraud proofs. This is only true if pow fraud proofs are enabled
        // in the configuration.
        if self.config.pow_fraud_proofs && required_services.has(ServiceFlags::from(1 << 25)) {
            return ServiceFlags::from(1 << 25);
        }

        // we need at least one utreexo peer
        if !self.has_utreexo_peers() {
            return service_flags::UTREEXO.into();
        }

        // we need at least one peer with compact filters
        if !self.has_compact_filters_peer() {
            return ServiceFlags::COMPACT_FILTERS;
        }

        // we have at least one peer with the required services, so we can connect
        // with any random peer
        ServiceFlags::NONE
    }

    pub(crate) async fn create_connection(&mut self, kind: ConnectionKind) -> Option<()> {
        let required_services = self.get_required_services();
        let address = match &self.fixed_peer {
            Some(address) => Some((0, address.clone())),
            None => self
                .address_man
                .get_address_to_connect(required_services, matches!(kind, ConnectionKind::Feeler)),
        };

        debug!(
            "attempting connection with address={:?} kind={:?}",
            address, kind
        );
        let (peer_id, address) = address?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Defaults to failed, if the connection is successful, we'll update the state
        self.address_man
            .update_set_state(peer_id, AddressState::Failed(now));

        // Don't connect to the same peer twice
        if self
            .0
            .peers
            .iter()
            .any(|peers| peers.1.address == address.get_net_address())
        {
            return None;
        }
        self.open_connection(kind, peer_id, address).await;

        Some(())
    }

    /// Opens a new connection that doesn't require a proxy and includes the functionalities of create_outbound_connection.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn open_non_proxy_connection(
        kind: ConnectionKind,
        peer_id: usize,
        address: LocalAddress,
        requests_rx: UnboundedReceiver<NodeRequest>,
        peer_id_count: u32,
        mempool: Arc<RwLock<Mempool>>,
        network: bitcoin::Network,
        node_tx: UnboundedSender<NodeNotification>,
        user_agent: String,
    ) -> Result<(), WireError> {
        let address = (address.get_net_address(), address.get_port());
        let stream = TcpStream::connect(address).await?;

        stream.set_nodelay(true)?;
        let (reader, writer) = tokio::io::split(stream);

        let (actor_receiver, actor) = create_tcp_stream_actor(reader);
        tokio::spawn(async move {
            let _ = actor.run().await;
        });

        // Use create_peer function instead of manually creating the peer
        Peer::<WriteHalf>::create_peer(
            peer_id_count,
            mempool,
            network,
            node_tx.clone(),
            requests_rx,
            peer_id,
            kind,
            actor_receiver,
            writer,
            user_agent,
        )
        .await;

        Ok(())
    }
    /// Opens a connection through a socks5 interface
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn open_proxy_connection(
        proxy: SocketAddr,
        kind: ConnectionKind,
        mempool: Arc<RwLock<Mempool>>,
        network: bitcoin::Network,
        node_tx: UnboundedSender<NodeNotification>,
        peer_id: usize,
        address: LocalAddress,
        requests_rx: UnboundedReceiver<NodeRequest>,
        peer_id_count: u32,
        user_agent: String,
    ) -> Result<(), Socks5Error> {
        let addr = match address.get_address() {
            AddrV2::Cjdns(addr) => Socks5Addr::Ipv6(addr),
            AddrV2::I2p(addr) => Socks5Addr::Domain(addr.into()),
            AddrV2::Ipv4(addr) => Socks5Addr::Ipv4(addr),
            AddrV2::Ipv6(addr) => Socks5Addr::Ipv6(addr),
            AddrV2::TorV2(addr) => Socks5Addr::Domain(addr.into()),
            AddrV2::TorV3(addr) => Socks5Addr::Domain(addr.into()),
            AddrV2::Unknown(_, _) => {
                return Err(Socks5Error::InvalidAddress);
            }
        };

        let proxy = TcpStream::connect(proxy).await?;
        let stream = Socks5StreamBuilder::connect(proxy, addr, address.get_port()).await?;
        let (reader, writer) = tokio::io::split(stream);
        let (actor_receiver, actor) = create_tcp_stream_actor(reader);
        tokio::spawn(async move {
            let _ = actor.run().await;
        });

        Peer::<WriteHalf>::create_peer(
            peer_id_count,
            mempool,
            network,
            node_tx,
            requests_rx,
            peer_id,
            kind,
            actor_receiver,
            writer,
            user_agent,
        )
        .await;
        Ok(())
    }

    /// Creates a new outgoing connection with `address`. Connection may or may not be feeler,
    /// a special connection type that is used to learn about good peers, but are not kept afer
    /// handshake.
    pub(crate) async fn open_connection(
        &mut self,
        kind: ConnectionKind,
        peer_id: usize,
        address: LocalAddress,
    ) {
        let (requests_tx, requests_rx) = unbounded_channel();
        if let Some(ref proxy) = self.socks5 {
            spawn(timeout(
                Duration::from_secs(10),
                Self::open_proxy_connection(
                    proxy.address,
                    kind,
                    self.mempool.clone(),
                    self.network.into(),
                    self.node_tx.clone(),
                    peer_id,
                    address.clone(),
                    requests_rx,
                    self.peer_id_count,
                    self.config.user_agent.clone(),
                ),
            ));
        } else {
            spawn(timeout(
                Duration::from_secs(10),
                Self::open_non_proxy_connection(
                    kind,
                    peer_id,
                    address.clone(),
                    requests_rx,
                    self.peer_id_count,
                    self.mempool.clone(),
                    self.network.into(),
                    self.node_tx.clone(),
                    self.config.user_agent.clone(),
                ),
            ));
        }

        let peer_count: u32 = self.peer_id_count;

        self.inflight.insert(
            InflightRequests::Connect(peer_count),
            (peer_count, Instant::now()),
        );

        self.peers.insert(
            peer_count,
            LocalPeerView {
                address: address.get_net_address(),
                port: address.get_port(),
                user_agent: "".to_string(),
                state: PeerStatus::Awaiting,
                channel: requests_tx,
                services: ServiceFlags::NONE,
                _last_message: Instant::now(),
                kind,
                address_id: peer_id as u32,
                height: 0,
                banscore: 0,
            },
        );

        self.peer_id_count += 1;
    }
}

/// Run a task and log any errors that might occur.
macro_rules! try_and_log {
    ($what:expr) => {
        let result = $what;

        if let Err(error) = result {
            log::error!("{}:{} - {:?}", line!(), file!(), error);
        }
    };
}
macro_rules! periodic_job {
    ($what:expr, $timer:expr, $interval:ident, $context:ty) => {
        if $timer.elapsed() > Duration::from_secs(<$context>::$interval) {
            try_and_log!($what);
            $timer = Instant::now();
        }
    };
    ($what:expr, $timer:expr, $interval:ident, $context:ty, $no_log:literal) => {
        if $timer.elapsed() > Duration::from_secs(<$context>::$interval) {
            $what;
            $timer = Instant::now();
        }
    };
}
pub(crate) use periodic_job;
pub(crate) use try_and_log;
