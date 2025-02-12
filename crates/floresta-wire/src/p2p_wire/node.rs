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
use floresta_common::FractionAvg;
use floresta_compact_filters::flat_filters_store::FlatFiltersStore;
use floresta_compact_filters::network_filters::NetworkFilters;
use log::debug;
use log::info;
use log::warn;
use serde::Deserialize;
use serde::Serialize;
use tokio::net::tcp::WriteHalf;
use tokio::spawn;
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::Mutex;
use tokio::time::timeout;

use super::address_man::AddressMan;
use super::address_man::AddressState;
use super::address_man::LocalAddress;
use super::error::AddrParseError;
use super::error::WireError;
use super::mempool::Mempool;
use super::mempool::MempoolProof;
use super::node_context::NodeContext;
use super::node_interface::NodeInterface;
use super::node_interface::PeerInfo;
use super::node_interface::UserRequest;
use super::peer::create_actors;
use super::peer::Peer;
use super::peer::PeerMessages;
use super::peer::Version;
use super::running_node::RunningNode;
use super::socks::Socks5StreamBuilder;
use super::transport;
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
                requests: std::sync::Mutex::new(Vec::new()),
            }),
            last_invs: HashMap::default(),
            inflight_filters: BTreeMap::new(),
        }
    }
}

pub struct NodeCommon<Chain: BlockchainInterface + UpdatableChainstate> {
    // 1. Core Blockchain and Transient Data
    pub(crate) chain: Chain,
    pub(crate) blocks: HashMap<BlockHash, (PeerId, UtreexoBlock)>,
    pub(crate) mempool: Arc<tokio::sync::Mutex<Mempool>>,
    pub(crate) block_filters: Option<Arc<NetworkFilters<FlatFiltersStore>>>,
    pub(crate) last_filter: BlockHash,

    // 2. Peer Management
    pub(crate) peer_id_count: u32,
    pub(crate) peer_ids: Vec<u32>,
    pub(crate) peers: HashMap<u32, LocalPeerView>,
    pub(crate) peer_by_service: HashMap<ServiceFlags, Vec<u32>>,
    pub(crate) max_banscore: u32,
    pub(crate) address_man: AddressMan,

    // 3. Internal Communication
    pub(crate) node_rx: UnboundedReceiver<NodeNotification>,
    pub(crate) node_tx: UnboundedSender<NodeNotification>,

    // 4. Networking Configuration
    pub(crate) socks5: Option<Socks5StreamBuilder>,
    pub(crate) fixed_peer: Option<LocalAddress>,

    // 5. Time and Event Tracking
    pub(crate) inflight: HashMap<InflightRequests, (u32, Instant)>,
    pub(crate) last_headers_request: Instant,
    pub(crate) last_tip_update: Instant,
    pub(crate) last_connection: Instant,
    pub(crate) last_peer_db_dump: Instant,
    pub(crate) last_block_request: u32,
    pub(crate) last_get_address_request: Instant,
    pub(crate) last_broadcast: Instant,
    pub(crate) last_send_addresses: Instant,
    pub(crate) block_sync_avg: FractionAvg,

    // 6. Configuration and Metadata
    pub(crate) config: UtreexoNodeConfig,
    pub(crate) datadir: String,
    pub(crate) network: Network,
}

pub struct UtreexoNode<Chain: BlockchainInterface + UpdatableChainstate, Context> {
    pub(crate) common: NodeCommon<Chain>,
    pub(crate) context: Context,
}

impl<Chain: BlockchainInterface + UpdatableChainstate, T> Deref for UtreexoNode<Chain, T> {
    fn deref(&self) -> &Self::Target {
        &self.common
    }
    type Target = NodeCommon<Chain>;
}

impl<T, Chain: BlockchainInterface + UpdatableChainstate> DerefMut for UtreexoNode<Chain, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

#[derive(Debug, PartialEq, Clone, Copy, Deserialize, Serialize)]
pub enum PeerStatus {
    Awaiting,
    Ready,
    Banned,
}

impl<T, Chain> UtreexoNode<Chain, T>
where
    T: 'static + Default + NodeContext,
    WireError: From<<Chain as BlockchainInterface>::Error>,
    Chain: BlockchainInterface + UpdatableChainstate + 'static,
{
    pub fn new(
        config: UtreexoNodeConfig,
        chain: Chain,
        mempool: Arc<Mutex<Mempool>>,
        block_filters: Option<Arc<NetworkFilters<FlatFiltersStore>>>,
    ) -> Result<Self, WireError> {
        let (node_tx, node_rx) = unbounded_channel();
        let socks5 = config.proxy.map(Socks5StreamBuilder::new);

        let fixed_peer = config
            .fixed_peer
            .as_ref()
            .map(|address| {
                Self::resolve_connect_host(address, Self::get_port(config.network.into()))
            })
            .transpose()?;

        Ok(UtreexoNode {
            common: NodeCommon {
                block_sync_avg: FractionAvg::new(0, 0),
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
                fixed_peer,
                config,
            },
            context: T::default(),
        })
    }

    fn get_port(network: Network) -> u16 {
        match network {
            Network::Bitcoin => 8333,
            Network::Signet => 38333,
            Network::Testnet => 18333,
            Network::Regtest => 18444,
        }
    }

    #[cfg(feature = "metrics")]
    /// Register a message on `self.inflights` hooking it to metrics
    pub(crate) fn register_message_time(&self, notification: &NodeNotification) -> Option<()> {
        use metrics::get_metrics;
        let now = Instant::now();
        let NodeNotification::FromPeer(peer, message) = notification;

        let when = match message {
            PeerMessages::Block(block) => {
                let inflight = self
                    .inflight
                    .get(&InflightRequests::Blocks(block.block.block_hash()))?;

                inflight.1
            }

            PeerMessages::Ready(_) => {
                let inflight = self.inflight.get(&InflightRequests::Connect(*peer))?;
                inflight.1
            }

            PeerMessages::Headers(_) => {
                let inflight = self.inflight.get(&InflightRequests::Headers)?;
                inflight.1
            }

            PeerMessages::BlockFilter((_, _)) => {
                let inflight = self.inflight.get(&InflightRequests::GetFilters)?;
                inflight.1
            }

            PeerMessages::UtreexoState(_) => {
                let inflight = self.inflight.get(&InflightRequests::UtreexoState(*peer))?;
                inflight.1
            }

            _ => return None,
        };

        let metrics = get_metrics();
        let elapsed = now.duration_since(when).as_secs_f64();
        metrics.message_times.observe(elapsed);
        Some(())
    }

    /// Resolves a string address into a LocalAddress
    ///
    /// This function should get an address in the format `<address>[<:port>]` and return a
    /// usable [`LocalAddress`]. It can be an ipv4, ipv6 or a hostname. In case of hostnames,
    /// we resolve them using the system's DNS resolver and return an ip address. Errors if
    /// the provided address is invalid, or we can't resolve it.
    ///
    /// TODO: Allow for non-clearnet addresses like onion services and i2p.
    fn resolve_connect_host(
        address: &str,
        default_port: u16,
    ) -> Result<LocalAddress, AddrParseError> {
        // ipv6
        if address.starts_with('[') {
            if !address.contains(']') {
                return Err(AddrParseError::InvalidIpv6);
            }

            let mut split = address.trim_end().split(']');
            let hostname = split.next().ok_or(AddrParseError::InvalidIpv6)?;
            let port = split
                .next()
                .filter(|x| !x.is_empty())
                .map(|port| {
                    port.trim_start_matches(':')
                        .parse()
                        .map_err(|_e| AddrParseError::InvalidPort)
                })
                .transpose()?
                .unwrap_or(default_port);

            let hostname = hostname.trim_start_matches('[');
            let ip = hostname.parse().map_err(|_e| AddrParseError::InvalidIpv6)?;
            return Ok(LocalAddress::new(
                AddrV2::Ipv6(ip),
                0,
                AddressState::NeverTried,
                ServiceFlags::NONE,
                port,
                rand::random(),
            ));
        }

        // ipv4 - it's hard to differentiate between ipv4 and hostname without an actual regex
        // simply try to parse it as an ip address and if it fails, assume it's a hostname

        // this breake the necessity of feature gate on windows
        let mut address = address;
        if address.is_empty() {
            address = "127.0.0.1"
        }

        let mut split = address.split(':');
        let ip = split
            .next()
            .ok_or(AddrParseError::InvalidIpv4)?
            .parse()
            .map_err(|_e| AddrParseError::InvalidIpv4);

        match ip {
            Ok(ip) => {
                let port = split
                    .next()
                    .map(|port| port.parse().map_err(|_e| AddrParseError::InvalidPort))
                    .transpose()?
                    .unwrap_or(default_port);

                if split.next().is_some() {
                    return Err(AddrParseError::Inconclusive);
                }

                let id = rand::random();
                Ok(LocalAddress::new(
                    AddrV2::Ipv4(ip),
                    0,
                    AddressState::NeverTried,
                    ServiceFlags::NONE,
                    port,
                    id,
                ))
            }

            Err(_) => {
                let mut split = address.split(':');
                let hostname = split.next().ok_or(AddrParseError::InvalidHostname)?;
                let port = split
                    .next()
                    .map(|port| port.parse().map_err(|_e| AddrParseError::InvalidPort))
                    .transpose()?
                    .unwrap_or(default_port);

                if split.next().is_some() {
                    return Err(AddrParseError::Inconclusive);
                }

                let ip = dns_lookup::lookup_host(hostname)
                    .map_err(|_e| AddrParseError::InvalidHostname)?;
                let id = rand::random();
                let ip = match ip[0] {
                    std::net::IpAddr::V4(ip) => AddrV2::Ipv4(ip),
                    std::net::IpAddr::V6(ip) => AddrV2::Ipv6(ip),
                };

                Ok(LocalAddress::new(
                    ip,
                    0,
                    AddressState::NeverTried,
                    ServiceFlags::NONE,
                    port,
                    id,
                ))
            }
        }
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

    #[cfg(feature = "metrics")]
    pub(crate) fn update_peer_metrics(&self) {
        use metrics::get_metrics;

        let metrics = get_metrics();
        metrics.peer_count.set(self.peer_ids.len() as f64);
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

        #[cfg(feature = "metrics")]
        self.update_peer_metrics();

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

        if let Some(peer_data) = self.common.peers.get_mut(&peer) {
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
                self.common
                    .peer_by_service
                    .entry(service_flags::UTREEXO.into())
                    .or_default()
                    .push(peer);
            }

            if peer_data.services.has(ServiceFlags::COMPACT_FILTERS) {
                self.common
                    .peer_by_service
                    .entry(ServiceFlags::COMPACT_FILTERS)
                    .or_default()
                    .push(peer);
            }

            if peer_data.services.has(ServiceFlags::from(1 << 25)) {
                self.common
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

        #[cfg(feature = "metrics")]
        self.update_peer_metrics();
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

    /// Increases the "banscore" of a peer.
    ///
    /// This is a always increasing number that, if reaches our `max_banscore` setting,
    /// will cause our peer to be banned for one BANTIME.
    /// The amount of each increment is given by factor, and it's calibrated for each misbehaving
    /// action that a peer may incur in.
    pub(crate) async fn increase_banscore(
        &mut self,
        peer_id: u32,
        factor: u32,
    ) -> Result<(), WireError> {
        let Some(peer) = self.common.peers.get_mut(&peer_id) else {
            return Ok(());
        };

        peer.banscore += factor;

        // This peer is misbehaving too often, ban it
        let is_missbehaving = peer.banscore >= self.common.max_banscore;
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
        let anchors = self.common.address_man.start_addr_man(
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
        try_and_log!(self.save_utreexo_peers());
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
                let txid = transaction.compute_txid();
                let mut mempool = self.mempool.lock().await;

                if self.network == Network::Regtest {
                    match mempool.try_prove(&transaction, &self.chain) {
                        Ok(proof) => {
                            let MempoolProof {
                                proof,
                                target_hashes,
                                leaves,
                            } = proof;

                            let leaves = transaction
                                .input
                                .iter()
                                .cloned()
                                .map(|input| input.previous_output)
                                .zip(leaves.into_iter())
                                .collect::<Vec<_>>();

                            let targets = proof.targets.clone();
                            try_and_log!(mempool.accept_to_mempool(
                                transaction,
                                proof,
                                &leaves,
                                &target_hashes,
                                &targets,
                            ));
                        }
                        Err(e) => {
                            log::error!(
                                "Could not prove tx {} because: {:?}",
                                transaction.compute_txid(),
                                e
                            );
                        }
                    }

                    peer.channel
                        .send(NodeRequest::BroadcastTransaction(txid))
                        .map_err(WireError::ChannelSend)?;
                }

                let stale = self.mempool.lock().await.get_stale();
                for tx in stale {
                    peer.channel
                        .send(NodeRequest::BroadcastTransaction(tx))
                        .map_err(WireError::ChannelSend)?;
                }
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

    /// Saves the utreexo peers to disk so we can reconnect with them later
    pub(crate) fn save_utreexo_peers(&self) -> Result<(), WireError> {
        let peers: &Vec<u32> = self
            .peer_by_service
            .get(&service_flags::UTREEXO.into())
            .ok_or(WireError::NoPeersAvailable)?;
        let peers_usize: Vec<usize> = peers.iter().map(|&peer| peer as usize).collect();
        if peers_usize.is_empty() {
            warn!("No connected utreexo peers to save to disk");
            return Ok(());
        }
        info!("Saving utreexo peers to disk");
        self.address_man
            .dump_utreexo_peers(&self.datadir, &peers_usize)
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
            .context
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
        let required_services = self.context.get_required_services();

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
            .common
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
        mempool: Arc<Mutex<Mempool>>,
        network: bitcoin::Network,
        node_tx: UnboundedSender<NodeNotification>,
        user_agent: String,
        allow_v1_fallback: bool,
    ) -> Result<(), WireError> {
        let address = (address.get_net_address(), address.get_port());

        let (transport_reader, transport_writer) =
            transport::connect(address, network, allow_v1_fallback).await?;

        let (cancellation_sender, cancellation_receiver) = tokio::sync::oneshot::channel();
        let (actor_receiver, actor) = create_actors(transport_reader);
        tokio::spawn(async move {
            tokio::select! {
                _ = cancellation_receiver => {}
                _ = actor.run() => {}
            }
        });

        // Use create_peer function instead of manually creating the peer
        Peer::<WriteHalf>::create_peer(
            peer_id_count,
            mempool,
            node_tx.clone(),
            requests_rx,
            peer_id,
            kind,
            actor_receiver,
            transport_writer,
            user_agent,
            cancellation_sender,
        )
        .await;

        Ok(())
    }
    /// Opens a connection through a socks5 interface
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn open_proxy_connection(
        proxy: SocketAddr,
        kind: ConnectionKind,
        mempool: Arc<Mutex<Mempool>>,
        network: bitcoin::Network,
        node_tx: UnboundedSender<NodeNotification>,
        peer_id: usize,
        address: LocalAddress,
        requests_rx: UnboundedReceiver<NodeRequest>,
        peer_id_count: u32,
        user_agent: String,
        allow_v1_fallback: bool,
    ) -> Result<(), WireError> {
        let (transport_reader, transport_writer) =
            transport::connect_proxy(proxy, address, network, allow_v1_fallback).await?;

        let (cancellation_sender, cancellation_receiver) = tokio::sync::oneshot::channel();
        let (actor_receiver, actor) = create_actors(transport_reader);
        tokio::spawn(async move {
            tokio::select! {
                _ = cancellation_receiver => {}
                _ = actor.run() => {}
            }
        });

        Peer::<WriteHalf>::create_peer(
            peer_id_count,
            mempool,
            node_tx,
            requests_rx,
            peer_id,
            kind,
            actor_receiver,
            transport_writer,
            user_agent,
            cancellation_sender,
        )
        .await;
        Ok(())
    }

    /// Creates a new outgoing connection with `address`. Connection may or may not be feeler,
    /// a special connection type that is used to learn about good peers, but are not kept after
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
                    self.config.allow_v1_fallback,
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
                    self.config.allow_v1_fallback,
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

#[cfg(test)]
mod tests {
    use floresta_chain::pruned_utreexo::partial_chain::PartialChainState;

    use crate::node::UtreexoNode;
    use crate::running_node::RunningNode;

    fn check_address_resolving(address: &str, port: u16, should_succeed: bool, description: &str) {
        let result =
            UtreexoNode::<PartialChainState, RunningNode>::resolve_connect_host(address, port);
        if should_succeed {
            assert!(result.is_ok(), "Failed: {}", description);
        } else {
            assert!(result.is_err(), "Unexpected success: {}", description);
        }
    }

    #[test]
    fn test_parse_address() {
        // IPv6 Tests
        check_address_resolving("[::1]", 8333, true, "Valid IPv6 without port");
        check_address_resolving("[::1", 8333, false, "Invalid IPv6 format");
        check_address_resolving("[::1]:8333", 8333, true, "Valid IPv6 with port");
        check_address_resolving(
            "[::1]:8333:8333",
            8333,
            false,
            "Invalid IPv6 with multiple ports",
        );

        // IPv4 Tests
        check_address_resolving("127.0.0.1", 8333, true, "Valid IPv4 without port");
        check_address_resolving("321.321.321.321", 8333, false, "Invalid IPv4 format");
        check_address_resolving("127.0.0.1:8333", 8333, true, "Valid IPv4 with port");
        check_address_resolving(
            "127.0.0.1:8333:8333",
            8333,
            false,
            "Invalid IPv4 with multiple ports",
        );

        // Hostname Tests
        check_address_resolving("example.com", 8333, true, "Valid hostname without port");
        check_address_resolving("example", 8333, false, "Invalid hostname");
        check_address_resolving("example.com:8333", 8333, true, "Valid hostname with port");
        check_address_resolving(
            "example.com:8333:8333",
            8333,
            false,
            "Invalid hostname with multiple ports",
        );

        // Edge Cases
        // This could fail on windows but doesnt since inside `resolve_connect_host` we specificate empty addresses as localhost for all OS`s.
        check_address_resolving("", 8333, true, "Empty string address");
        check_address_resolving(
            " 127.0.0.1:8333 ",
            8333,
            false,
            "Address with leading/trailing spaces",
        );
        check_address_resolving("127.0.0.1:0", 0, true, "Valid address with port 0");
        check_address_resolving(
            "127.0.0.1:65535",
            65535,
            true,
            "Valid address with maximum port",
        );
        check_address_resolving(
            "127.0.0.1:65536",
            65535,
            false,
            "Valid address with out-of-range port",
        )
    }
}
