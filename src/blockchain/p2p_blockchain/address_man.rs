//! Address manager is a module that keeps track of known peer addresses and associated
//! metadata. This module is very important in keeping our node protected against targeted
//! attacks, like eclipse attacks.

use bitcoin::network::{
    address::{AddrV2, AddrV2Message},
    constants::ServiceFlags,
};
use log::info;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::blockchain::error::BlockchainError;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub enum AddressState {
    /// We never tried this peer before, so we don't know what to expect
    NeverTried,
    /// We tried this peer before, and had success at least once, so we know what to expect
    Tried(u64),
    /// This peer misbehaved and we banned them
    Banned(u64),
    /// We are connected to this peer right now
    Connected,
}
/// How do we store peers locally
#[derive(Debug, Clone, PartialEq)]
pub struct LocalAddress {
    /// An actual address
    address: AddrV2,
    /// Last time we successfully connected to this peer, only relevant is state == State::Tried
    last_connected: u64,
    /// Our local state for this peer, as defined in AddressState
    state: AddressState,
    /// Network services announced by this peer
    services: ServiceFlags,
    /// Network port this peers listens to
    port: u16,
    /// Random id for this peer
    id: usize,
}

impl From<AddrV2> for LocalAddress {
    fn from(value: AddrV2) -> Self {
        LocalAddress {
            address: value,
            last_connected: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            state: AddressState::NeverTried,
            services: ServiceFlags::NONE,
            port: 8333,
            id: rand::random::<usize>(),
        }
    }
}
impl From<AddrV2Message> for LocalAddress {
    fn from(value: AddrV2Message) -> Self {
        LocalAddress {
            address: value.addr,
            last_connected: value.time.into(),
            state: AddressState::NeverTried,
            services: value.services,
            port: value.port,
            id: rand::random::<usize>(),
        }
    }
}
impl TryFrom<&str> for LocalAddress {
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let split = value.split(":").collect::<Vec<_>>();
        let address = split[0].parse::<Ipv4Addr>()?;
        let port = if let Some(port) = split.get(1) {
            port.parse().unwrap_or(8333)
        } else {
            8333
        };
        Ok(LocalAddress::new(
            AddrV2::Ipv4(address),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            super::address_man::AddressState::NeverTried,
            ServiceFlags::NONE,
            port,
            rand::random::<usize>(),
        ))
    }

    type Error = BlockchainError;
}

impl LocalAddress {
    pub fn new(
        address: AddrV2,
        last_connected: u64,
        state: AddressState,
        services: ServiceFlags,
        port: u16,
        id: usize,
    ) -> LocalAddress {
        LocalAddress {
            address,
            last_connected,
            state,
            services,
            port,
            id,
        }
    }
    /// Returns this address's port
    pub fn get_port(&self) -> u16 {
        self.port
    }
    /// Return an IP address associated with this peer address
    pub fn get_net_address(&self) -> IpAddr {
        match self.address {
            // IPV4
            AddrV2::Ipv4(ipv4) => IpAddr::V4(ipv4),
            // IPV6
            AddrV2::Ipv6(ipv6) => IpAddr::V6(ipv6),
            _ => IpAddr::V4(Ipv4Addr::LOCALHOST),
        }
    }
}
/// A module that keeps track of know addresses and serve them to our node to connect
#[derive(Default)]
pub struct AddressMan {
    addresses: HashMap<usize, LocalAddress>,
    good_addresses: Vec<usize>,
    utreexo_addresses: Vec<usize>,
}
impl AddressMan {
    /// Add a new address to our list of known address
    pub fn push_addresses(&mut self, addresses: &[LocalAddress]) {
        for address in addresses {
            let id = address.id;
            if !self.addresses.contains_key(&id) {
                // For now we assume that all addresses are valid, until proven otherwise.
                self.good_addresses.push(id);
                if address.services.has(ServiceFlags::NODE_UTREEXO) {
                    self.utreexo_addresses.push(id);
                }
                self.addresses.insert(id, address.to_owned());
            }
        }
    }
    pub fn get_seeds_from_dns(
        &mut self,
        seed: &str,
        default_port: u16,
    ) -> Result<usize, std::io::Error> {
        let mut addresses = Vec::new();
        for ip in dns_lookup::lookup_host(seed)? {
            if let Ok(ip) = LocalAddress::try_from(format!("{}:{}", ip, default_port).as_str()) {
                addresses.push(ip);
            }
        }
        self.push_addresses(&addresses);
        Ok(addresses.len())
    }
    /// Returns a new random address to open a new connection, we try to get addresses with
    /// a set of features supported for our peers
    pub fn get_address_to_connect(
        &mut self,
        flags: ServiceFlags,
        feeler: bool,
    ) -> Option<(usize, LocalAddress)> {
        if self.addresses.is_empty() {
            return None;
        }
        // Feeler connection are used to test if a peer is still alive, we don't care about
        // the features it supports or even if it's a valid peer. The only thing we care about
        // is that we haven't banned it.
        if feeler {
            let idx = rand::random::<usize>() % self.addresses.len();
            let peer = self.addresses.keys().nth(idx)?;
            let address = self.addresses.get(peer)?.to_owned();
            if let AddressState::Banned(_) = address.state {
                return None;
            }
            return Some((*peer, address));
        }
        if flags.has(ServiceFlags::NODE_UTREEXO) {
            if self.utreexo_addresses.is_empty() {
                return None;
            }
            let idx = rand::random::<usize>() % self.utreexo_addresses.len();
            let utreexo_peer = self.utreexo_addresses.get(idx)?;
            return Some((*utreexo_peer, self.addresses.get(utreexo_peer)?.to_owned()));
        }
        if self.good_addresses.is_empty() {
            return None;
        }
        let idx = rand::random::<usize>() % self.good_addresses.len();
        let good_peer = self.good_addresses.get(idx)?;
        Some((*good_peer, self.addresses.get(good_peer)?.to_owned()))
    }
    pub fn dump_peers(&self, datadir: &str) -> std::io::Result<()> {
        let peers: Vec<_> = self
            .addresses
            .values()
            .cloned()
            .map(|item| Into::<DiskLocalAddress>::into(item))
            .collect::<Vec<_>>();
        let peers = serde_json::to_string(&peers);
        if let Ok(peers) = peers {
            std::fs::write(datadir.to_owned() + "/peers.json", peers)?;
        }
        Ok(())
    }
    pub fn start_addr_man(
        &mut self,
        datadir: String,
        default_port: u16,
        dns_seeds: &[&'static str],
    ) -> Result<(), BlockchainError> {
        let local_db = std::fs::read_to_string(datadir + "/peers.json");
        let peers = if let Ok(peers) = local_db {
            info!("Peers database found, using it");

            serde_json::from_str::<Vec<DiskLocalAddress>>(&peers)
        } else {
            info!("No peers available, using fixed peers");
            let mut peers_from_dns = 0;
            for seed in dns_seeds {
                peers_from_dns += self.get_seeds_from_dns(&seed, default_port)?;
            }
            info!("Got {peers_from_dns} peers from DNS Seeds",);
            let addresses = include_str!("fixed_peers.json");
            serde_json::from_str(addresses)
        };
        if let Ok(peers) = peers {
            let peers = peers
                .iter()
                .cloned()
                .map(|addr| Into::<LocalAddress>::into(addr))
                .collect::<Vec<_>>();
            self.push_addresses(&peers);
        }

        Ok(())
    }

    /// Updates the state of an address
    pub fn update_set_state(&mut self, idx: usize, state: AddressState) {
        match state {
            AddressState::Banned(_) => {
                self.good_addresses.retain(|&x| x != idx);
            }
            AddressState::Tried(_) => {
                if !self.good_addresses.contains(&idx) {
                    self.good_addresses.push(idx);
                }
            }
            AddressState::NeverTried => {
                self.good_addresses.retain(|&x| x != idx);
            }
            AddressState::Connected => {
                if !self.good_addresses.contains(&idx) {
                    self.good_addresses.push(idx);
                }
            }
        }
        if let Some(address) = self.addresses.get_mut(&idx) {
            address.state = state;
        };
    }
    /// Updates the service flags after we receive a version message
    pub fn update_set_service_flag(&mut self, idx: usize, flags: ServiceFlags) {
        if let Some(address) = self.addresses.get_mut(&idx) {
            address.services = flags;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskLocalAddress {
    /// An actual address
    address: Address,
    /// Last time we successfully connected to this peer, only relevant is state == State::Tried
    last_connected: u64,
    /// Our local state for this peer, as defined in AddressState
    state: AddressState,
    /// Network services announced by this peer
    services: u64,
    /// Network port this peers listens to
    port: u16,
    /// An id to identify this address
    id: Option<usize>,
}
impl From<LocalAddress> for DiskLocalAddress {
    fn from(value: LocalAddress) -> Self {
        let address = match value.address {
            AddrV2::Ipv4(ip) => Address::V4(ip),
            AddrV2::Ipv6(ip) => Address::V6(ip),
            _ => {
                unreachable!()
            }
        };

        DiskLocalAddress {
            address,
            last_connected: value.last_connected,
            state: if value.state == AddressState::Connected {
                AddressState::Tried(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                )
            } else {
                value.state
            },
            services: value.services.to_u64(),
            port: value.port,
            id: Some(value.id),
        }
    }
}
impl From<DiskLocalAddress> for LocalAddress {
    fn from(value: DiskLocalAddress) -> Self {
        let address = match value.address {
            Address::V4(ip) => AddrV2::Ipv4(ip),
            Address::V6(ip) => AddrV2::Ipv6(ip),
        };
        let services = ServiceFlags::from(value.services);
        LocalAddress {
            address,
            last_connected: value.last_connected,
            state: value.state,
            services,
            port: value.port,
            id: value.id.unwrap_or_else(|| rand::random::<usize>()),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Address {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}
