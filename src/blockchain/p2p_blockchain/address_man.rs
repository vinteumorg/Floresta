use bitcoin::network::{
    address::{AddrV2, AddrV2Message},
    constants::ServiceFlags,
};
use serde::Deserialize;
use std::{
    net::{IpAddr, Ipv4Addr},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub enum AddressState {
    /// We never tried this peer before, so we don't know what to expect
    NeverTried,
    /// We tried this peer before, and had success at least once, so we know what to expect
    Tried,
    /// This peer misbehaved and we banned them
    Banned,
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
    services: Option<ServiceFlags>,
    /// Network port this peers listens to
    port: u16,
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
            services: None,
            port: 8333,
        }
    }
}
impl From<AddrV2Message> for LocalAddress {
    fn from(value: AddrV2Message) -> Self {
        LocalAddress {
            address: value.addr,
            last_connected: value.time.into(),
            state: AddressState::NeverTried,
            services: Some(value.services),
            port: value.port,
        }
    }
}
impl TryFrom<&str> for LocalAddress {
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let split = value.split(":").collect::<Vec<_>>();
        let address = split[0].parse::<Ipv4Addr>().unwrap();
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
            None,
            port,
        ))
    }

    type Error = crate::error::Error;
}

impl LocalAddress {
    pub fn new(
        address: AddrV2,
        last_connected: u64,
        state: AddressState,
        services: Option<ServiceFlags>,
        port: u16,
    ) -> LocalAddress {
        LocalAddress {
            address,
            last_connected,
            state,
            services,
            port,
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
    addresses: Vec<LocalAddress>,
}
impl AddressMan {
    /// Add a new address to our list of known address
    pub fn push_addresses(&mut self, addresses: &[LocalAddress]) {
        self.addresses.extend(addresses.iter().cloned());
    }
    /// Returns a new random address to open a new connection, we try to get addresses with
    /// a set of features supported for our peers
    pub fn get_address_to_connect(
        &mut self,
        features: ServiceFlags,
    ) -> Option<(usize, LocalAddress)> {
        if self.addresses.is_empty() {
            return None;
        }
        // try at most 10 times
        for _ in 0..10 {
            let idx = rand::random::<usize>() % self.addresses.len();
            let address = self
                .addresses
                .get(idx)
                .expect("index in 0 <= n <= addresses.len() should exist");
            if address.state == AddressState::Connected || address.state == AddressState::Banned {
                continue;
            }
            if address.services.is_none() || address.services.unwrap().has(features) {
                return Some((idx, address.to_owned()));
            }
        }
        None
    }
    /// Updates the state of an address
    pub fn update_set_state(&mut self, idx: usize, state: AddressState) {
        self.addresses.get_mut(idx).unwrap().state = state;
    }
    /// Updates the service flags after we receive a version message
    pub fn _update_add_service_flag(&mut self, idx: usize, flags: ServiceFlags) {
        self.addresses.get_mut(idx).unwrap().services = Some(flags);
    }
}
