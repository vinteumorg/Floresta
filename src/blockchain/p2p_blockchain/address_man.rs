use async_std::net::ToSocketAddrs;
use bitcoin::network::{
    address::{AddrV2, AddrV2Message},
    constants::ServiceFlags,
};
use serde::Deserialize;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub enum AddressState {
    NeverTried,
    Tried,
    Banned,
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
            port.parse().unwrap_or(38333)
        } else {
            38333
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
#[derive(Debug, Clone, PartialEq)]
pub struct LocalAddress {
    address: AddrV2,
    last_connected: u64,
    state: AddressState,
    services: Option<ServiceFlags>,
    port: u16,
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
    pub fn get_port(&self) -> u16 {
        self.port
    }
    pub fn get_net_address(&self) -> IpAddr {
        match self.address {
            /// IPV4
            AddrV2::Ipv4(ipv4) => IpAddr::V4(ipv4),
            /// IPV6
            AddrV2::Ipv6(ipv6) => IpAddr::V6(ipv6),
            _ => IpAddr::V4(Ipv4Addr::LOCALHOST),
        }
    }
}
#[derive(Default)]
pub struct AddressMan {
    addresses: Vec<LocalAddress>,
}
impl AddressMan {
    pub fn push_addresses(&mut self, addresses: &[LocalAddress]) {
        self.addresses.extend(addresses.iter().cloned());
    }
    pub fn get_address_to_connect(&mut self, features: ServiceFlags) -> Option<LocalAddress> {
        if self.addresses.is_empty() {
            return None;
        }
        // try at most 10 times
        for _ in 0..10 {
            let idx = rand::random::<usize>() % self.addresses.len();
            let address = self.addresses.remove(idx);
            if address.services.is_none() || address.services.unwrap().has(features) {
                return Some(address.to_owned());
            }
            self.addresses.push(address);
        }
        None
    }
    pub fn update_set_state(&mut self, address: LocalAddress, state: AddressState) {
        let address = self.addresses.iter().position(|addr| *addr == address);
        if let Some(address) = address {
            self.addresses.get_mut(address).unwrap().state = state;
        }
    }
    pub fn update_add_service_flag(&mut self, address: LocalAddress, flags: ServiceFlags) {
        let address = self.addresses.iter().position(|addr| *addr == address);
        if let Some(address) = address {
            self.addresses.get_mut(address).unwrap().services = Some(flags);
        }
    }
}
