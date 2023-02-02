use bitcoin::network::{address::AddrV2, constants::ServiceFlags};
use std::time::Instant;

#[derive(Debug, Clone, PartialEq)]
pub enum AddressState {
    NeverTried,
    Tried,
    Banned,
}
impl From<AddrV2> for LocalAddress {
    fn from(value: AddrV2) -> Self {
        LocalAddress {
            address: value,
            last_connected: Instant::now(),
            state: AddressState::NeverTried,
            services: None,
        }
    }
}
#[derive(Debug, Clone, PartialEq)]
pub struct LocalAddress {
    address: AddrV2,
    last_connected: Instant,
    state: AddressState,
    services: Option<ServiceFlags>,
}
impl LocalAddress {
    pub fn new(
        address: AddrV2,
        last_connected: Instant,
        state: AddressState,
        services: Option<ServiceFlags>,
    ) -> LocalAddress {
        LocalAddress {
            address,
            last_connected,
            state,
            services,
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
    pub fn get_address_to_connect(&self, features: ServiceFlags) -> Option<LocalAddress> {
        // try at most 10 times
        for _ in 0..10 {
            let idx = rand::random::<usize>() % self.addresses.len();
            let address = self.addresses.get(idx).unwrap();
            if address.services.unwrap_or(ServiceFlags::NONE).has(features) {
                return Some(address.to_owned());
            }
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
