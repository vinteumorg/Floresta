use bitcoin::network::{address::AddrV2, constants::ServiceFlags};
use std::time::Instant;

#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct LocalAddress {
    address: AddrV2,
    last_connected: Instant,
    state: AddressState,
    services: Option<ServiceFlags>,
}
#[derive(Default)]
pub struct AddressMan {
    addresses: Vec<LocalAddress>,
}
impl AddressMan {
    pub fn push_addresses(&mut self, addresses: &[LocalAddress]) {
        self.addresses.extend(addresses.iter().cloned());
    }
    pub fn get_address_to_connect(&self) -> LocalAddress {
        let idx = rand::random::<usize>() % self.addresses.len();
        self.addresses.get(idx).unwrap().to_owned()
    }
    pub fn update_set_state(&mut self, address: LocalAddress, state: AddressState) {}
    pub fn update_add_service_flag(&mut self, address: LocalAddress, flags: ServiceFlags) {}
}
