// Written in 2022 by Davidson Souza

//! This is a basic kv database that stores all metadata about our blockchain and utreexo
//! state.
//! Author: Davidson Souza

use kv::{Config, Store};
pub trait ChainStore {
    /// Saves the current state of our accumulator.
    fn save_roots(&self, roots: String) -> Result<(), kv::Error>;
    /// Loads the state of our accumulator.
    fn load_roots(&self) -> Result<Option<String>, kv::Error>;
}

pub struct KvChainStore(Store);
impl KvChainStore {
    pub fn new(datadir: String) -> Result<KvChainStore, kv::Error> {
        // Configure the database
        let cfg = Config::new(datadir + "/chaindata");

        // Open the key/value store
        let store = Store::new(cfg)?;
        Ok(KvChainStore(store))
    }
}
impl ChainStore for KvChainStore {
    fn load_roots(&self) -> Result<Option<String>, kv::Error> {
        let bucket = self.0.bucket::<&str, String>(Some("addresses"))?;
        bucket.get(&"roots")
    }
    fn save_roots(&self, roots: String) -> Result<(), kv::Error> {
        let bucket = self.0.bucket::<&str, String>(Some("addresses"))?;
        bucket.set(&"roots", &roots)?;
        bucket.flush()?;
        Ok(())
    }
}
