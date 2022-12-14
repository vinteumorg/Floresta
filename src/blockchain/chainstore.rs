// Written in 2022 by Davidson Souza

//! This is a basic kv database that stores all metadata about our blockchain and utreexo
//! state.
//! Author: Davidson Souza
type Result<T> = std::result::Result<T, kv::Error>;
use kv::{Config, Store};
pub trait ChainStore {
    /// Saves the current state of our accumulator.
    fn save_roots(&self, roots: Vec<u8>) -> Result<()>;
    /// Loads the state of our accumulator.
    fn load_roots(&self) -> Result<Option<Vec<u8>>>;
    /// Loads the blockchain height
    fn load_height(&self) -> Result<Option<String>>;
    fn save_height(&self, height: String) -> Result<()>;
    fn get_headers(&self) -> Result<Option<Vec<u8>>>;
    fn save_headers(&self, headers: Vec<u8>) -> Result<()>;
}

pub struct KvChainStore(Store);
impl KvChainStore {
    pub fn new(datadir: String) -> Result<KvChainStore> {
        // Configure the database
        let cfg = Config::new(datadir + "/chain_data");

        // Open the key/value store
        let store = Store::new(cfg)?;

        Ok(KvChainStore(store))
    }
}
impl ChainStore for KvChainStore {
    fn load_roots(&self) -> Result<Option<Vec<u8>>> {
        let bucket = self.0.bucket::<&str, Vec<u8>>(None)?;
        bucket.get(&"roots")
    }
    fn save_roots(&self, roots: Vec<u8>) -> Result<()> {
        let bucket = self.0.bucket::<&str, Vec<u8>>(None)?;
        bucket.set(&"roots", &roots)?;
        bucket.flush()?;
        Ok(())
    }

    fn load_height(&self) -> Result<Option<String>> {
        let bucket = self.0.bucket::<&str, String>(None)?;
        bucket.get(&"height")
    }

    fn save_height(&self, height: String) -> Result<()> {
        let bucket = self.0.bucket::<&str, String>(None)?;
        bucket.set(&"height", &height)?;
        bucket.flush()?;
        Ok(())
    }
    fn get_headers(&self) -> Result<Option<Vec<u8>>> {
        let bucket = self.0.bucket::<&str, Vec<u8>>(None)?;
        bucket.get(&"headers")
    }
    fn save_headers(&self, headers: Vec<u8>) -> Result<()> {
        let bucket = self.0.bucket::<&str, Vec<u8>>(None)?;
        bucket.set(&"headers", &headers)?;
        bucket.flush()?;
        Ok(())
    }
}
