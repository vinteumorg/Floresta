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
    fn load_height(&self) -> Result<u32>;
    fn save_height(&self) -> Result<()>;
}

pub struct KvChainStore {
    meta: Store,
    headers: Store,
}
impl KvChainStore {
    pub fn new(datadir: String) -> Result<KvChainStore> {
        // Configure the database
        let meta = Config::new(datadir.clone() + "/meta");
        let cfg_blocks = Config::new(datadir + "/blocks");

        // Open the key/value store
        let meta = Store::new(meta)?;
        let headers = Store::new(cfg_blocks)?;

        Ok(KvChainStore { meta, headers })
    }
}
impl ChainStore for KvChainStore {
    fn load_roots(&self) -> Result<Option<Vec<u8>>> {
        let bucket = self.meta.bucket::<&str, Vec<u8>>(None)?;
        bucket.get(&"roots")
    }
    fn save_roots(&self, roots: Vec<u8>) -> Result<()> {
        let bucket = self.meta.bucket::<&str, Vec<u8>>(None)?;
        bucket.set(&"roots", &roots)?;
        bucket.flush()?;
        Ok(())
    }

    fn load_height(&self) -> Result<u32> {
        todo!()
    }

    fn save_height(&self) -> Result<()> {
        todo!()
    }
}
