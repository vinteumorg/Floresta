//! An in-memory database to store addresses data. Being in-memory means this database is
//! volatile, and all data is lost after the database is dropped or the process is terminated.
//! It's not meant to use in production, but for the integrated testing framework
//!
//! For actual databases that can be used for production code, see [KvDatabase].
use super::{AddressCacheDatabase, CachedAddress, CachedTransaction, Stats};
use crate::error::Error;

use bitcoin::{hashes::sha256, Txid};
use std::{collections::HashMap, sync::RwLock};
#[derive(Debug, Default)]
struct Inner {
    addresses: HashMap<sha256::Hash, CachedAddress>,
    transactions: HashMap<Txid, CachedTransaction>,
    stats: Stats,
    height: u32,
    descriptors: Vec<String>,
}

pub struct MemoryDatabase {
    inner: RwLock<Inner>,
}
impl MemoryDatabase {
    fn get_inner_mut(&self) -> Result<std::sync::RwLockWriteGuard<Inner>, Error> {
        self.inner.write().map_err(|_| Error::DatabaseError)
    }
    fn get_inner(&self) -> Result<std::sync::RwLockReadGuard<Inner>, Error> {
        self.inner.read().map_err(|_| Error::DatabaseError)
    }
    pub fn new() -> MemoryDatabase {
        MemoryDatabase {
            inner: Default::default(),
        }
    }
}
impl AddressCacheDatabase for MemoryDatabase {
    fn save(&self, address: &CachedAddress) {
        self.get_inner_mut()
            .map(|mut inner| {
                inner
                    .addresses
                    .insert(address.script_hash, address.to_owned())
            })
            .unwrap();
    }

    fn load<E>(&self) -> Result<Vec<CachedAddress>, E>
    where
        E: From<crate::error::Error>
            + Into<crate::error::Error>
            + std::convert::From<kv::Error>
            + std::convert::From<serde_json::Error>,
    {
        Ok(self.get_inner()?.addresses.values().cloned().collect())
    }

    fn get_stats(&self) -> Result<super::Stats, crate::error::Error> {
        Ok(self.get_inner()?.stats.to_owned())
    }

    fn save_stats(&self, stats: &super::Stats) -> Result<(), crate::error::Error> {
        self.get_inner_mut().map(|mut inner| {
            inner.stats.clone_from(stats);
        })
    }

    fn update(&self, address: &super::CachedAddress) {
        self.get_inner_mut()
            .map(|mut inner| {
                inner
                    .addresses
                    .entry(address.script_hash)
                    .and_modify(|addr| *addr = address.to_owned());
            })
            .unwrap();
    }

    fn get_cache_height(&self) -> Result<u32, crate::error::Error> {
        Ok(self.get_inner()?.height)
    }

    fn set_cache_height(&self, height: u32) -> Result<(), crate::error::Error> {
        self.get_inner_mut()?.height = height;
        Ok(())
    }

    fn desc_save(&self, descriptor: &str) -> Result<(), crate::error::Error> {
        self.get_inner_mut().map(|mut inner| {
            inner.descriptors.push(descriptor.into());
        })
    }

    fn descs_get(&self) -> Result<Vec<String>, crate::error::Error> {
        Ok(self.get_inner()?.descriptors.to_owned())
    }

    fn get_transaction(
        &self,
        txid: &bitcoin::Txid,
    ) -> Result<super::CachedTransaction, crate::error::Error> {
        self.get_inner()?
            .transactions
            .get(txid)
            .map_or(Err(Error::TransactionNotFound), |tx| Ok(tx.to_owned()))
    }

    fn save_transaction(&self, tx: &super::CachedTransaction) -> Result<(), crate::error::Error> {
        self.get_inner_mut()
            .map(|mut inner| inner.transactions.insert(tx.hash, tx.to_owned()))
            .map_err(|_| Error::DatabaseError)?;
        Ok(())
    }
}
