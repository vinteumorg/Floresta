//! An in-memory database to store addresses data. Being in-memory means this database is
//! volatile, and all data is lost after the database is dropped or the process is terminated.
//! It's not meant to use in production, but for the integrated testing framework
//!
//! For actual databases that can be used for production code, see [KvDatabase].
use super::{AddressCacheDatabase, CachedAddress, CachedTransaction, Stats};

use bitcoin::{hashes::sha256, Txid};
use std::{collections::HashMap, sync::RwLock};
use thiserror::Error;
#[derive(Debug, Default)]
struct Inner {
    addresses: HashMap<sha256::Hash, CachedAddress>,
    transactions: HashMap<Txid, CachedTransaction>,
    stats: Stats,
    height: u32,
    descriptors: Vec<String>,
}
#[derive(Debug, Error)]
pub enum MemoryDatabaseError {
    #[error("Lock poisoned")]
    PoisonedLock,
}
#[derive(Debug, Default)]
pub struct MemoryDatabase {
    inner: RwLock<Inner>,
}
impl MemoryDatabase {
    fn get_inner(&self) -> Result<std::sync::RwLockReadGuard<Inner>, MemoryDatabaseError> {
        self.inner
            .read()
            .map_err(|_| MemoryDatabaseError::PoisonedLock)
    }
    fn get_inner_mut(&self) -> Result<std::sync::RwLockWriteGuard<Inner>, MemoryDatabaseError> {
        self.inner
            .write()
            .map_err(|_| MemoryDatabaseError::PoisonedLock)
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

    fn load(&self) -> anyhow::Result<Vec<CachedAddress>> {
        Ok(self.get_inner()?.addresses.values().cloned().collect())
    }

    fn get_stats(&self) -> anyhow::Result<super::Stats> {
        Ok(self.get_inner()?.stats.to_owned())
    }

    fn save_stats(&self, stats: &super::Stats) -> anyhow::Result<()> {
        self.get_inner_mut().map(|mut inner| {
            inner.stats.clone_from(stats);
        })?;
        anyhow::Ok(())
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

    fn get_cache_height(&self) -> anyhow::Result<u32> {
        Ok(self.get_inner()?.height)
    }

    fn set_cache_height(&self, height: u32) -> anyhow::Result<()> {
        self.get_inner_mut()?.height = height;
        Ok(())
    }

    fn desc_save(&self, descriptor: &str) -> anyhow::Result<()> {
        anyhow::Ok(self.get_inner_mut().map(|mut inner| {
            inner.descriptors.push(descriptor.into());
        })?)
    }

    fn descs_get(&self) -> anyhow::Result<Vec<String>> {
        Ok(self.get_inner()?.descriptors.to_owned())
    }

    fn get_transaction(&self, txid: &bitcoin::Txid) -> anyhow::Result<super::CachedTransaction> {
        if let Some(tx) = self.get_inner()?.transactions.get(txid) {
            return anyhow::Ok(tx.clone());
        }
        Err(MemoryDatabaseError::PoisonedLock.into())
    }

    fn save_transaction(&self, tx: &super::CachedTransaction) -> anyhow::Result<()> {
        self.get_inner_mut()?
            .transactions
            .insert(tx.hash, tx.to_owned());
        anyhow::Ok(())
    }

    fn list_transactions(&self) -> anyhow::Result<Vec<Txid>> {
        Ok(self.get_inner()?.transactions.keys().copied().collect())
    }

    fn list_transactions(&self) -> Result<Vec<Txid>, crate::error::Error> {
        Ok(self.get_inner()?.transactions.keys().copied().collect())
    }
}
