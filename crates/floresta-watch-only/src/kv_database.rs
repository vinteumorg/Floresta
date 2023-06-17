use crate::WatchOnlyError;

use super::{AddressCacheDatabase, Stats};
use anyhow::Result;
use bitcoin::{
    consensus::{deserialize, serialize},
    hashes::Hash,
    Txid,
};
use kv::{Bucket, Config, Store};

pub struct KvDatabase(Store, Bucket<'static, String, Vec<u8>>);
impl KvDatabase {
    pub fn new(datadir: String) -> Result<KvDatabase, kv::Error> {
        // Configure the database
        let cfg = Config::new(datadir);

        // Open the key/value store
        let store = Store::new(cfg)?;
        let bucket = store.bucket::<String, Vec<u8>>(Some("addresses"))?;
        Ok(KvDatabase(store, bucket))
    }
}
impl AddressCacheDatabase for KvDatabase {
    fn load(&self) -> Result<Vec<super::CachedAddress>> {
        let mut addresses = vec![];
        for item in self.1.iter() {
            let item = item?;
            let key = item.key::<String>()?;
            if *"height" == key || *"desc" == key {
                continue;
            }
            let value: Vec<u8> = item.value().unwrap();
            let value = serde_json::from_slice(&value)?;
            addresses.push(value);
        }
        Ok(addresses)
    }
    fn save(&self, address: &super::CachedAddress) {
        let key = address.script_hash.to_string();
        let value = serde_json::to_vec(&address).expect("Invalid object serialization");

        self.1
            .set(&key, &value)
            .expect("Fatal: Database isn't working");
        self.1.flush().expect("Could not write to disk");
    }
    fn update(&self, address: &super::CachedAddress) {
        self.save(address);
    }
    fn get_cache_height(&self) -> Result<u32> {
        let height = self.1.get(&"height".to_string())?;
        if let Some(height) = height {
            return Ok(deserialize(&height)?);
        }
        Err(anyhow::Error::new(WatchOnlyError::WalletNotInitialized))
    }
    fn set_cache_height(&self, height: u32) -> Result<()> {
        self.1.set(&"height".to_string(), &serialize(&height))?;
        self.1.flush()?;
        Ok(())
    }

    fn desc_save(&self, descriptor: &str) -> Result<()> {
        let mut descs = self.descs_get()?;
        descs.push(descriptor.to_string());
        self.1
            .set(&"desc".to_string(), &serde_json::to_vec(&descs).unwrap())?;
        self.1.flush()?;

        Ok(())
    }

    fn descs_get(&self) -> Result<Vec<String>> {
        let res = self.1.get(&"desc".to_string())?;
        if let Some(res) = res {
            return Ok(serde_json::de::from_slice(&res)?);
        }
        Ok(vec![])
    }

    fn get_transaction(&self, txid: &bitcoin::Txid) -> Result<super::CachedTransaction> {
        let store = self.0.bucket::<&[u8], Vec<u8>>(Some("transactions"))?;
        let res = store.get(&txid.to_vec().as_slice())?;
        if let Some(res) = res {
            return Ok(serde_json::de::from_slice(&res)?);
        }
        Err(WatchOnlyError::TransactionNotFound.into())
    }

    fn save_transaction(&self, tx: &super::CachedTransaction) -> Result<()> {
        let store = self.0.bucket::<&[u8], Vec<u8>>(Some("transactions"))?;
        let ser_tx = serde_json::to_vec(&tx)?;
        store.set(&tx.tx.txid().to_vec().as_slice(), &ser_tx)?;
        self.1.flush()?;

        Ok(())
    }

    fn get_stats(&self) -> Result<super::Stats> {
        let store = self.0.bucket::<&[u8], Vec<u8>>(Some("stats"))?;
        let res = store.get(&"stats".to_string().as_bytes())?;
        if let Some(res) = res {
            return Ok(serde_json::de::from_slice(&res)?);
        }
        Err(WatchOnlyError::TransactionNotFound.into())
    }

    fn save_stats(&self, stats: &Stats) -> Result<()> {
        let store = self.0.bucket::<&[u8], Vec<u8>>(Some("stats"))?;
        let ser_stats = serde_json::to_vec(&stats)?;
        store.set(&"stats".to_string().as_bytes(), &ser_stats)?;
        self.1.flush()?;

        Ok(())
    }

    fn list_transactions(&self) -> Result<Vec<bitcoin::Txid>> {
        let mut transactions = vec![];
        let store = self.0.bucket::<&[u8], Vec<u8>>(Some("transactions"))?;

        for item in store.iter() {
            let item = item?;
            let key = item.key::<&[u8]>()?;
            transactions.push(Txid::from_slice(key).unwrap());
        }
        Ok(transactions)
    }
}
