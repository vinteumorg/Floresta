use super::{AddressCacheDatabase, CachedAddress};
use bitcoin::hashes::hex::ToHex;
use kv::{Bucket, Config, Store};

pub struct KvDatabase(Store, Bucket<'static, String, String>);
impl<'a> KvDatabase {
    pub fn new(datadir: String) -> Result<KvDatabase, kv::Error> {
        // Configure the database
        let cfg = Config::new(datadir);

        // Open the key/value store
        let store = Store::new(cfg)?;
        let bucket = store.bucket::<String, String>(Some("addresses"))?;
        Ok(KvDatabase(store, bucket))
    }
}
impl<'a> AddressCacheDatabase for KvDatabase {
    fn load<E>(&self) -> Result<Vec<super::CachedAddress>, E> {
        let mut addresses = vec![];
        while let Some(Ok(item)) = self.1.iter().next() {
            let value: String = item.value().unwrap();
            let value = CachedAddress::from(value);
            addresses.push(value);
        }
        Ok(addresses)
    }
    fn save(&self, address: &super::CachedAddress) {
        let key = address.script_hash.to_string();
        let mut transactions = String::new();
        for transaction in address.transactions.iter() {
            let tx = transaction.to_string() + ":";
            transactions.extend(tx.chars().into_iter());
        }
        let value = format!(
            "{}:{}:{}:{transactions}",
            address.script_hash,
            address.balance,
            address.script.to_hex()
        );

        self.1
            .set(&key, &value)
            .expect("Fatal: Database isn't working");
    }
    fn update(&self, address: &super::CachedAddress) {
        self.save(address);
    }
    fn get_cache_height(&self) -> Result<u32, crate::error::Error> {
        self.0.bucket::<String, String>(Some("meta"))?;
        let height = self.1.get(&"height".to_string())?;
        if let Some(height) = height {
            return Ok(height.parse::<u32>().unwrap_or(0));
        }
        Err(crate::error::Error::WalletNotInitialized)
    }
    fn set_cache_height(&self, height: u32) -> Result<(), crate::error::Error> {
        self.0.bucket::<String, String>(Some("meta"))?;
        self.1.set(&"height".to_string(), &height.to_string())?;
        Ok(())
    }
}
