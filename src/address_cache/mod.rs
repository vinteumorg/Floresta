pub mod sqlite_storage;
use std::{
    collections::{HashMap, HashSet},
    ops::RangeInclusive,
    vec,
};

use crate::electrum::electrum_protocol::get_spk_hash;
use bitcoin::{
    consensus::deserialize,
    consensus::encode::serialize_hex,
    hash_types::Txid,
    hashes::{
        hex::{FromHex, ToHex},
        sha256::{self, Hash},
    },
    Block, MerkleBlock, Script, Transaction, TxOut,
};
#[derive(Debug, Clone)]
pub struct CachedTransaction {
    pub tx_hex: String,
    pub height: u32,
    pub merkle_block: MerkleBlock,
    pub hash: String,
    pub position: u32,
}
impl std::fmt::Display for CachedTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let merkle_block = serialize_hex(&self.merkle_block);
        write!(f, "{}:{}:{}", self.tx_hex, self.height, merkle_block)
    }
}
impl From<String> for CachedTransaction {
    fn from(transaction: String) -> Self {
        let mut transaction = transaction.split(":");
        let tx_hex = transaction.nth(0).unwrap().to_string();
        let height = transaction.nth(1).unwrap().parse::<u32>().unwrap();
        let merkle_block = Vec::from_hex(transaction.nth(2).unwrap()).unwrap();
        let merkle_block = deserialize(&merkle_block).unwrap();
        let tx = Vec::from_hex(transaction.nth(2).unwrap()).unwrap();
        let tx = deserialize::<Transaction>(&tx).unwrap();

        CachedTransaction {
            tx_hex,
            height,
            merkle_block,
            hash: tx.txid().to_string(),
            position: 0,
        }
    }
}
impl From<String> for CachedAddress {
    /// TODO: Get rid of this unwraps
    fn from(address: String) -> Self {
        let mut address = address.split(":");
        let script_hash = address.next().unwrap().to_string();
        let script_hash = sha256::Hash::from_hex(&script_hash).unwrap();
        let balance = address.next().unwrap().parse::<u64>().unwrap();
        let script = Script::from_hex(address.next().unwrap()).unwrap();

        let mut transactions = vec![];
        for transaction in address {
            let transaction = transaction.to_string();
            let transaction = CachedTransaction::from(transaction);
            transactions.push(transaction);
        }
        CachedAddress {
            balance,
            script_hash,
            transactions,
            script,
        }
    }
}
#[derive(Debug, Clone)]
pub struct CachedAddress {
    script_hash: Hash,
    balance: u64,
    transactions: Vec<CachedTransaction>,
    script: Script,
}

impl CachedAddress {
    pub fn _new(
        script_hash: Hash,
        balance: u64,
        transactions: Vec<CachedTransaction>,
        script: Script,
    ) -> CachedAddress {
        CachedAddress {
            script_hash,
            balance,
            transactions,
            script,
        }
    }
}
pub trait AddressCacheDatabase {
    /// Saves a new address to the database. If the address already exists, `update` should
    /// be used instead
    fn save(&self, address: &CachedAddress);
    /// Loads all addresses we have cached so far
    fn load<E>(&self) -> Result<Vec<CachedAddress>, E>;
    /// Updates an address, probably because a new transaction arrived
    fn update(&self, address: &CachedAddress);
    /// TODO: Maybe turn this into another db
    /// Returns the height of the last block we filtered
    fn get_cache_height(&self) -> Result<u32, crate::error::Error>;
    /// Saves the height of the last block we filtered
    fn set_cache_height(&self, height: u32) -> Result<(), crate::error::Error>;
}
/// Holds all addresses and associated transactions. We need a database with some basic
/// methods, to store all data
pub struct AddressCache<D: AddressCacheDatabase> {
    /// A database that will be used to persist all needed to get our address history
    database: D,
    /// Maps a hash to a cached address struct, this is basically an in-memory version
    /// of our database, used for speeding up processing a block. This hash is the electrum's
    /// script hash.
    address_map: HashMap<Hash, CachedAddress>,
    /// Holds all scripts we are interested in.
    script_set: HashSet<Script>,
    tx_index: HashMap<Txid, (Hash, usize)>,
}
impl<D: AddressCacheDatabase> AddressCache<D> {
    /// Iterates through a block, finds transactions destined to ourselves.
    /// Returns all transactions we found.
    pub fn block_process(&mut self, block: &Block, height: u32) -> Vec<(Transaction, TxOut)> {
        let mut my_transactions = vec![];
        for (position, transaction) in block.txdata.iter().enumerate() {
            for output in transaction.output.iter() {
                if self.script_set.contains(&output.script_pubkey) {
                    my_transactions.push((transaction.clone(), output.clone()));
                    let my_txid = transaction.txid();
                    let merkle_block =
                        MerkleBlock::from_block_with_predicate(block, |txid| *txid == my_txid);
                    self.cache_transaction(
                        transaction,
                        height,
                        output,
                        merkle_block,
                        position as u32,
                    );
                }
            }
        }

        my_transactions
    }
    pub fn new(database: D) -> AddressCache<D> {
        let scripts = database.load::<crate::error::Error>();
        let mut address_map = HashMap::new();
        let mut script_set = HashSet::new();

        if let Ok(scripts) = scripts {
            for address in scripts {
                script_set.insert(address.script.clone());
                address_map.insert(address.script_hash, address);
            }
        }
        AddressCache {
            database,
            address_map,
            script_set,
            tx_index: HashMap::new(),
        }
    }
    fn get_transaction(&self, txid: &Txid) -> Option<CachedTransaction> {
        if let Some((address, idx)) = self.tx_index.get(txid) {
            if let Some(address) = self.address_map.get(address) {
                if let Some(tx) = address.transactions.get(*idx) {
                    return Some(tx.clone());
                }
            }
        }
        None
    }
    /// Returns all transactions this address has, both input and outputs
    pub fn get_address_history(&self, script_hash: &sha256::Hash) -> Vec<CachedTransaction> {
        if let Some(cached_script) = self.address_map.get(script_hash) {
            return cached_script.transactions.clone();
        }
        vec![]
    }
    /// Returns the balance of this address, debts (spends) are taken in account
    pub fn get_address_balance(&self, script_hash: &sha256::Hash) -> u64 {
        if let Some(cached_script) = self.address_map.get(script_hash) {
            return cached_script.balance;
        }

        0
    }
    /// Returns the Merkle Proof for a given address
    pub fn get_merkle_proof(&self, txid: &Txid) -> Option<(Vec<String>, u32)> {
        let mut hashes = vec![];

        if let Some(tx) = self.get_transaction(txid) {
            for hash in tx.merkle_block.txn.hashes() {
                hashes.push(hash.to_hex());
            }
            // Rust Bitcoin (and Bitcoin Core) includes the target hash, but Electrum
            // doesn't like this.
            hashes.pop();
            return Some((hashes, tx.position));
        }

        None
    }
    pub fn get_height(&self, txid: &Txid) -> Option<u32> {
        if let Some(tx) = self.get_transaction(txid) {
            return Some(tx.height);
        }

        None
    }
    pub fn get_sync_limits(
        &self,
        current_hight: u32,
    ) -> Result<RangeInclusive<u32>, crate::error::Error> {
        let hight = self.database.get_cache_height()?;
        Ok(hight..=current_hight)
    }
    pub fn get_cached_transaction(&self, txid: &Txid) -> Option<String> {
        if let Some(tx) = self.get_transaction(txid) {
            return Some(tx.tx_hex);
        }
        None
    }
    pub fn cache_address(&mut self, script_pk: Script) {
        let hash = get_spk_hash(&script_pk);
        let new_address = CachedAddress {
            balance: 0,
            script_hash: hash,
            transactions: vec![],
            script: script_pk.clone(),
        };
        self.database.save(&new_address);

        self.address_map.insert(hash, new_address);
        self.script_set.insert(script_pk);
    }
    pub fn cache_transaction(
        &mut self,
        transaction: &Transaction,
        height: u32,
        out: &TxOut,
        merkle_block: MerkleBlock,
        position: u32,
    ) {
        let transaction_to_cache = CachedTransaction {
            height,
            merkle_block,
            tx_hex: serialize_hex(transaction),
            hash: transaction.txid().to_string(),
            position,
        };
        let hash = get_spk_hash(&out.script_pubkey);
        if let Some(address) = self.address_map.get_mut(&hash) {
            self.tx_index.insert(
                transaction.txid(),
                (address.script_hash, address.transactions.len()),
            );

            address.transactions.push(transaction_to_cache);
            self.database.update(&address);
        } else {
            // This means `cache_transaction` have been called with an address we don't
            // follow. This may be useful for caching new addresses without re-scanning.
            // We can track this address from now onwards, but the past history is only
            // available with full rescan
            let new_address = CachedAddress {
                balance: 0,
                script_hash: hash,
                transactions: vec![transaction_to_cache],
                script: out.script_pubkey.clone(),
            };
            self.database.save(&new_address);

            self.address_map.insert(hash, new_address);
            self.script_set.insert(out.script_pubkey.clone());
        }
    }
}

#[cfg(test)]
mod test {
    use bitcoin::{hashes::hex::FromHex, Script};

    use super::{sqlite_storage::KvDatabase, AddressCache};

    #[test]
    fn test_create_cache() {
        // None of this should fail
        let database = KvDatabase::new("/tmp/utreexo/".into()).unwrap();
        let _ = AddressCache::new(database);
    }
    #[test]
    fn cache_address() {
        let database = KvDatabase::new("/tmp/utreexo/".into()).unwrap();
        let mut cache = AddressCache::new(database);
        let script_pk = Script::from_hex("00").unwrap();
        cache.cache_address(script_pk);
        assert_eq!(cache.address_map.len(), 1);
    }
}
