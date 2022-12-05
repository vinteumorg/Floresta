pub mod sqlite_storage;
use std::{
    collections::{HashMap, HashSet},
    ops::RangeInclusive,
    str::Split,
    vec,
};

use crate::{blockchain::sync::BlockchainSync, electrum::electrum_protocol::get_spk_hash};
use bitcoin::{
    consensus::deserialize,
    consensus::encode::serialize_hex,
    hash_types::Txid,
    hashes::{
        hex::{FromHex, ToHex},
        sha256::{self, Hash},
        Hash as HashTrait,
    },
    Block, MerkleBlock, Script, Transaction, TxOut,
};
use rustreexo::accumulator::{proof::Proof, stump::Stump};
#[derive(Debug, Clone)]
pub struct CachedTransaction {
    pub tx_hex: String,
    pub height: u32,
    pub merkle_block: Option<MerkleBlock>,
    pub hash: String,
    pub position: u32,
}
impl Default for CachedTransaction {
    fn default() -> Self {
        CachedTransaction {
            tx_hex: sha256::Hash::all_zeros().to_string(),
            height: 0,
            merkle_block: None,
            hash: sha256::Hash::all_zeros().to_string(),
            position: 0,
        }
    }
}
impl std::fmt::Display for CachedTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let merkle_block = if let Some(merkle_block) = &self.merkle_block {
            serialize_hex(merkle_block)
        } else {
            "".to_string()
        };
        write!(f, "{};{};{}", self.tx_hex, self.height, merkle_block)
    }
}
/// TODO: Clean this function up
fn get_arg<'a>(
    mut split: Split<'a, &'a str>,
) -> Result<(&'a str, Split<'a, &'a str>), crate::error::Error> {
    if let Some(data) = split.nth(0) {
        return Ok((data, split));
    }
    Err(crate::error::Error::DbParseError)
}
impl TryFrom<String> for CachedTransaction {
    type Error = crate::error::Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let transaction = value.split(";");

        let (tx_hex, transaction) = get_arg(transaction)?;

        let (height, transaction) = get_arg(transaction)?;

        let (merkle_block, _) = get_arg(transaction)?;
        let merkle_block = Vec::from_hex(merkle_block)?;
        let merkle_block = deserialize(&merkle_block)?;

        let tx = Vec::from_hex(tx_hex)?;
        let tx = deserialize::<Transaction>(&tx)?;

        Ok(CachedTransaction {
            tx_hex: tx_hex.to_string(),
            height: height.parse::<u32>()?,
            merkle_block: Some(merkle_block),
            hash: tx.txid().to_string(),
            position: 0,
        })
    }
}
impl TryFrom<String> for CachedAddress {
    type Error = crate::error::Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let address = value.split(":");
        let (script_hash, address) = get_arg(address)?;
        let script_hash = sha256::Hash::from_hex(&script_hash.to_string())?;

        let (balance, address) = get_arg(address)?;

        let (script, address) = get_arg(address)?;
        let script = Script::from_hex(script)?;

        let mut transactions = vec![];

        for transaction in address {
            if transaction.len() == 0 {
                continue;
            }

            let transaction = transaction.to_string();
            let transaction = CachedTransaction::try_from(transaction)?;

            transactions.push(transaction);
        }

        Ok(CachedAddress {
            balance: balance.parse()?,
            script_hash,
            transactions,
            script,
        })
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
    fn load<E>(&self) -> Result<Vec<CachedAddress>, E>
    where
        E: From<crate::error::Error> + Into<crate::error::Error> + std::convert::From<kv::Error>;
    /// Updates an address, probably because a new transaction arrived
    fn update(&self, address: &CachedAddress);
    /// TODO: Maybe turn this into another db
    /// Returns the height of the last block we filtered
    fn get_cache_height(&self) -> Result<u32, crate::error::Error>;
    /// Saves the height of the last block we filtered
    fn set_cache_height(&self, height: u32) -> Result<(), crate::error::Error>;
    /// Saves the descriptor of associated cache
    fn desc_save(&self, descriptor: String) -> Result<(), crate::error::Error>;
    /// Get associated descriptor
    fn desc_get(&self) -> Result<String, crate::error::Error>;
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
    /// Maps transaction ids to a script hash and the position of this transaction in a block
    tx_index: HashMap<Txid, (Hash, usize)>,
    /// Our utreexo accumulator
    acc: Stump,
}
impl<D: AddressCacheDatabase> AddressCache<D> {
    /// Iterates through a block, finds transactions destined to ourselves.
    /// Returns all transactions we found.
    pub fn block_process(
        &mut self,
        block: &Block,
        height: u32,
        proof: Proof,
        del_hashes: Vec<sha256::Hash>,
    ) -> Vec<(Transaction, TxOut)> {
        let mut my_transactions = vec![];
        self.acc = BlockchainSync::update_acc(&self.acc, &block, height, proof, del_hashes)
            .expect(format!("Could not update the accumulator at {height}").as_str());

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
        self.database
            .set_cache_height(height)
            .expect("Database is not working");
        my_transactions
    }
    pub fn new(database: D) -> AddressCache<D> {
        let scripts = database
            .load::<crate::error::Error>()
            .expect("Could not load database");

        let mut address_map = HashMap::new();
        let mut script_set = HashSet::new();

        for address in scripts {
            script_set.insert(address.script.clone());
            address_map.insert(address.script_hash, address);
        }

        AddressCache {
            database,
            address_map,
            script_set,
            tx_index: HashMap::new(),
            acc: Stump::new(),
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
            for hash in tx.merkle_block.unwrap().txn.hashes() {
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
    /// Setup is the first command that should be executed. In a new cache. It sets our wallet's
    /// state, like the height we should start scanning and the wallet's descriptor.
    pub fn setup(&self, descriptor: String) -> Result<(), crate::error::Error> {
        // We don't start from 0, because the genesis's utxo is not spendable, and it don't
        // have any proof. We skip it and start from block one when filtering.
        self.database.set_cache_height(1)?;
        self.database.desc_save(descriptor)
    }
    /// Caches a new transaction. This method may be called for addresses we don't follow yet,
    /// this automatically makes we follow this address.
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
            merkle_block: Some(merkle_block),
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

    use crate::electrum::electrum_protocol::get_spk_hash;

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
        let hash = &get_spk_hash(&script_pk);

        cache.cache_address(script_pk);
        assert_eq!(cache.address_map.len(), 1);
        assert_eq!(cache.get_address_balance(hash), 0);
    }
    #[test]
    fn test_persistency() {
        {
            let database = KvDatabase::new("/tmp/utreexo/".into()).unwrap();
            let mut cache = AddressCache::new(database);
            let script_pk = Script::from_hex("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac").unwrap();
            cache.cache_address(script_pk);
        }
        let database = KvDatabase::new("/tmp/utreexo/".into()).unwrap();
        let cache = AddressCache::new(database);
        assert_eq!(cache.script_set.len(), 1);
    }
}
