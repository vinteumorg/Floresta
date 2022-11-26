pub mod sqlite_storage;
use std::{
    collections::{HashMap, HashSet},
    vec,
};

use crate::electrum::electrum_protocol::get_spk_hash;
use bdk::bitcoin::{
    consensus::encode::{deserialize, serialize_hex},
    hashes::{
        hex::{FromHex, ToHex},
        sha256::Hash,
    },
    Block, MerkleBlock, Script, Transaction, TxOut,
};
#[derive(Debug, Clone)]
pub struct CachedTransaction {
    tx_hex: String,
    height: u32,
    merkle_block: MerkleBlock,
}
#[derive(Debug, Clone)]
pub struct CachedAddress {
    script_hash: Hash,
    balance: u64,
    transactions: Vec<CachedTransaction>,
}
impl CachedAddress {
    pub fn new(
        script_hash: Hash,
        balance: u64,
        transactions: Vec<CachedTransaction>,
    ) -> CachedAddress {
        CachedAddress {
            script_hash,
            balance,
            transactions,
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
}
impl<D: AddressCacheDatabase> AddressCache<D> {
    /// Iterates through a block, finds transactions destined to ourselves.
    /// Returns all transactions we found.
    pub fn block_process(&mut self, block: &Block, height: u32) -> Vec<(Transaction, TxOut)> {
        let mut my_transactions = vec![];
        for transaction in block.txdata.iter() {
            for output in transaction.output.iter() {
                if self.script_set.contains(&output.script_pubkey) {
                    my_transactions.push((transaction.clone(), output.clone()));
                    let my_txid = transaction.txid();
                    let merkle_block =
                        MerkleBlock::from_block_with_predicate(block, |txid| *txid == my_txid);
                    self.cache_transaction(transaction, height, output, merkle_block);
                }
            }
        }
        my_transactions
    }
    pub fn new(database: D) {}
    pub fn cache_transaction(
        &mut self,
        transaction: &Transaction,
        height: u32,
        out: &TxOut,
        merkle_block: MerkleBlock,
    ) {
        let transaction_to_cache = CachedTransaction {
            height,
            merkle_block,
            tx_hex: serialize_hex(transaction),
        };
        let hash = get_spk_hash(&out.script_pubkey);
        if let Some(address) = self.address_map.get_mut(&hash) {
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
            };
            self.database.save(&new_address);

            self.address_map.insert(hash, new_address);
            self.script_set.insert(out.script_pubkey.clone());
        }
    }
}
