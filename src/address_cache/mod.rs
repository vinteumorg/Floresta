pub mod kv_database;
pub mod merkle;
use merkle::MerkleProof;
use serde::{Deserialize, Serialize};

use std::{
    collections::{HashMap, HashSet},
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
        Hash as HashTrait,
    },
    Block, OutPoint, Script, Transaction, TxOut,
};
/// Every address contains zero or more associated transactions, this struct defines what
/// data we store for those.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedTransaction {
    pub tx_hex: String,
    pub height: u32,
    pub merkle_block: Option<MerkleProof>,
    pub hash: String,
    pub position: u32,
    pub is_spend: bool,
}
impl Default for CachedTransaction {
    fn default() -> Self {
        CachedTransaction {
            tx_hex: sha256::Hash::all_zeros().to_string(),
            height: 0,
            merkle_block: None,
            hash: sha256::Hash::all_zeros().to_string(),
            position: 0,
            is_spend: false,
        }
    }
}

/// An address inside our cache, contains all information we need to satisfy electrum's requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedAddress {
    script_hash: Hash,
    balance: u64,
    transactions: Vec<CachedTransaction>,
    script: Script,
    utxos: Vec<OutPoint>,
}

impl CachedAddress {
    pub fn _new(
        script_hash: Hash,
        balance: u64,
        transactions: Vec<CachedTransaction>,
        script: Script,
        utxos: Vec<OutPoint>,
    ) -> CachedAddress {
        CachedAddress {
            script_hash,
            balance,
            transactions,
            script,
            utxos,
        }
    }
}
/// Public trait defining a common interface for databases to be used with our cache
pub trait AddressCacheDatabase {
    /// Saves a new address to the database. If the address already exists, `update` should
    /// be used instead
    fn save(&self, address: &CachedAddress);
    /// Loads all addresses we have cached so far
    fn load<E>(&self) -> Result<Vec<CachedAddress>, E>
    where
        E: From<crate::error::Error>
            + Into<crate::error::Error>
            + std::convert::From<kv::Error>
            + std::convert::From<serde_json::Error>;
    /// Updates an address, probably because a new transaction arrived
    fn update(&self, address: &CachedAddress);
    /// TODO: Maybe turn this into another db
    /// Returns the height of the last block we filtered
    fn get_cache_height(&self) -> Result<u32, crate::error::Error>;
    /// Saves the height of the last block we filtered
    fn set_cache_height(&self, height: u32) -> Result<(), crate::error::Error>;
    /// Saves the descriptor of associated cache
    fn desc_save(&self, descriptor: &str) -> Result<(), crate::error::Error>;
    /// Get associated descriptors
    fn descs_get(&self) -> Result<Vec<String>, crate::error::Error>;
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
    /// Keeps track of all utxos we own, and the script hash they belong to
    utxo_index: HashMap<OutPoint, Hash>,
}
impl<D: AddressCacheDatabase> AddressCache<D> {
    /// Iterates through a block, finds transactions destined to ourselves.
    /// Returns all transactions we found.
    pub fn block_process(&mut self, block: &Block, height: u32) -> Vec<(Transaction, TxOut)> {
        let mut my_transactions = vec![];

        for (position, transaction) in block.txdata.iter().enumerate() {
            for (vin, txin) in transaction.input.iter().enumerate() {
                //     // TODO: Simplify this whole thing
                //     if let Some((script, _)) = self.tx_index.get(&txin.previous_output.txid) {
                //         // If a transaction is spending some utxo we own
                //         let script = self.address_map.get(script).unwrap();
                //         let tx = self.get_transaction(&txin.previous_output.txid).unwrap();
                //         let tx: Transaction = deserialize(&Vec::from_hex(&tx.tx_hex).unwrap()).unwrap();

                //         let output = tx.output.get(txin.previous_output.vout as usize).unwrap();
                //         // A transaction can get in our cache, even if none of the outputs are ours,
                //         // if it's a wallet spend. In this case, we might have a false-positive when those
                //         // outputs are spent. This if prevents from caching tx we don't actually care about.
                //         if output.script_pubkey != script.script {
                //             continue;
                //         }
                //         my_transactions.push((transaction.clone(), output.clone()));

                //         let merkle_block = MerkleProof::from_block(block, position as u64);

                //         self.cache_transaction(
                //             transaction,
                //             height,
                //             output.value,
                //             merkle_block,
                //             position as u32,
                //             vin,
                //             true,
                //             &output.script_pubkey,
                //         );
                //     }
                if let Some(script) = self.utxo_index.get(&txin.previous_output) {
                    let script = self.address_map.get(script).unwrap().to_owned();
                    let tx = self.get_transaction(&txin.previous_output.txid).unwrap();
                    let tx: Transaction = deserialize(&Vec::from_hex(&tx.tx_hex).unwrap()).unwrap();
                    let utxo = tx.output.get(txin.previous_output.vout as usize).unwrap();
                    let merkle_block = MerkleProof::from_block(block, position as u64);

                    self.cache_transaction(
                        transaction,
                        height,
                        utxo.value,
                        merkle_block,
                        position as u32,
                        vin,
                        true,
                        &script.script,
                    )
                }
            }

            for (vout, output) in transaction.output.iter().enumerate() {
                if self.script_set.contains(&output.script_pubkey) {
                    my_transactions.push((transaction.clone(), output.clone()));

                    let merkle_block = MerkleProof::from_block(block, position as u64);

                    self.cache_transaction(
                        transaction,
                        height,
                        output.value,
                        merkle_block,
                        position as u32,
                        vout,
                        false,
                        &output.script_pubkey,
                    );
                }
            }
        }
        my_transactions
    }
    pub fn bump_height(&self, height: u32) {
        self.database
            .set_cache_height(height)
            .expect("Database is not working");
    }
    pub fn new(database: D) -> AddressCache<D> {
        let scripts = database
            .load::<crate::error::Error>()
            .expect("Could not load database");

        let mut address_map = HashMap::new();
        let mut script_set = HashSet::new();
        let mut tx_index = HashMap::new();
        let mut utxo_index = HashMap::new();
        for address in scripts {
            for (pos, tx) in address.transactions.iter().enumerate() {
                let txid = Txid::from_hex(&tx.hash).expect("Cached an invalid txid");
                tx_index.insert(txid, (address.script_hash, pos));
            }
            for utxo in address.utxos.iter() {
                utxo_index.insert(*utxo, address.script_hash);
            }
            script_set.insert(address.script.clone());
            address_map.insert(address.script_hash, address);
        }
        AddressCache {
            database,
            address_map,
            script_set,
            tx_index,
            utxo_index,
        }
    }
    pub fn get_address_utxos(&self, script_hash: &sha256::Hash) -> Option<Vec<(TxOut, OutPoint)>> {
        let address = self.address_map.get(script_hash)?;
        let utxos = &address.utxos;
        let mut address_utxos = vec![];
        for utxo in utxos {
            let tx = address
                .transactions
                .iter()
                .find(|transaction| Txid::from_hex(&*transaction.hash).unwrap() == utxo.txid)?;
            let tx = Vec::from_hex(&tx.tx_hex).unwrap();
            let tx = deserialize::<Transaction>(&tx).unwrap();
            address_utxos.push((tx.output[utxo.vout as usize].to_owned(), utxo.to_owned()));
        }

        Some(address_utxos)
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
            // If a given transaction is cached, but the merkle tree doesn't exist, that means
            // an unconfirmed transaction.
            tx.merkle_block.as_ref()?;
            for hash in tx.merkle_block.unwrap().hashes() {
                hashes.push(hash.to_hex());
            }
            return Some((hashes, tx.position));
        }
        // Tx not found
        // TODO: Ain't that an error?
        None
    }
    pub fn get_position(&self, txid: &Txid) -> Option<u32> {
        Some(self.get_transaction(txid)?.position)
    }
    pub fn get_height(&self, txid: &Txid) -> Option<u32> {
        if let Some(tx) = self.get_transaction(txid) {
            return Some(tx.height);
        }

        None
    }

    pub fn get_cached_transaction(&self, txid: &Txid) -> Option<String> {
        if let Some(tx) = self.get_transaction(txid) {
            return Some(tx.tx_hex);
        }
        None
    }
    /// Adds a new address to track, should be called at wallet setup and every once in a while
    /// to cache new addresses, as we use the first ones. Only requires a script to cache.
    pub fn cache_address(&mut self, script_pk: Script) {
        let hash = get_spk_hash(&script_pk);
        if self.address_map.contains_key(&hash) {
            return;
        }
        let new_address = CachedAddress {
            balance: 0,
            script_hash: hash,
            transactions: Vec::new(),
            script: script_pk.clone(),
            utxos: Vec::new(),
        };
        self.database.save(&new_address);

        self.address_map.insert(hash, new_address);
        self.script_set.insert(script_pk);
    }
    /// Setup is the first command that should be executed. In a new cache. It sets our wallet's
    /// state, like the height we should start scanning and the wallet's descriptor.
    pub fn setup(&self) -> Result<(), crate::error::Error> {
        if self.database.descs_get().is_err() {
            self.database.set_cache_height(0)?;
        }
        Ok(())
    }
    /// Tells whether or not a descriptor is already cached
    pub fn is_cached(&self, desc: &String) -> Result<bool, crate::error::Error> {
        let known_descs = self.database.descs_get()?;
        Ok(known_descs.contains(desc))
    }
    pub fn push_descriptor(&self, descriptor: &str) -> Result<(), crate::error::Error> {
        self.database.desc_save(descriptor)
    }
    /// Caches a new transaction. This method may be called for addresses we don't follow yet,
    /// this automatically makes we follow this address.
    #[allow(clippy::too_many_arguments)]
    pub fn cache_transaction(
        &mut self,
        transaction: &Transaction,
        height: u32,
        value: u64,
        merkle_block: MerkleProof,
        position: u32,
        index: usize,
        is_spend: bool,
        script: &Script,
    ) {
        let transaction_to_cache = CachedTransaction {
            height,
            merkle_block: Some(merkle_block),
            tx_hex: serialize_hex(transaction),
            hash: transaction.txid().to_string(),
            position,
            is_spend,
        };
        let hash = get_spk_hash(script);
        if let Some(address) = self.address_map.get_mut(&hash) {
            if is_spend {
                address.balance -= value;
                let input = transaction
                    .input
                    .get(index as usize)
                    .expect("Malformed call, index is bigger than the output vector");
                let idx = address
                    .utxos
                    .iter()
                    .position(|utxo| *utxo == input.previous_output);
                let utxo = address.utxos.remove(idx.unwrap());
                self.utxo_index.remove(&utxo);
            } else {
                let utxo = OutPoint {
                    txid: transaction.txid(),
                    vout: index as u32,
                };
                address.utxos.push(utxo);
                self.utxo_index.insert(utxo, hash);

                address.balance += value;
            }
            if address
                .transactions
                .iter()
                .any(|tx| tx.hash == transaction_to_cache.hash)
            {
                return;
            }
            self.tx_index.insert(
                transaction.txid(),
                (address.script_hash, address.transactions.len()),
            );
            address.transactions.push(transaction_to_cache);
            self.database.update(address);
        } else {
            // This means `cache_transaction` have been called with an address we don't
            // follow. This may be useful for caching new addresses without re-scanning.
            // We can track this address from now onwards, but the past history is only
            // available with full rescan
            let new_address = CachedAddress {
                balance: transaction.output[index].value,
                script_hash: hash,
                transactions: vec![transaction_to_cache],
                script: script.to_owned(),
                utxos: vec![OutPoint {
                    txid: transaction.txid(),
                    vout: index as u32,
                }],
            };
            self.database.save(&new_address);

            self.address_map.insert(hash, new_address);
            self.script_set.insert(script.to_owned());
        }
    }
}

#[cfg(test)]
mod test {
    use crate::electrum::electrum_protocol::get_spk_hash;
    use bitcoin::{
        consensus::{deserialize, Decodable},
        hashes::{hex::FromHex, sha256},
        Address, Script, Txid,
    };
    use std::str::FromStr;

    const BLOCK_FIRST_UTXO: &str = "00000020b4f594a390823c53557c5a449fa12413cbbae02be529c11c4eb320ff8e000000dd1211eb35ca09dc0ee519b0f79319fae6ed32c66f8bbf353c38513e2132c435474d81633c4b011e195a220002010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0403edce01feffffff028df2052a0100000016001481113cad52683679a83e76f76f84a4cfe36f75010000000000000000776a24aa21a9ed67863b4f356b7b9f3aab7a2037615989ef844a0917fb0a1dcd6c23a383ee346b4c4fecc7daa2490047304402203768ff10a948a2dd1825cc5a3b0d336d819ea68b5711add1390b290bf3b1cba202201d15e73791b2df4c0904fc3f7c7b2f22ab77762958e9bc76c625138ad3a04d290100012000000000000000000000000000000000000000000000000000000000000000000000000002000000000101be07b18750559a418d144f1530be380aa5f28a68a0269d6b2d0e6ff3ff25f3200000000000feffffff0240420f00000000001600142b6a2924aa9b1b115d1ac3098b0ba0e6ed510f2a326f55d94c060000160014c2ed86a626ee74d854a12c9bb6a9b72a80c0ddc50247304402204c47f6783800831bd2c75f44d8430bf4d962175349dc04d690a617de6c1eaed502200ffe70188a6e5ad89871b2acb4d0f732c2256c7ed641d2934c6e84069c792abc012103ba174d9c66078cf813d0ac54f5b19b5fe75104596bdd6c1731d9436ad8776f41ecce0100";
    const BLOCK_SPEND: &str = "000000203ea734fa2c8dee7d3194878c9eaf6e83a629f79b3076ec857793995e01010000eb99c679c0305a1ac0f5eb2a07a9f080616105e605b92b8c06129a2451899225ab5481633c4b011e0b26720102020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0403efce01feffffff026ef2052a01000000225120a1a1b1376d5165617a50a6d2f59abc984ead8a92df2b25f94b53dbc2151824730000000000000000776a24aa21a9ed1b4c48a7220572ff3ab3d2d1c9231854cb62542fbb1e0a4b21ebbbcde8d652bc4c4fecc7daa2490047304402204b37c41fce11918df010cea4151737868111575df07f7f2945d372e32a6d11dd02201658873a8228d7982df6bdbfff5d0cad1d6f07ee400e2179e8eaad8d115b7ed001000120000000000000000000000000000000000000000000000000000000000000000000000000020000000001017ca523c5e6df0c014e837279ab49be1676a9fe7571c3989aeba1e5d534f4054a0000000000fdffffff01d2410f00000000001600142b6a2924aa9b1b115d1ac3098b0ba0e6ed510f2a02473044022071b8583ba1f10531b68cb5bd269fb0e75714c20c5a8bce49d8a2307d27a082df022069a978dac00dd9d5761aa48c7acc881617fa4d2573476b11685596b17d437595012103b193d06bd0533d053f959b50e3132861527e5a7a49ad59c5e80a265ff6a77605eece0100";
    fn deserialize_from_str<T: Decodable>(thing: &str) -> T {
        let hex = Vec::from_hex(thing).unwrap();
        deserialize(&hex).unwrap()
    }
    use super::{kv_database::KvDatabase, AddressCache};
    fn get_test_cache() -> AddressCache<KvDatabase> {
        let random_name = rand::random::<u64>();
        let database = KvDatabase::new(format!("/tmp/utreexo/{random_name}"))
            .expect("Could not open database");
        AddressCache::new(database)
    }
    fn get_test_address() -> (Address, sha256::Hash) {
        let address = Address::from_str("tb1q9d4zjf92nvd3zhg6cvyckzaqumk4zre26x02q9").unwrap();
        let script_hash = get_spk_hash(&address.script_pubkey());
        (address, script_hash)
    }
    #[test]
    fn test_create() {
        let _ = get_test_cache();
    }
    #[test]
    fn test_cache_address() {
        let (address, script_hash) = get_test_address();
        let mut cache = get_test_cache();
        // Should have no address before caching
        assert_eq!(cache.address_map.len(), 0);

        cache.cache_address(address.script_pubkey());
        // Assert we indeed have one cached address
        assert_eq!(cache.address_map.len(), 1);
        assert_eq!(cache.get_address_balance(&script_hash), 0);
        assert_eq!(cache.get_address_history(&script_hash), vec![]);
    }
    #[test]
    fn test_cache_transaction() {
        // Signet transaction with id 6bb0665122c7dcecc6e6c45b6384ee2bdce148aea097896e6f3e9e08070353ea
        // block hash 0000009298f9e75a91fa763c78b66d1555cb059d9ca9d45601eed2b95166a151.
        let transaction = "020000000001017ca523c5e6df0c014e837279ab49be1676a9fe7571c3989aeba1e5d534f4054a0000000000fdffffff01d2410f00000000001600142b6a2924aa9b1b115d1ac3098b0ba0e6ed510f2a02473044022071b8583ba1f10531b68cb5bd269fb0e75714c20c5a8bce49d8a2307d27a082df022069a978dac00dd9d5761aa48c7acc881617fa4d2573476b11685596b17d437595012103b193d06bd0533d053f959b50e3132861527e5a7a49ad59c5e80a265ff6a77605eece0100";
        let transaction = Vec::from_hex(transaction).unwrap();
        let transaction = deserialize(&transaction).unwrap();

        let merkle_block = "0100000000000000ea530307089e3e6f6e8997a0ae48e1dc2bee84635bc4e6c6ecdcc7225166b06b010000000000000034086ef398efcdec47b37241221c8f4613e02bc31026cc74d07ddb3092e6d6e7";
        let merkle_block = Vec::from_hex(merkle_block).unwrap();
        let merkle_block = deserialize(&merkle_block).unwrap();

        let (address, script_hash) = get_test_address();
        let mut cache = get_test_cache();
        cache.cache_address(address.script_pubkey());

        cache.cache_transaction(
            &transaction,
            118511,
            transaction.output[0].value,
            merkle_block,
            1,
            0,
            false,
            &transaction.output[0].script_pubkey,
        );

        assert_eq!(cache.tx_index.len(), 1);
        let balance = cache.get_address_balance(&script_hash);
        let history = cache.get_address_history(&script_hash);
        let cached_merkle_block = cache.get_merkle_proof(&transaction.txid()).unwrap();
        assert_eq!(balance, 999890);
        assert_eq!(
            history[0].hash,
            String::from("6bb0665122c7dcecc6e6c45b6384ee2bdce148aea097896e6f3e9e08070353ea")
        );
        let expected_hashes = vec![String::from(
            "e7d6e69230db7dd074cc2610c32be013468f1c224172b347eccdef98f36e0834",
        )];
        assert_eq!(cached_merkle_block, (expected_hashes, 1));
    }
    #[test]
    fn test_process_block() {
        let (address, script_hash) = get_test_address();
        let mut cache = get_test_cache();
        cache.cache_address(address.script_pubkey());

        let block = "000000203ea734fa2c8dee7d3194878c9eaf6e83a629f79b3076ec857793995e01010000eb99c679c0305a1ac0f5eb2a07a9f080616105e605b92b8c06129a2451899225ab5481633c4b011e0b26720102020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0403efce01feffffff026ef2052a01000000225120a1a1b1376d5165617a50a6d2f59abc984ead8a92df2b25f94b53dbc2151824730000000000000000776a24aa21a9ed1b4c48a7220572ff3ab3d2d1c9231854cb62542fbb1e0a4b21ebbbcde8d652bc4c4fecc7daa2490047304402204b37c41fce11918df010cea4151737868111575df07f7f2945d372e32a6d11dd02201658873a8228d7982df6bdbfff5d0cad1d6f07ee400e2179e8eaad8d115b7ed001000120000000000000000000000000000000000000000000000000000000000000000000000000020000000001017ca523c5e6df0c014e837279ab49be1676a9fe7571c3989aeba1e5d534f4054a0000000000fdffffff01d2410f00000000001600142b6a2924aa9b1b115d1ac3098b0ba0e6ed510f2a02473044022071b8583ba1f10531b68cb5bd269fb0e75714c20c5a8bce49d8a2307d27a082df022069a978dac00dd9d5761aa48c7acc881617fa4d2573476b11685596b17d437595012103b193d06bd0533d053f959b50e3132861527e5a7a49ad59c5e80a265ff6a77605eece0100";
        let block = deserialize(&Vec::from_hex(block).unwrap()).unwrap();
        cache.block_process(&block, 118511);
        assert_eq!(cache.tx_index.len(), 1);
        let balance = cache.get_address_balance(&script_hash);
        let history = cache.get_address_history(&script_hash);
        let transaction_id =
            Txid::from_str("6bb0665122c7dcecc6e6c45b6384ee2bdce148aea097896e6f3e9e08070353ea")
                .unwrap();
        let cached_merkle_block = cache.get_merkle_proof(&transaction_id).unwrap();
        assert_eq!(balance, 999890);
        assert_eq!(
            history[0].hash,
            String::from("6bb0665122c7dcecc6e6c45b6384ee2bdce148aea097896e6f3e9e08070353ea")
        );
        let expected_hashes = vec![String::from(
            "e7d6e69230db7dd074cc2610c32be013468f1c224172b347eccdef98f36e0834",
        )];
        assert_eq!(cached_merkle_block, (expected_hashes, 1));
    }
    #[test]
    fn test_persistency() {
        let random_name = rand::random::<u64>();
        let (address, script_hash) = get_test_address();
        // Create a new address cache
        {
            let database = KvDatabase::new(format!("/tmp/utreexo/{random_name}"))
                .expect("Could not open database");
            let mut cache = AddressCache::new(database);

            cache.cache_address(address.script_pubkey());

            let block = "000000203ea734fa2c8dee7d3194878c9eaf6e83a629f79b3076ec857793995e01010000eb99c679c0305a1ac0f5eb2a07a9f080616105e605b92b8c06129a2451899225ab5481633c4b011e0b26720102020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0403efce01feffffff026ef2052a01000000225120a1a1b1376d5165617a50a6d2f59abc984ead8a92df2b25f94b53dbc2151824730000000000000000776a24aa21a9ed1b4c48a7220572ff3ab3d2d1c9231854cb62542fbb1e0a4b21ebbbcde8d652bc4c4fecc7daa2490047304402204b37c41fce11918df010cea4151737868111575df07f7f2945d372e32a6d11dd02201658873a8228d7982df6bdbfff5d0cad1d6f07ee400e2179e8eaad8d115b7ed001000120000000000000000000000000000000000000000000000000000000000000000000000000020000000001017ca523c5e6df0c014e837279ab49be1676a9fe7571c3989aeba1e5d534f4054a0000000000fdffffff01d2410f00000000001600142b6a2924aa9b1b115d1ac3098b0ba0e6ed510f2a02473044022071b8583ba1f10531b68cb5bd269fb0e75714c20c5a8bce49d8a2307d27a082df022069a978dac00dd9d5761aa48c7acc881617fa4d2573476b11685596b17d437595012103b193d06bd0533d053f959b50e3132861527e5a7a49ad59c5e80a265ff6a77605eece0100";
            let block = deserialize(&Vec::from_hex(block).unwrap()).unwrap();
            cache.block_process(&block, 118511);
            cache.bump_height(118511)
        }
        // Load it from disk after persisting the  data
        let database = KvDatabase::new(format!("/tmp/utreexo/{random_name}"))
            .expect("Could not open database");
        let cache = AddressCache::new(database);

        assert_eq!(cache.tx_index.len(), 1);
        let balance = cache.get_address_balance(&script_hash);
        let history = cache.get_address_history(&script_hash);
        let transaction_id =
            Txid::from_str("6bb0665122c7dcecc6e6c45b6384ee2bdce148aea097896e6f3e9e08070353ea")
                .unwrap();
        let cached_merkle_block = cache.get_merkle_proof(&transaction_id).unwrap();
        assert_eq!(balance, 999890);
        assert_eq!(
            history[0].hash,
            String::from("6bb0665122c7dcecc6e6c45b6384ee2bdce148aea097896e6f3e9e08070353ea")
        );
        let expected_hashes = vec![String::from(
            "e7d6e69230db7dd074cc2610c32be013468f1c224172b347eccdef98f36e0834",
        )];
        assert_eq!(cached_merkle_block, (expected_hashes, 1));
    }
    #[test]
    fn test_multiple_transaction() {
        let block1 = deserialize_from_str(BLOCK_FIRST_UTXO);
        let block2 = deserialize_from_str(BLOCK_SPEND);

        let spk = Script::from_hex("00142b6a2924aa9b1b115d1ac3098b0ba0e6ed510f2a")
            .expect("Valid address");
        let script_hash = get_spk_hash(&spk);
        let mut cache = get_test_cache();

        cache.cache_address(spk);

        cache.block_process(&block1, 118511);
        cache.block_process(&block2, 118509);

        let address = cache.address_map.get(&script_hash).unwrap();

        assert_eq!(address.transactions.len(), 2);
        assert_eq!(address.utxos.len(), 1);
    }
}
