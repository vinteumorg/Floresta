use std::{
    collections::{HashMap, HashSet},
    io::Write,
};
lazy_static::lazy_static!(
    static ref REGTEST_GENESIS: Block = deserialize(&Vec::from_hex("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f20020000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000").unwrap()).unwrap();
);
use crate::{read_lock, write_lock};
use async_std::{channel::Sender, task::block_on};
use bitcoin::{
    blockdata::constants::genesis_block,
    consensus::{deserialize, deserialize_partial, Encodable},
    hashes::{hex::FromHex, sha256, Hash},
    util::uint::Uint256,
    Block, BlockHash, BlockHeader, Network, OutPoint, Transaction, TxOut,
};
use rustreexo::accumulator::{proof::Proof, stump::Stump};
use sha2::{Digest, Sha512_256};
use std::sync::RwLock;

pub struct ChainStateInner<PersistedState: ChainStore> {
    /// Caches the map between height and hash for newest blocks
    block_index_cache: HashMap<u32, BlockHash>,
    /// Caches some of the newest block headers for easy access.
    block_headers_cache: HashMap<BlockHash, BlockHeader>,
    /// The acc we use for validation.
    acc: Stump,
    /// All data is persisted here.
    chainstore: PersistedState,
    /// Best known block, cached in a specific field to faster access.
    best_block: (u32, BlockHash),
    /// When one of our consumers tries to broadcast a transaction, this transaction gets
    /// writen to broadcast_queue, and the ChainStateBackend can use it's own logic to actually
    /// broadcast the tx.
    broadcast_queue: Vec<Transaction>,
    /// We may have more than one consumer, that access our data through [BlockchainInterface],
    /// they might need to be notified about new data coming in, like blocks. They do so by calling
    /// `subscribe` and passing a [async_std::channel::Sender]. We save all Senders here.
    subscribers: Vec<Sender<Notification>>,
    /// Fee estimation for 1, 10 and 20 blocks
    fee_estimation: (f64, f64, f64),
    /// Are we in Initial Block Download?
    ibd: bool,
}
use super::{
    chainstore::{ChainStore, KvChainStore},
    error::{BlockValidationErrors, BlockchainError},
    BlockchainInterface, BlockchainProviderInterface, Notification,
};
pub struct ChainState<PersistedState: ChainStore> {
    inner: RwLock<ChainStateInner<PersistedState>>,
}

impl<PersistedState: ChainStore> ChainState<PersistedState> {
    // TODO: Move to LeafData
    pub fn get_leaf_hashes(
        transaction: &Transaction,
        vout: u32,
        height: u32,
        block_hash: BlockHash,
    ) -> sha256::Hash {
        let header_code = height << 1;

        let mut ser_utxo = vec![];
        let utxo = transaction.output.get(vout as usize).unwrap();
        utxo.consensus_encode(&mut ser_utxo).unwrap();
        let header_code = if transaction.is_coin_base() {
            header_code | 1
        } else {
            header_code
        };

        let leaf_hash = Sha512_256::new()
            .chain_update(block_hash)
            .chain_update(transaction.txid())
            .chain_update(vout.to_le_bytes())
            .chain_update(header_code.to_le_bytes())
            .chain_update(ser_utxo)
            .finalize();
        sha256::Hash::from_slice(leaf_hash.as_slice())
            .expect("parent_hash: Engines shouldn't be Err")
    }
    pub fn verify_block_transactions(
        mut utxos: HashMap<OutPoint, TxOut>,
        transactions: &[Transaction],
    ) -> Result<bool, crate::error::Error> {
        for transaction in transactions {
            if !transaction.is_coin_base() {
                transaction.verify(|outpoint| utxos.remove(outpoint))?;
            }
        }
        Ok(true)
    }
    fn calc_next_work_required(last_block: &BlockHeader, first_block: &BlockHeader) -> Uint256 {
        let cur_target = last_block.target();
        let timespan = first_block.time - last_block.time;
        let new_target = cur_target.mul_u32(timespan);
        let new_target = new_target.mul_u32(2016 * 6 * 60);

        new_target
    }
    fn get_next_required_work(&self, last_block: &BlockHeader, next_height: u32) -> Uint256 {
        // Retarget
        if next_height % 2016 == 0 {
            // First block in this epoch
            let first_block_height = next_height - 2016;
            let first_block = self
                .get_block_hash(first_block_height)
                .expect("This block should be present");
            let first_block = self
                .get_block_header(&first_block)
                .expect("This block should also be present");

            return Self::calc_next_work_required(last_block, &first_block);
        }
        last_block.target()
    }
    pub fn update_acc(
        acc: &Stump,
        block: &Block,
        height: u32,
        proof: Proof,
        del_hashes: Vec<sha256::Hash>,
    ) -> Result<Stump, BlockchainError> {
        let block_hash = block.block_hash();
        let mut leaf_hashes = vec![];
        if !proof.verify(&del_hashes, acc)? {
            return Err(BlockchainError::InvalidProof);
        }
        let mut block_inputs = HashSet::new();
        for transaction in block.txdata.iter() {
            for input in transaction.input.iter() {
                block_inputs.insert((input.previous_output.txid, input.previous_output.vout));
            }
        }

        for transaction in block.txdata.iter() {
            for (i, output) in transaction.output.iter().enumerate() {
                if !output.script_pubkey.is_provably_unspendable()
                    && !block_inputs.contains(&(transaction.txid(), i as u32))
                {
                    leaf_hashes.push(Self::get_leaf_hashes(
                        transaction,
                        i as u32,
                        height,
                        block_hash,
                    ))
                }
            }
        }
        let acc = acc.modify(&leaf_hashes, &del_hashes, &proof)?.0;

        Ok(acc)
    }

    pub fn save_acc(&self) -> Result<(), bitcoin::consensus::encode::Error> {
        let inner = read_lock!(self);
        let mut ser_acc: Vec<u8> = vec![];
        inner.acc.leafs.consensus_encode(&mut ser_acc)?;

        for root in inner.acc.roots.iter() {
            ser_acc
                .write(&*root)
                .expect("String formatting should not err");
        }

        inner
            .chainstore
            .save_roots(ser_acc)
            .expect("Chain store is not working");
        Ok(())
    }
    pub fn new(chainstore: KvChainStore, network: Network) -> ChainState<KvChainStore> {
        let genesis = genesis_block(network);

        let mut block_index_cache = HashMap::new();
        let mut block_headers_cache = HashMap::new();

        block_index_cache.insert(0, genesis.block_hash());
        block_headers_cache.insert(genesis.block_hash(), genesis.header);

        ChainState {
            inner: RwLock::new(ChainStateInner {
                chainstore,
                block_index_cache,
                block_headers_cache,
                acc: Stump::new(),
                best_block: (0, genesis.block_hash()),
                broadcast_queue: vec![],
                subscribers: vec![],
                fee_estimation: (1_f64, 1_f64, 1_f64),
                ibd: true,
            }),
        }
    }
    pub fn load_chain_state(
        chainstore: KvChainStore,
    ) -> Result<ChainState<KvChainStore>, BlockchainError> {
        let acc = Self::load_acc(&chainstore);
        let height = chainstore.load_height()?;
        let (headers_map, best_hash, block_index) = Self::get_headers(&chainstore)?;
        let height = if let Some(height) = height {
            height.parse().unwrap_or(0)
        } else {
            0
        };
        let inner = ChainStateInner {
            acc,
            best_block: (height, best_hash),
            block_headers_cache: headers_map,
            block_index_cache: block_index,
            broadcast_queue: Vec::new(),
            chainstore,
            fee_estimation: (0_f64, 0_f64, 0_f64),
            subscribers: Vec::new(),
            ibd: true,
        };
        Ok(ChainState {
            inner: RwLock::new(inner),
        })
    }
    pub fn get_headers(
        chainstore: &KvChainStore,
    ) -> Result<
        (
            HashMap<BlockHash, BlockHeader>,
            BlockHash,
            HashMap<u32, BlockHash>,
        ),
        BlockchainError,
    > {
        let block_headers = chainstore.get_headers()?;
        if block_headers.is_none() {
            return Err(BlockchainError::ChainNotInitialized);
        }

        let mut headers_map = HashMap::new();
        let mut block_index = HashMap::new();
        let mut height = 1;
        let mut block_headers = block_headers.unwrap();
        let mut best = BlockHash::all_zeros();

        while block_headers.len() >= 80 {
            let header = block_headers.drain(0..80).collect::<Vec<_>>();
            let header: BlockHeader = deserialize(&header)?;
            best = header.block_hash();

            block_index.insert(height, header.block_hash());
            headers_map.insert(header.block_hash(), header);
            height += 1;
        }

        Ok((headers_map, best, block_index))
    }
    pub fn load_acc<Storage: ChainStore>(data_storage: &Storage) -> Stump {
        let acc = data_storage
            .load_roots()
            .expect("load_acc: Could not read roots");
        if acc.is_none() {
            return Stump::new();
        }
        let mut acc = acc.unwrap();
        let mut leaves = acc.drain(0..8).collect::<Vec<u8>>();
        let (leaves, _) =
            deserialize_partial::<u64>(&mut leaves).expect("load_acc: Invalid num_leaves");
        let mut roots = vec![];
        while acc.len() >= 32 {
            // Since we only expect hashes after the num_leaves, it should always align with 32 bytes
            assert_eq!(acc.len() % 32, 0);
            let root = acc.drain(0..32).collect::<Vec<u8>>();
            let root = sha256::Hash::from_slice(&root).expect("Invalid hash");
            roots.push(root);
        }
        Stump {
            leafs: leaves,
            roots,
        }
    }
}

impl<PersistedState: ChainStore> BlockchainInterface for ChainState<PersistedState> {
    fn is_in_idb(&self) -> bool {
        self.inner.read().unwrap().ibd
    }
    fn get_block_hash(&self, height: u32) -> super::Result<bitcoin::BlockHash> {
        let inner = self.inner.read().expect("get_block_hash: Poisoned lock");
        if let Some(hash) = inner.block_index_cache.get(&height) {
            return Ok(*hash);
        }
        Err(BlockchainError::BlockNotPresent)
    }

    fn get_tx(&self, _txid: &bitcoin::Txid) -> super::Result<Option<bitcoin::Transaction>> {
        todo!()
    }

    fn get_height(&self) -> super::Result<u32> {
        let inner = read_lock!(self);
        Ok(inner.best_block.0)
    }

    fn broadcast(&self, tx: &bitcoin::Transaction) -> super::Result<()> {
        let mut inner = write_lock!(self);
        inner.broadcast_queue.push(tx.clone());
        Ok(())
    }

    fn estimate_fee(&self, target: usize) -> super::Result<f64> {
        let inner = read_lock!(self);
        if target == 1 {
            Ok(inner.fee_estimation.0)
        } else if target == 10 {
            Ok(inner.fee_estimation.1)
        } else {
            Ok(inner.fee_estimation.2)
        }
    }

    fn get_block(&self, _hash: &BlockHash) -> super::Result<bitcoin::Block> {
        unimplemented!("This chainstate doesn't hold full blocks")
    }

    fn get_best_block(&self) -> super::Result<(u32, BlockHash)> {
        let inner = read_lock!(self);
        Ok(inner.best_block)
    }

    fn get_block_header(&self, hash: &BlockHash) -> super::Result<bitcoin::BlockHeader> {
        let inner = read_lock!(self);
        if let Some(header) = inner.block_headers_cache.get(hash) {
            return Ok(*header);
        }
        Err(BlockchainError::BlockNotPresent)
    }
    fn subscribe(&self, tx: Sender<Notification>) {
        let mut inner = self.inner.write().expect("get_block_hash: Poisoned lock");
        inner.subscribers.push(tx);
    }
}
impl<PersistedState: ChainStore> BlockchainProviderInterface for ChainState<PersistedState> {
    fn notify(&self, what: Notification) {
        for client in self.inner.read().unwrap().subscribers.iter() {
            let _ = block_on(client.send(what.clone()));
        }
    }
    fn connect_block(
        &self,
        block: &Block,
        proof: Proof,
        del_hashes: Vec<sha256::Hash>,
        height: u32,
    ) -> super::Result<()> {
        let inner = self.inner.read().unwrap();
        let best_block = inner.best_block;
        let acc = Self::update_acc(&inner.acc, block, height, proof, del_hashes)?;

        if !block.check_merkle_root() {
            return Err(BlockchainError::BlockValidationError(
                BlockValidationErrors::BadMerkleRoot,
            ));
        }
        if !block.check_witness_commitment() {
            return Err(BlockchainError::BlockValidationError(
                BlockValidationErrors::BadWitnessCommitment,
            ));
        }
        if block.header.prev_blockhash != best_block.1 {
            return Err(BlockchainError::BlockValidationError(
                BlockValidationErrors::PrevBlockNotFound(block.header.prev_blockhash),
            ));
        }
        let prev_block = inner
            .block_headers_cache
            .get(&best_block.1)
            .expect("At this point, we must have this header");
        // Check pow
        let target = self.get_next_required_work(prev_block, height);
        let hash = block.header.validate_pow(&target).map_err(|_| {
            BlockchainError::BlockValidationError(BlockValidationErrors::NotEnoughPow)
        })?;

        let mut utxos = HashMap::new();
        for tx in block.txdata.iter() {
            for (vout, out) in tx.output.iter().enumerate() {
                utxos.insert(OutPoint::new(tx.txid(), vout as u32), out.clone());
            }
        }
        Self::verify_block_transactions(utxos, &block.txdata)
            .map_err(|_| BlockchainError::BlockValidationError(BlockValidationErrors::InvalidTx))?;
        self.notify(Notification::NewBlock((block.to_owned(), height)));
        // Drop this lock because we need a write lock to inner, if we hold this lock this will
        // cause a deadlock.
        drop(inner);
        // Updates our local view of the network
        let mut inner = self.inner.write().unwrap();
        inner.acc = acc;
        inner.best_block = (height, hash);
        inner.block_headers_cache.insert(hash, block.header);
        inner.block_index_cache.insert(height, hash);

        Ok(())
    }

    fn handle_reorg(&self) -> super::Result<()> {
        todo!()
    }

    fn handle_transaction(&self) -> super::Result<()> {
        unimplemented!("This chian_state has no mempool")
    }

    fn flush(&self) -> super::Result<()> {
        let _ = self.save_acc();
        Ok(())
    }
    fn get_unbroadcasted(&self) -> Vec<Transaction> {
        let mut inner = write_lock!(self);
        inner.broadcast_queue.drain(..).collect()
    }
}
#[macro_export]
macro_rules! read_lock {
    ($obj: ident) => {
        $obj.inner.read().expect("get_block_hash: Poisoned lock")
    };
}
#[macro_export]
macro_rules! write_lock {
    ($obj: ident) => {
        $obj.inner.write().expect("get_block_hash: Poisoned lock")
    };
}
