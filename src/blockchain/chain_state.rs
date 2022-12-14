use std::{collections::HashMap, io::Write};

use crate::{read_lock, write_lock};
use async_std::{channel::Sender, task::block_on};
use bitcoin::{
    consensus::{deserialize_partial, Encodable},
    hashes::{sha256, Hash},
    Block, BlockHash, BlockHeader, Transaction,
};
use rustreexo::accumulator::{proof::Proof, stump::Stump};
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
    error::BlockchainError,
    BlockchainInterface, BlockchainProviderInterface, Notification,
};
#[allow(unused)]
pub struct ChainState<PersistedState: ChainStore> {
    inner: RwLock<ChainStateInner<PersistedState>>,
}

impl<PersistedState: ChainStore> ChainState<PersistedState> {
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

    pub fn _new(chainstore: KvChainStore) -> ChainState<KvChainStore> {
        ChainState {
            inner: RwLock::new(ChainStateInner {
                chainstore,
                block_index_cache: HashMap::new(),
                block_headers_cache: HashMap::new(),
                acc: Stump::new(),
                best_block: (0, BlockHash::all_zeros()),
                broadcast_queue: vec![],
                subscribers: vec![],
                fee_estimation: (0_f64, 0_f64, 0_f64),
                ibd: true,
            }),
        }
    }
    pub fn load_chain_state(
        chainstore: KvChainStore,
    ) -> Result<ChainState<KvChainStore>, kv::Error> {
        let acc = Self::load_acc(&chainstore);
        let height = chainstore.load_height()?.unwrap().parse().unwrap();
        // block

        let inner = ChainStateInner {
            acc,
            best_block: (height, BlockHash::all_zeros()),
            block_headers_cache: HashMap::new(),
            block_index_cache: HashMap::new(),
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
        todo!()
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
        _proof: Proof,
        _del_hashes: Vec<sha256::Hash>,
    ) -> super::Result<()> {
        self.notify(Notification::NewBlock(block.clone()));

        Ok(())
    }

    fn handle_reorg(&self) -> super::Result<()> {
        todo!()
    }

    fn handle_transaction(&self) -> super::Result<()> {
        todo!()
    }

    fn flush(&self) -> super::Result<()> {
        let _ = self.save_acc();
        Ok(())
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
