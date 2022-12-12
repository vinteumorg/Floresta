use std::{collections::HashMap, fmt::Write};

use crate::{read_lock, write_lock};
use bitcoin::{
    hashes::{hex::FromHex, sha256, Hash},
    Block, BlockHash, BlockHeader, Transaction,
};
use rustreexo::accumulator::stump::Stump;
use std::sync::RwLock;
pub struct ChainStateInner<PersistedState: ChainStore> {
    block_index: HashMap<u32, BlockHash>,
    block_headers: HashMap<BlockHash, BlockHeader>,
    acc: Stump,
    chainstore: PersistedState,
    best_block: (u32, BlockHash),
    broadcast_queue: Vec<Transaction>,
    subscribers: Vec<Box<dyn Fn(Block) -> ()>>,
    /// Fee estimation for 1, 10 and 20 blocks
    fee_estimation: (f64, f64, f64),
}
use super::{
    chainstore::{ChainStore, KvChainStore},
    error::BlockchainError,
    BlockchainInterface,
};
#[allow(unused)]
pub struct ChainState<PersistedState: ChainStore> {
    inner: RwLock<ChainStateInner<PersistedState>>,
}

impl<PersistedState: ChainStore> ChainState<PersistedState> {
    pub fn save_acc(&self) {
        let inner = read_lock!(self);
        let mut acc = String::new();
        acc.write_fmt(format_args!("{} ", inner.acc.leafs))
            .expect("String formatting should not err");
        for root in inner.acc.roots.iter() {
            acc.write_fmt(format_args!("{root}"))
                .expect("String formatting should not err");
        }

        inner
            .chainstore
            .save_roots(acc)
            .expect("Chain store is not working");
    }
    pub fn new() -> ChainState<KvChainStore> {
        ChainState {
            inner: RwLock::new(ChainStateInner {
                block_index: HashMap::new(),
                block_headers: HashMap::new(),
                acc: Stump::new(),
                chainstore: KvChainStore::new("/tmp/utreexod".to_owned()).unwrap(),
                best_block: (0, BlockHash::all_zeros()),
                broadcast_queue: vec![],
                subscribers: vec![],
                fee_estimation: (0_f64, 0_f64, 0_f64),
            }),
        }
    }
    pub fn load_acc(&self) -> Stump {
        let inner = read_lock!(self);
        let acc = inner.chainstore.load_roots().expect("Could not load roots");
        if let Some(acc) = acc {
            let acc = acc.split(' ').collect::<Vec<_>>();
            let leaves = acc.first().expect("Missing leaves count");

            let leaves = leaves
                .parse::<u64>()
                .expect("Invalid number, maybe the accumulator got corrupted?");
            let acc = acc.get(1);
            let mut roots = vec![];

            if let Some(acc) = acc {
                let mut acc = acc.to_string();
                while acc.len() >= 64 {
                    let hash = acc.drain(0..64).collect::<String>();
                    let hash =
                        sha256::Hash::from_hex(hash.as_str()).expect("Invalid hash provided");
                    roots.push(hash);
                }
            }

            Stump {
                leafs: leaves,
                roots,
            }
        } else {
            Stump::new()
        }
    }
}

impl<PersistedState: ChainStore> BlockchainInterface for ChainState<PersistedState> {
    fn connect_block(&self, _block: bitcoin::Block) -> super::Result<u32> {
        // self.acc = BlockchainSync::update_acc(&self.acc, block, height, proof, del_hashes)
        //     .unwrap_or_else(|_| panic!("Could not update the accumulator at {height}"));
        todo!()
    }

    fn get_block_hash(&self, height: u32) -> super::Result<bitcoin::BlockHash> {
        let inner = self.inner.read().expect("get_block_hash: Poisoned lock");
        if let Some(hash) = inner.block_index.get(&height) {
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
        if let Some(header) = inner.block_headers.get(hash) {
            return Ok(*header);
        }
        Err(BlockchainError::BlockNotPresent)
    }
    fn subscribe<F: Fn(bitcoin::Block) -> () + 'static>(&self, callback: F) {
        let mut inner = self.inner.write().expect("get_block_hash: Poisoned lock");
        inner.subscribers.push(Box::new(callback));
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
