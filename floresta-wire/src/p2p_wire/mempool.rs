use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use bitcoin::{Block, Transaction, Txid};

#[derive(Debug, Default)]
pub struct Mempool(HashMap<Txid, (Transaction, Instant)>);
impl Mempool {
    pub fn new() -> Mempool {
        Mempool(HashMap::new())
    }
    pub fn consume_block(&mut self, block: &Block) -> Vec<Transaction> {
        if self.0.is_empty() {
            return vec![];
        }
        let mut delta = vec![];
        for tx in block.txdata.iter() {
            if self.0.contains_key(&tx.txid()) {
                delta.push(self.0.remove(&tx.txid()));
            }
        }
        delta.into_iter().flat_map(|tx| Some(tx?.0)).collect()
    }
    pub fn accept_to_mempool(&mut self, transaction: Transaction) {
        self.0
            .insert(transaction.txid(), (transaction, Instant::now()));
    }
    pub fn get_from_mempool(&self, id: &Txid) -> Option<&Transaction> {
        if let Some(tx) = self.0.get(id) {
            return Some(&tx.0);
        }
        None
    }
    pub fn get_stale(&mut self) -> Vec<Txid> {
        let mut stale = vec![];
        for (txid, transaction) in self.0.iter_mut() {
            if transaction.1.elapsed() > Duration::from_secs(60 * 60) {
                transaction.1 = Instant::now();
                stale.push(*txid);
            }
        }
        stale
    }
}
