// SPDX-License-Identifier: MIT
//! A simple mempool that keeps our transactions in memory. It try to rebroadcast
//! our transactions every 1 hour.
//! Once our transaction is included in a block, we remove it from the mempool.
use std::collections::HashMap;
use std::time::Duration;
use std::time::Instant;

use bitcoin::Block;
use bitcoin::Transaction;
use bitcoin::Txid;
/// Holds the transactions that we broadcasted and are still in the mempool.
#[derive(Debug, Default)]
pub struct Mempool(HashMap<Txid, (Transaction, Instant)>);

impl Mempool {
    pub fn new() -> Mempool {
        Mempool(HashMap::new())
    }
    /// Find all transactions that are in the mempool and were included in the given block.
    /// Remove them from the mempool and return them.
    pub fn consume_block(&mut self, block: &Block) -> Vec<Transaction> {
        if self.0.is_empty() {
            return Vec::new();
        }
        let mut delta = Vec::new();
        for tx in block.txdata.iter() {
            if self.0.contains_key(&tx.txid()) {
                delta.push(self.0.remove(&tx.txid()));
            }
        }
        delta.into_iter().flat_map(|tx| Some(tx?.0)).collect()
    }
    /// Add a transaction to the mempool.
    pub fn accept_to_mempool(&mut self, transaction: Transaction) {
        self.0
            .insert(transaction.txid(), (transaction, Instant::now()));
    }
    /// Get a transaction from the mempool.
    pub fn get_from_mempool(&self, id: &Txid) -> Option<&Transaction> {
        if let Some(tx) = self.0.get(id) {
            return Some(&tx.0);
        }
        None
    }
    /// Get all transactions that were in the mempool for more than 1 hour.
    pub fn get_stale(&mut self) -> Vec<Txid> {
        let mut stale = Vec::new();
        for (txid, transaction) in self.0.iter_mut() {
            if transaction.1.elapsed() > Duration::from_secs(60 * 60) {
                transaction.1 = Instant::now();
                stale.push(*txid);
            }
        }
        stale
    }
}
