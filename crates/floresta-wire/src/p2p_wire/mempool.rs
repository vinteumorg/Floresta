// SPDX-License-Identifier: MIT
//! A simple mempool that keeps our transactions in memory. It try to rebroadcast
//! our transactions every 1 hour.
//! Once our transaction is included in a block, we remove it from the mempool.
use std::collections::HashMap;
use std::time::Duration;
use std::time::Instant;

use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::Amount;
use bitcoin::Block;
use bitcoin::OutPoint;
use bitcoin::Transaction;
use bitcoin::TxOut;
use bitcoin::Txid;
use floresta_chain::proof_util;
use floresta_chain::pruned_utreexo::BlockchainInterface;
use floresta_chain::CompactLeafData;
use floresta_chain::LeafData;
use rustreexo::accumulator::node_hash::BitcoinNodeHash;
use rustreexo::accumulator::pollard::Pollard;
use rustreexo::accumulator::pollard::PollardAddition;
use rustreexo::accumulator::proof::Proof;

/// Holds the transactions that we broadcasted and are still in the mempool.
#[derive(Debug, Default)]
pub struct Mempool {
    /// A list of all transactions we currently have in the mempool.
    ///
    /// Transactions are kept as a map of their transaction id to the transaction itself, we
    /// also keep track of when we added the transaction to the mempool to be able to remove
    /// stale transactions.
    transactions: HashMap<Txid, (Transaction, Instant)>,
    /// How much memory (in bytes) does the mempool currently use.
    mempool_size: usize,
    /// The maximum size of the mempool in bytes.
    max_mempool_size: usize,
    /// The accumulator that we use to verify proofs.
    ///
    /// This is a Pollard, a light version of a Utreexo accumulator that allows you to hold some
    /// leaves, but not all of them. We use this to keep track of mempool proofs so we don't need
    /// to re-download them.
    acc: Pollard<BitcoinNodeHash>,
    /// A map of all the prevouts that are being spent by transactions in the mempool.
    ///
    /// Since we don't have a full UTXO set, we need to keep track of the outputs that are being
    /// spent in order to perform validation and fee calculation.
    prevouts: HashMap<OutPoint, CompactLeafData>,
    /// A queue of transaction we know about, but don't have a proof for
    queue: Vec<Txid>,
}

unsafe impl Send for Mempool {}

#[derive(Debug, Clone)]
/// An error returned when we try to add a transaction to the mempool.
pub enum AcceptToMempoolError {
    /// The proof provided is invalid.
    InvalidProof,
    /// The transaction is trying to spend an output that we don't have.
    InvalidPrevout,
    /// Memory usage is too high.
    MemoryUsageTooHigh,
    PrevoutNotFound,
    Rustreexo(String),
}

pub struct MempoolProof {
    pub proof: Proof,
    pub target_hashes: Vec<BitcoinNodeHash>,
    pub leaves: Vec<CompactLeafData>,
}

impl Mempool {
    pub fn new(acc: Pollard<BitcoinNodeHash>, max_mempool_size: usize) -> Mempool {
        Mempool {
            transactions: HashMap::new(),
            prevouts: HashMap::new(),
            queue: Vec::new(),
            mempool_size: 0,
            max_mempool_size,
            acc,
        }
    }

    /// List transactions we are pending to process.
    ///
    /// Usually, we don't have a proof for these transactions, so we can't add them to the mempool,
    /// a wire implementation should call this method and try to get a proof for these
    /// transactions.
    pub fn list_unprocessed(&self) -> Vec<Txid> {
        self.queue.clone()
    }

    /// List all transactions we've accepted to the mempool.
    ///
    /// This won't count transactions that are still in the queue.
    pub fn list_mempool(&self) -> Vec<Txid> {
        self.transactions.keys().cloned().collect()
    }

    pub fn get_prevouts(&self, tx: &Transaction) -> Vec<TxOut> {
        tx.input
            .iter()
            .filter_map(|input| {
                let leaf_data = self.prevouts.get(&input.previous_output)?;
                let script_pubkey = proof_util::reconstruct_script_pubkey(leaf_data, input).ok()?;
                Some(TxOut {
                    value: Amount::from_sat(leaf_data.amount),
                    script_pubkey,
                })
            })
            .collect()
    }

    pub fn try_prove(
        &self,
        tx: &Transaction,
        chain: &impl BlockchainInterface,
    ) -> Result<MempoolProof, AcceptToMempoolError> {
        let mut target_hashes = Vec::new();
        let mut leaves = Vec::new();
        for input in tx.input.iter() {
            let prevout = self
                .prevouts
                .get(&input.previous_output)
                .ok_or(AcceptToMempoolError::PrevoutNotFound)?;

            let block_hash = chain.get_block_hash(prevout.header_code >> 1).unwrap();
            let leaf_data: LeafData =
                proof_util::reconstruct_leaf_data(prevout, input, block_hash)
                    .map_err(|_| AcceptToMempoolError::InvalidPrevout)?;

            let hash = leaf_data._get_leaf_hashes();
            let hash = BitcoinNodeHash::Some(hash.to_byte_array());

            target_hashes.push(hash);
            leaves.push(prevout.clone());
        }

        let proof = self
            .acc
            .batch_proof(&target_hashes)
            .map_err(AcceptToMempoolError::Rustreexo)?;

        Ok(MempoolProof {
            proof,
            target_hashes,
            leaves,
        })
    }

    /// Returns a list of transactions that are in the mempool up to the block weight limit.
    ///
    /// You can use this method to produce a template and mine a block.
    pub fn get_block_template(&self, block_header: Header) -> Block {
        // add transactions until we reach the block limit
        let mut size = 0;
        let mut txs = Vec::new();
        for (_, (tx, _)) in self.transactions.iter() {
            let tx_size = tx.weight().to_wu();
            if size + tx_size > 4_000_000 {
                break;
            }

            size += tx_size;
            txs.push(tx.clone());
        }

        Block {
            header: block_header,
            txdata: txs,
        }
    }

    /// Consume a block and remove all transactions that were included in it.
    ///
    /// This method will remove all transactions that were included in the block from the mempool,
    /// update the local accumulator and return the transactions that were included in the block.
    pub fn consume_block(
        &mut self,
        block: &Block,
        proof: Proof,
        adds: &[PollardAddition<BitcoinNodeHash>],
        del_hashes: &[BitcoinNodeHash],
    ) -> Result<Vec<Transaction>, String> {
        if self.transactions.is_empty() {
            return Ok(Vec::new());
        }

        self.acc.modify(adds, del_hashes, proof)?;

        Ok(block
            .txdata
            .iter()
            .filter_map(|tx| {
                self.transactions
                    .remove(&tx.compute_txid())
                    .map(|(tx, _)| tx)
            })
            .collect())
    }

    pub fn get_block_proof(
        &self,
        _adds: &[PollardAddition<BitcoinNodeHash>],
        _del_hashes: &[BitcoinNodeHash],
    ) -> Result<Proof, &str> {
        todo!()
    }

    pub fn accept_to_mempool_no_acc(&mut self, transaction: Transaction) {
        let tx_size = transaction.total_size();
        self.mempool_size += tx_size;
        self.transactions
            .insert(transaction.compute_txid(), (transaction, Instant::now()));
    }

    /// Add a transaction to the mempool.
    pub fn accept_to_mempool(
        &mut self,
        transaction: Transaction,
        proof: Proof,
        prevouts: &[(OutPoint, CompactLeafData)],
        del_hashes: &[BitcoinNodeHash],
        remembers: &[u64],
    ) -> Result<(), AcceptToMempoolError> {
        let tx_size = transaction.total_size();

        if self.mempool_size + tx_size > self.max_mempool_size {
            return Err(AcceptToMempoolError::MemoryUsageTooHigh);
        }

        self.acc
            .verify_and_ingest(proof, del_hashes, remembers)
            .map_err(|_| AcceptToMempoolError::InvalidProof)?;

        self.prevouts.extend(prevouts.iter().cloned());
        self.transactions
            .insert(transaction.compute_txid(), (transaction, Instant::now()));

        Ok(())
    }

    /// Get a transaction from the mempool.
    pub fn get_from_mempool(&self, id: &Txid) -> Option<&Transaction> {
        self.transactions.get(id).map(|(tx, _)| tx)
    }

    /// Get all transactions that were in the mempool for more than 1 hour.
    pub fn get_stale(&mut self) -> Vec<Txid> {
        self.transactions
            .iter()
            .filter_map(|(id, (_, time))| {
                if time.elapsed() > Duration::from_secs(3600) {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect()
    }
}
