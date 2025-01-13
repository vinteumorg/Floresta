// SPDX-License-Identifier: MIT
//! A simple mempool that keeps our transactions in memory. It try to rebroadcast
//! our transactions every 1 hour.
//! Once our transaction is included in a block, we remove it from the mempool.
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::HashSet;
use std::time::Duration;
use std::time::Instant;

use bitcoin::block::Header;
use bitcoin::block::Version;
use bitcoin::hashes::Hash;
use bitcoin::Amount;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::CompactTarget;
use bitcoin::OutPoint;
use bitcoin::Transaction;
use bitcoin::TxMerkleNode;
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

/// A short transaction id that we use to identify transactions in the mempool.
///
/// We use this to keep track of dependencies between transactions, since keeping the full txid
/// would be too expensive. This value is computed using a keyed hash function, with a local key
/// that only we know. This way, peers can't cause collisions and make our mempool slow.
type ShortTxid = u64;

#[derive(Debug)]
struct MempoolTransaction {
    transaction: Transaction,
    time: Instant,
    depends: Vec<ShortTxid>,
    children: Vec<ShortTxid>,
}

/// Holds the transactions that we broadcasted and are still in the mempool.
#[derive(Debug)]
pub struct Mempool {
    /// A list of all transactions we currently have in the mempool.
    ///
    /// Transactions are kept as a map of their transaction id to the transaction itself, we
    /// also keep track of when we added the transaction to the mempool to be able to remove
    /// stale transactions.
    transactions: HashMap<ShortTxid, MempoolTransaction>,
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
    hasher: ahash::RandomState,
}

unsafe impl Send for Mempool {}

#[derive(Debug, Clone, PartialEq, Eq)]
/// An error returned when we try to add a transaction to the mempool.
pub enum AcceptToMempoolError {
    /// The proof provided is invalid.
    InvalidProof,
    /// The transaction is trying to spend an output that we don't have.
    InvalidPrevout,
    /// Memory usage is too high.
    MemoryUsageTooHigh,
    PrevoutNotFound,
    ConflictingTransaction,
    Rustreexo(String),
}

pub struct MempoolProof {
    pub proof: Proof,
    pub target_hashes: Vec<BitcoinNodeHash>,
    pub leaves: Vec<CompactLeafData>,
}

impl Mempool {
    pub fn new(acc: Pollard<BitcoinNodeHash>, max_mempool_size: usize) -> Mempool {
        let a = rand::random();
        let b = rand::random();
        let c = rand::random();
        let d = rand::random();

        let hasher = ahash::RandomState::with_seeds(a, b, c, d);

        Mempool {
            transactions: HashMap::new(),
            prevouts: HashMap::new(),
            queue: Vec::new(),
            mempool_size: 0,
            max_mempool_size,
            acc,
            hasher,
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
        self.transactions
            .keys()
            .map(|id| self.transactions[id].transaction.compute_txid())
            .collect()
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
            let leaf_data: LeafData = proof_util::reconstruct_leaf_data(prevout, input, block_hash)
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
    pub fn get_block_template(
        &self,
        version: Version,
        prev_blockhash: BlockHash,
        time: u32,
        bits: CompactTarget,
    ) -> Block {
        // add transactions until we reach the block limit
        let mut size = 0;

        let mut txs = Vec::new();
        for (_, tx) in self.transactions.iter() {
            let tx_size = tx.transaction.weight().to_wu();
            if size + tx_size > 4_000_000 {
                break;
            }

            if txs.contains(&tx.transaction) {
                continue;
            }

            size += tx_size;
            let short_txid = self.hasher.hash_one(&tx.transaction.compute_txid());
            self.add_transaction_to_block(&mut txs, short_txid);
        }

        let mut block = Block {
            header: Header {
                version,
                prev_blockhash,
                merkle_root: TxMerkleNode::all_zeros(),
                time,
                bits,
                nonce: 0,
            },
            txdata: txs,
        };

        block.header.merkle_root = block.compute_merkle_root().unwrap();
        block
    }

    pub fn add_transaction_to_block(
        &self,
        block_transactions: &mut Vec<Transaction>,
        short_txid: ShortTxid,
    ) {
        let transaction = self.transactions.get(&short_txid).unwrap();
        if block_transactions.contains(&transaction.transaction) {
            return;
        }

        let depends_on = transaction.depends.clone();

        for depend in depends_on {
            self.add_transaction_to_block(block_transactions, depend);
        }

        block_transactions.push(transaction.transaction.clone());
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
                let short_txid = self.hasher.hash_one(&tx.compute_txid());
                self.transactions
                    .remove(&short_txid)
                    .map(|tx| tx.transaction)
            })
            .collect())
    }

    pub fn get_block_proof(&self, del_hashes: &[BitcoinNodeHash]) -> Result<Proof, String> {
        self.acc.batch_proof(del_hashes)
    }

    fn is_already_spent(&self, outpoint: &OutPoint) -> bool {
        let short_txid = self.hasher.hash_one(&outpoint.txid);
        let Some(tx) = self.transactions.get(&short_txid) else {
            return false;
        };

        tx.children.iter().any(|child| {
            let Some(child_tx) = self.transactions.get(child) else {
                return false;
            };

            child_tx.transaction.input.iter().any(|input| {
                input.previous_output.txid == outpoint.txid
                    && input.previous_output.vout == outpoint.vout
            })
        })
    }

    pub fn accept_to_mempool_no_acc(&mut self, transaction: Transaction) -> Result<(), AcceptToMempoolError> {
        let tx_size = transaction.total_size();
        self.mempool_size += tx_size;

        let short_txid = self.hasher.hash_one(&transaction.compute_txid());
        let depends = self.find_mempool_depends(&transaction);
        
        // check for duplicate inputs
        let inputs = transaction.input.iter().map(|input| input.previous_output).collect::<BTreeSet<_>>();
        if inputs.len() != transaction.input.len() {
            return Err(AcceptToMempoolError::ConflictingTransaction);
        }

        for depend in depends.iter() {
            // check if the input is already spent
            for input in transaction.input.iter() {
                if self.is_already_spent(&input.previous_output) {
                    return Err(AcceptToMempoolError::ConflictingTransaction);
                }
            }

            let tx = self.transactions.get_mut(depend).unwrap();
            tx.children.push(short_txid);
        }

        self.transactions.insert(
            short_txid,
            MempoolTransaction {
                time: Instant::now(),
                depends,
                transaction,
                children: Vec::new(),
            },
        );

        Ok(())
    }

    fn find_mempool_depends(&self, tx: &Transaction) -> Vec<ShortTxid> {
        tx.input
            .iter()
            .filter_map(|input| {
                let short_txid = self.hasher.hash_one(&input.previous_output.txid);
                self.transactions.get(&short_txid).map(|_| short_txid)
            })
            .collect()
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

        let short_txid = self.hasher.hash_one(&transaction.compute_txid());
        let depends = self.find_mempool_depends(&transaction);

        for depend in depends.iter() {
            // check if the input is already spent
            for input in transaction.input.iter() {
                if self.is_already_spent(&input.previous_output) {
                    return Err(AcceptToMempoolError::ConflictingTransaction);
                }
            }

            let tx = self.transactions.get_mut(depend).unwrap();
            tx.children.push(short_txid);
        }

        self.transactions.insert(
            short_txid,
            MempoolTransaction {
                time: Instant::now(),
                depends,
                transaction,
                children: Vec::new(),
            },
        );



        Ok(())
    }

    /// Get a transaction from the mempool.
    pub fn get_from_mempool<'a>(&'a self, id: &Txid) -> Option<&'a Transaction> {
        let id = self.hasher.hash_one(id);
        self.transactions.get(&id).map(|tx| &tx.transaction)
    }

    /// Get all transactions that were in the mempool for more than 1 hour.
    pub fn get_stale(&mut self) -> Vec<Txid> {
        self.transactions
            .iter()
            .filter_map(|(_, tx)| {
                let txid = tx.transaction.compute_txid();
                if tx.time.elapsed() > Duration::from_secs(3600) {
                    Some(txid)
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use bitcoin::{absolute, block, hashes::Hash, transaction::Version, CompactTarget, OutPoint, Sequence, Target, Transaction, Witness};
    /// builds a list of transactions in a pseudo-random way
    ///
    /// We use those transactions in mempool tests
    use rand::{Rng, SeedableRng};
    use rustreexo::accumulator::pollard::Pollard;

    fn build_transactions(seed: u64, conflict: bool) -> Vec<Transaction> {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let mut transactions = Vec::new();
        
        let n = rng.gen_range(1..10_000);
        let mut outputs = Vec::new();

        for _ in 0..n {
            let mut tx = bitcoin::Transaction {
                version: Version::ONE,
                lock_time: absolute::LockTime::from_consensus(0),
                input: Vec::new(),
                output: Vec::new(),
            };
            
            let inputs = rng.gen_range(1..10);
            for _ in 0..inputs {
                if outputs.is_empty() {
                    break;
                }

                let index = rng.gen_range(0..outputs.len());
                let previous_output: OutPoint = match conflict  {
                    false => outputs.remove(index),
                    true => outputs.get(index).unwrap().clone(),
                };

                let input = bitcoin::TxIn {
                    previous_output,
                    script_sig: bitcoin::Script::new().into(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                };

                tx.input.push(input);
            }
            
            let n = rng.gen_range(1..10);
            
            for _ in 0..n {
                let script = rng.gen::<[u8; 32]>();
                let output = bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(rng.gen_range(0..100_000_000)),
                    script_pubkey: bitcoin::Script::from_bytes(&script).into(),
                };
                
                tx.output.push(output);
            }

            outputs.extend(tx.output.iter().enumerate().map(|(vout, _)| OutPoint {
                txid: tx.compute_txid(),
                vout: vout as u32,
            }));
            
            transactions.push(tx);
        }

        transactions
    }
    
    #[test]
    fn test_random() {
        // just sanity check for build_transactions
        let transactions = build_transactions(42, false);
        assert!(!transactions.is_empty());

        let transactions2 = build_transactions(42, true);
        assert!(!transactions2.is_empty());
        assert_eq!(transactions, transactions2);
        
        let transactions3 = build_transactions(43, true);
        assert!(!transactions3.is_empty());
        assert_ne!(transactions, transactions3);
    }

    #[test]
    fn test_mepool_accept_no_acc() {
        let mut mempool = super::Mempool::new(
            rustreexo::accumulator::pollard::Pollard::default(),
            10_000_000,
        );

        let transactions = build_transactions(42, false);
        let len = transactions.len();

        for tx in transactions {
            mempool.accept_to_mempool_no_acc(tx).expect("failed to accept to mempool");
        }

        assert_eq!(mempool.transactions.len(), len);
    }
    
    #[test]
    fn test_gbt_with_conflict() {
        let mut mempool = super::Mempool::new(
            rustreexo::accumulator::pollard::Pollard::default(),
            10_000_000,
        );

        let transactions = build_transactions(42, true);
        let len = transactions.len();
        
        let mut did_confict = false;
        for tx in transactions {
            if let Err(super::AcceptToMempoolError::ConflictingTransaction) = mempool.accept_to_mempool_no_acc(tx) {
                did_confict = true;
            }
        }
        
        // we expect at least one conflict
        assert!(did_confict);
        
        let target = Target::MAX_ATTAINABLE_REGTEST;
        let mut block = mempool.get_block_template(
            block::Version::ONE,
            bitcoin::BlockHash::all_zeros(),
            0,
            target.to_compact_lossy(),
        );
        
        while !block.header.validate_pow(target).is_ok() {
            block.header.nonce += 1;
        }

        assert!(block.check_merkle_root());
    
        // make sure that all outputs are spent after being created, and only once
        let mut outputs = HashSet::new();
        for tx in block.txdata.iter() {
            for (vout, _) in tx.output.iter().enumerate() {
                let output = OutPoint {
                    txid: tx.compute_txid(),
                    vout: vout as u32,
                };
                outputs.insert(output);
            }
        }

        for tx in block.txdata.iter() {
            for input in tx.input.iter() {
                if input.previous_output.txid == bitcoin::Txid::all_zeros() {
                    continue;
                }
                assert!(outputs.remove(&input.previous_output), "double spend {input:?}");
            }
        }
    }

    #[test]
    fn test_gbt() {
        let mut mempool = super::Mempool::new(
            rustreexo::accumulator::pollard::Pollard::default(),
            10_000_000,
        );

        let transactions = build_transactions(42, false);
        let len = transactions.len();

        for tx in transactions {
            mempool.accept_to_mempool_no_acc(tx).expect("failed to accept to mempool");
        }
        
        let target = Target::MAX_ATTAINABLE_REGTEST;
        let mut block = mempool.get_block_template(
            block::Version::ONE,
            bitcoin::BlockHash::all_zeros(),
            0,
            target.to_compact_lossy(),
        );
        
        while !block.header.validate_pow(target).is_ok() {
            block.header.nonce += 1;
        }

        
        assert_eq!(block.txdata.len(), len);
        assert!(block.check_merkle_root());
    
        // make sure that all outputs are spent after being created, and only once
        let mut outputs = HashSet::new();
        for tx in block.txdata.iter() {
            for (vout, _) in tx.output.iter().enumerate() {
                let output = OutPoint {
                    txid: tx.compute_txid(),
                    vout: vout as u32,
                };
                outputs.insert(output);
            }
        }

        for tx in block.txdata.iter() {
            for input in tx.input.iter() {
                if input.previous_output.txid == bitcoin::Txid::all_zeros() {
                    continue;
                }
                assert!(outputs.remove(&input.previous_output), "double spend {input:?}");
            }
        }
    }
}
