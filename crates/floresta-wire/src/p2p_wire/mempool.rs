// SPDX-License-Identifier: MIT
//! A simple mempool that keeps our transactions in memory. It try to rebroadcast
//! our transactions every 1 hour.
//! Once our transaction is included in a block, we remove it from the mempool.
use std::collections::BTreeSet;
use std::collections::HashMap;
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
/// A transaction in the mempool.
///
/// This struct holds the transaction itself, the time when we added it to the mempool, the
/// transactions that depend on it, and the transactions that it depends on. We need those extra
/// informations to make decisions when to include or not a transaction in mempool or in a block.
struct MempoolTransaction {
    transaction: Transaction,
    time: Instant,
    depends: Vec<ShortTxid>,
    children: Vec<ShortTxid>,
}

pub trait BlockHashOracle {
    fn get_block_hash(&self, height: u32) -> Option<BlockHash>;
}

impl<T: BlockchainInterface> BlockHashOracle for T {
    fn get_block_hash(&self, height: u32) -> Option<BlockHash> {
        self.get_block_hash(height).ok()
    }
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
    /// A hasher that we use to compute the short transaction ids.
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
    /// We couldn't find a prevout in the mempool.
    ///
    /// This error only happens when we try to add a transaction without a proof, and we don't have
    /// the prevouts in the mempool.
    PrevoutNotFound,
    /// The transaction is conflicting with another transaction in the mempool.
    ConflictingTransaction,
    /// An error happened while trying to get a proof from the accumulator.
    Rustreexo(String),
    /// The transaction has duplicate inputs.
    DuplicateInput,
    BlockNotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A proof for a transaction in the mempool.
pub struct MempoolProof {
    /// The actual utreexo proof
    pub proof: Proof,
    /// The target hashes that we are trying to prove.
    pub target_hashes: Vec<BitcoinNodeHash>,
    /// The leaf data for the targets we are proving
    pub leaves: Vec<CompactLeafData>,
}

impl Mempool {
    /// Creates a new mempool with a given maximum size and accumulator.
    ///
    /// The acculator should have the same roots as the one inside our chainstate, or we won't be
    /// able to validate proofs.
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

    /// Returns the data of the prevouts that are being spent by a transaction.
    ///
    /// This data isn't part of the actual transaction, usually we would fetch it from the UTXO
    /// set, but we don't have one. Instead, we keep track of the prevouts that are being spent by
    /// transactions in the mempool and use this method to get the data.
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

    /// Proves that a mempool transaction is valid for the latest accumulator state.
    ///
    /// This should return a proof that the transaction is valid, and the data for the prevouts
    /// that are being spent by the transaction.
    pub fn try_prove(
        &self,
        tx: &Transaction,
        block_hash: &impl BlockHashOracle,
    ) -> Result<MempoolProof, AcceptToMempoolError> {
        let mut target_hashes = Vec::new();
        let mut leaves = Vec::new();
        for input in tx.input.iter() {
            let prevout = self
                .prevouts
                .get(&input.previous_output)
                .ok_or(AcceptToMempoolError::PrevoutNotFound)?;

            let block_hash = block_hash.get_block_hash(prevout.header_code >> 1).unwrap();
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

    /// Utility method that grabs one transaction and all its dependencies, then adds them to a tx
    /// list.
    fn add_transaction_to_block(
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
        block_height: u32,
        remember_all: bool,
    ) -> Result<Vec<Transaction>, String> {
        self.acc.modify(adds, del_hashes, proof)?;

        if remember_all {
            // add the newly created UTXOs to the prevouts
            for tx in block.txdata.iter() {
                let is_coinbase = tx.is_coinbase();

                for (vout, output) in tx.output.iter().enumerate() {
                    let leaf_data = CompactLeafData {
                        amount: output.value.to_sat(),
                        spk_ty: proof_util::get_script_type(&output.script_pubkey),
                        header_code: (block_height << 1) | is_coinbase as u32,
                    };

                    let prevout = OutPoint {
                        txid: tx.compute_txid(),
                        vout: vout as u32,
                    };

                    self.prevouts.insert(prevout, leaf_data);
                }

                for input in tx.input.iter() {
                    self.prevouts.remove(&input.previous_output);
                }
            }
        }

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

    /// Proves all transactions included in a block.
    pub fn get_block_proof(
        &self,
        block: &Block,
        get_block_hash: impl BlockHashOracle,
    ) -> Result<MempoolProof, String> {
        let (del_hashes, leaves): (Vec<_>, Vec<_>) = block
            .txdata
            .iter()
            .flat_map(|tx| {
                tx.input
                    .iter()
                    .flat_map(|input| {
                        let prevout = self
                            .prevouts
                            .get(&input.previous_output)
                            .ok_or(AcceptToMempoolError::PrevoutNotFound)?;

                        let block_height = prevout.header_code >> 1;
                        let block_hash = get_block_hash
                            .get_block_hash(block_height)
                            .ok_or(AcceptToMempoolError::BlockNotFound)?;
                        let node_hash = BitcoinNodeHash::Some(
                            proof_util::reconstruct_leaf_data(prevout, input, block_hash)
                                .unwrap()
                                ._get_leaf_hashes()
                                .to_byte_array(),
                        );

                        Ok::<_, AcceptToMempoolError>((node_hash, prevout.clone()))
                    })
                    .collect::<Vec<_>>()
            })
            .unzip();

        let proof = self.acc.batch_proof(&del_hashes)?;

        Ok(MempoolProof {
            proof,
            target_hashes: del_hashes,
            leaves,
        })
    }

    /// Checks if a outpoint is already spent in the mempool.
    ///
    /// This can be used to find conficts before adding a transaction to the mempool.
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

    /// Performs some very basic sanity checks on a transaction before adding it to the mempool.
    ///
    /// This method checks if the transaction doesn't have conflicting inputs, if it doesn't spend
    /// the same output twice, and if it doesn't exceed the memory usage limit.
    fn sanity_check_transaction(
        &self,
        transaction: &Transaction,
    ) -> Result<(), AcceptToMempoolError> {
        let tx_size = transaction.total_size();
        if self.mempool_size + tx_size > self.max_mempool_size {
            return Err(AcceptToMempoolError::MemoryUsageTooHigh);
        }

        // check for duplicate inputs
        let inputs = transaction
            .input
            .iter()
            .map(|input| input.previous_output)
            .collect::<BTreeSet<_>>();

        if inputs.len() != transaction.input.len() {
            return Err(AcceptToMempoolError::DuplicateInput);
        }

        for input in transaction.input.iter() {
            if self.is_already_spent(&input.previous_output) {
                return Err(AcceptToMempoolError::ConflictingTransaction);
            }
        }

        Ok(())
    }

    /// Internal utility to add a transaction to the mempool.
    ///
    /// This method should never be called for transactions coming from the wire, since it doesn't
    /// check if the transaction is valid other than basic constraint checks. This method is used
    /// by the mempool itself to add transactions that are already known to be valid, such as
    /// wallet transactions. For transactions coming from the wire, use `accept_to_mempool`.
    pub fn accept_to_mempool_no_acc(
        &mut self,
        transaction: Transaction,
    ) -> Result<(), AcceptToMempoolError> {
        let tx_size = transaction.total_size();
        self.mempool_size += tx_size;

        let short_txid = self.hasher.hash_one(&transaction.compute_txid());
        let depends = self.find_mempool_depends(&transaction);

        // this function should only be called if it spends unconfirmed outputs
        // Check if the inputs are actually in the mempool
        for input in transaction.input.iter() {
            if self.prevouts.contains_key(&input.previous_output) {
                continue;
            }

            let short_txid = self.hasher.hash_one(&input.previous_output.txid);
            if self.transactions.contains_key(&short_txid) {
                continue;
            }

            return Err(AcceptToMempoolError::PrevoutNotFound);
        }

        self.sanity_check_transaction(&transaction)?;

        for depend in depends.iter() {
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
    use std::collections::HashMap;
    use std::collections::HashSet;

    use bitcoin::absolute;
    use bitcoin::block;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::Block;
    use bitcoin::BlockHash;
    use bitcoin::OutPoint;
    use bitcoin::Script;
    use bitcoin::ScriptBuf;
    use bitcoin::Sequence;
    use bitcoin::Target;
    use bitcoin::Transaction;
    use bitcoin::Witness;
    use floresta_chain::LeafData;
    use rand::Rng;
    use rand::SeedableRng;
    use rustreexo::accumulator::node_hash::BitcoinNodeHash;
    use rustreexo::accumulator::pollard::PollardAddition;
    use rustreexo::accumulator::proof::Proof;

    use super::BlockHashOracle;
    use crate::mempool::MempoolProof;

    struct BlockHashProvider {
        block_hash: HashMap<u32, BlockHash>,
    }

    impl BlockHashOracle for BlockHashProvider {
        fn get_block_hash(&self, height: u32) -> Option<BlockHash> {
            self.block_hash.get(&height).cloned()
        }
    }

    /// builds a list of transactions in a pseudo-random way
    ///
    /// We use those transactions in mempool tests
    fn build_transactions(seed: u64, conflict: bool) -> Vec<Transaction> {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let mut transactions = Vec::new();

        let n = rng.gen_range(1..1_000);
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
                let previous_output: OutPoint = match conflict {
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
    fn test_block_proof() {
        let mut mempool = super::Mempool::new(
            rustreexo::accumulator::pollard::Pollard::default(),
            10_000_000,
        );

        let coinbase_spk: ScriptBuf = Script::from_bytes(&[0x6a]).into();

        let coinbase = bitcoin::Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::from_consensus(0),
            input: Vec::new(),
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(50_000_000),
                script_pubkey: coinbase_spk.clone(),
            }],
        };

        let coinbase_id = coinbase.compute_txid();

        let block = Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 0,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata: vec![coinbase],
        };

        let coinbase_out_leaf = LeafData {
            prevout: OutPoint {
                txid: coinbase_id,
                vout: 0,
            },
            utxo: bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(50_000_000),
                script_pubkey: coinbase_spk.clone(),
            },
            block_hash: block.block_hash(),
            header_code: 0,
        };

        let coinbase_out = PollardAddition::<BitcoinNodeHash> {
            hash: coinbase_out_leaf._get_leaf_hashes().into(),
            remember: true,
        };

        mempool
            .consume_block(&block, Proof::default(), &[coinbase_out], &[], 0, true)
            .expect("failed to consume block");

        let spending_tx = bitcoin::Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::from_consensus(0),
            input: vec![bitcoin::TxIn {
                previous_output: OutPoint {
                    txid: coinbase_id,
                    vout: 0,
                },
                script_sig: ScriptBuf::default().into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(50_000_000),
                script_pubkey: coinbase_spk.clone(),
            }],
        };

        let hashes = BlockHashProvider {
            block_hash: [(0, block.block_hash())].iter().cloned().collect(),
        };

        mempool
            .accept_to_mempool_no_acc(spending_tx)
            .expect("failed to accept to mempool");
        let block = mempool.get_block_template(
            block::Version::ONE,
            block.block_hash(),
            0,
            Target::MAX_ATTAINABLE_REGTEST.to_compact_lossy(),
        );

        let MempoolProof {
            proof,
            target_hashes,
            ..
        } = mempool
            .get_block_proof(&block, hashes)
            .expect("failed to get block proof");

        assert!(mempool.acc.verify(&proof, &target_hashes).is_ok());
    }

    #[test]
    fn test_random() {
        // just sanity check for build_transactions
        let transactions = build_transactions(42, true);
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
            mempool
                .accept_to_mempool_no_acc(tx)
                .expect("failed to accept to mempool");
        }

        assert_eq!(mempool.transactions.len(), len);
    }

    #[test]
    fn test_gbt_with_conflict() {
        let mut mempool = super::Mempool::new(
            rustreexo::accumulator::pollard::Pollard::default(),
            10_000_000,
        );

        let transactions = build_transactions(21, true);

        let mut did_confict = false;
        for tx in transactions {
            if let Err(_) = mempool.accept_to_mempool_no_acc(tx) {
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

        check_block_transactions(block);
    }

    fn check_block_transactions(block: Block) {
        // make sure that all outputs are spent after being created, and only once
        let mut outputs = HashSet::new();
        for tx in block.txdata.iter() {
            for input in tx.input.iter() {
                if input.previous_output.txid == bitcoin::Txid::all_zeros() {
                    continue;
                }

                assert!(
                    outputs.remove(&input.previous_output),
                    "double spend {input:?}"
                );
            }

            for (vout, _) in tx.output.iter().enumerate() {
                let output = OutPoint {
                    txid: tx.compute_txid(),
                    vout: vout as u32,
                };
                outputs.insert(output);
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
            mempool
                .accept_to_mempool_no_acc(tx)
                .expect("failed to accept to mempool");
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

        check_block_transactions(block);
    }
}
