//! A collection of functions that implement the consensus rules for the Bitcoin Network.
//! This module contains functions that are used to verify blocks and transactions, and doesn't
//! assume anything about the chainstate, so it can be used in any context.
//! We use this to avoid code reuse among the different implementations of the chainstate.
extern crate alloc;

use core::ffi::c_uint;

use bitcoin::block::Header as BlockHeader;
use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use bitcoin::Block;
use bitcoin::CompactTarget;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Target;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Txid;
use floresta_common::prelude::*;
use rustreexo::accumulator::proof::Proof;
use rustreexo::accumulator::stump::Stump;

use super::chainparams::ChainParams;
use super::error::BlockValidationErrors;
use super::error::BlockchainError;
use super::udata;
use crate::TransactionError;

/// The value of a single coin in satoshis.
pub const COIN_VALUE: u64 = 100_000_000;

/// The version tag to be prepended to the leafhash. It's just the sha512 hash of the string
/// `UtreexoV1` represented as a vector of [u8] ([85 116 114 101 101 120 111 86 49]).
/// The same tag is "5574726565786f5631" as a hex string.
pub const UTREEXO_TAG_V1: [u8; 64] = [
    0x5b, 0x83, 0x2d, 0xb8, 0xca, 0x26, 0xc2, 0x5b, 0xe1, 0xc5, 0x42, 0xd6, 0xcc, 0xed, 0xdd, 0xa8,
    0xc1, 0x45, 0x61, 0x5c, 0xff, 0x5c, 0x35, 0x72, 0x7f, 0xb3, 0x46, 0x26, 0x10, 0x80, 0x7e, 0x20,
    0xae, 0x53, 0x4d, 0xc3, 0xf6, 0x42, 0x99, 0x19, 0x99, 0x31, 0x77, 0x2e, 0x03, 0x78, 0x7d, 0x18,
    0x15, 0x6e, 0xb3, 0x15, 0x1e, 0x0e, 0xd1, 0xb3, 0x09, 0x8b, 0xdc, 0x84, 0x45, 0x86, 0x18, 0x85,
];

/// This struct contains all the information and methods needed to validate a block,
/// it is used by the [ChainState] to validate blocks and transactions.
#[derive(Debug, Clone)]
pub struct Consensus {
    /// The parameters of the chain we are validating, it is usually hardcoded
    /// constants. See [ChainParams] for more information.
    pub parameters: ChainParams,
}

impl Consensus {
    /// Returns the amount of block subsidy to be paid in a block, given it's height.
    /// Bitcoin Core source: https://github.com/bitcoin/bitcoin/blob/2b211b41e36f914b8d0487e698b619039cc3c8e2/src/validation.cpp#L1501-L1512
    pub fn get_subsidy(&self, height: u32) -> u64 {
        let halvings = height / self.parameters.subsidy_halving_interval as u32;
        // Force block reward to zero when right shift is undefined.
        if halvings >= 64 {
            return 0;
        }
        let mut subsidy = 50 * COIN_VALUE;
        // Subsidy is cut in half every 210,000 blocks which will occur approximately every 4 years.
        subsidy >>= halvings;
        subsidy
    }

    /// Verify if all transactions in a block are valid. Here we check the following:
    /// - The block must contain at least one transaction, and this transaction must be coinbase
    /// - The first transaction in the block must be coinbase
    /// - The coinbase transaction must have the correct value (subsidy + fees)
    /// - The block must not create more coins than allowed
    /// - All transactions must be valid:
    ///     - The transaction must not be coinbase (already checked)
    ///     - The transaction must not have duplicate inputs
    ///     - The transaction must not spend more coins than it claims in the inputs
    ///     - The transaction must have valid scripts
    #[allow(unused)]
    pub fn verify_block_transactions(
        height: u32,
        mut utxos: HashMap<OutPoint, TxOut>,
        transactions: &[Transaction],
        subsidy: u64,
        verify_script: bool,
        flags: c_uint,
    ) -> Result<(), BlockchainError> {
        // Blocks must contain at least one transaction (i.e. the coinbase)
        if transactions.is_empty() {
            return Err(BlockValidationErrors::EmptyBlock)?;
        }

        // Total block fees that the miner can claim in the coinbase
        let mut fee = 0;

        for (n, transaction) in transactions.iter().enumerate() {
            let txid = || transaction.compute_txid();

            if n == 0 {
                if !transaction.is_coinbase() {
                    return Err(BlockValidationErrors::FirstTxIsNotCoinbase)?;
                }
                // Check coinbase input and output script limits
                Self::verify_coinbase(transaction)?;
                // Skip next checks: coinbase input is exempt, coinbase reward checked later
                continue;
            }

            // Sum tx output amounts. This will be used for the fee calculation
            let out_value: u64 = transaction
                .output
                .iter()
                .map(|out| out.value.to_sat())
                .sum();

            // Sum tx input amounts, check their unlocking script sizes (scriptsig and TODO witness)
            let mut in_value = 0;
            for input in transaction.input.iter() {
                let txo = Self::get_utxo(input, &utxos, txid)?;

                in_value += txo.value.to_sat();

                Self::validate_script_size(&input.script_sig, txid)?;
                // TODO check also witness script size
            }

            // Value in should be greater or equal to value out. Otherwise, inflation.
            if out_value > in_value {
                return Err(tx_err!(txid, NotEnoughMoney))?;
            }
            // Sanity check
            if out_value > 21_000_000 * COIN_VALUE {
                return Err(BlockValidationErrors::TooManyCoins)?;
            }

            // Fee is the difference between inputs and outputs
            fee += in_value - out_value;

            // Verify the tx script
            #[cfg(feature = "bitcoinconsensus")]
            if verify_script {
                transaction
                    .verify_with_flags(|outpoint| utxos.remove(outpoint), flags)
                    .map_err(|e| tx_err!(txid, ScriptValidationError, e.to_string()))?;
            };
        }

        // Check coinbase output values to ensure the miner isn't producing excess coins
        let allowed_reward = fee + subsidy;
        let coinbase_total: u64 = transactions[0]
            .output
            .iter()
            .map(|out| out.value.to_sat())
            .sum();

        if coinbase_total > allowed_reward {
            return Err(BlockValidationErrors::BadCoinbaseOutValue)?;
        }

        Ok(())
    }

    /// Returns the TxOut being spent by the given input.
    ///
    /// Fails if the UTXO is not present in the given hashmap.
    fn get_utxo<'a, F: Fn() -> Txid>(
        input: &TxIn,
        utxos: &'a HashMap<OutPoint, TxOut>,
        txid: F,
    ) -> Result<&'a TxOut, TransactionError> {
        match utxos.get(&input.previous_output) {
            Some(txout) => Ok(txout),
            // This is the case when the spender:
            // - Spends an UTXO that doesn't exist
            // - Spends an UTXO that was already spent
            None => Err(tx_err!(txid, UtxoNotFound, input.previous_output)),
        }
    }

    #[allow(unused)]
    fn validate_locktime(
        input: &TxIn,
        transaction: &Transaction,
        height: u32,
    ) -> Result<(), BlockValidationErrors> {
        unimplemented!("validate_locktime")
    }

    /// Validates the script size and the number of sigops in a scriptpubkey or scriptsig.
    fn validate_script_size<F: Fn() -> Txid>(
        script: &ScriptBuf,
        txid: F,
    ) -> Result<(), TransactionError> {
        // The maximum script size for non-taproot spends is 10,000 bytes
        // https://github.com/bitcoin/bitcoin/blob/v28.0/src/script/script.h#L39
        if script.len() > 10_000 {
            return Err(tx_err!(txid, ScriptError));
        }
        if script.count_sigops() > 80_000 {
            return Err(tx_err!(txid, ScriptError));
        }
        Ok(())
    }

    /// Validates the coinbase transaction's input and enforces the limits on each
    /// output's script. The check for output values is not performed here.
    fn verify_coinbase(tx: &Transaction) -> Result<(), TransactionError> {
        let txid = || tx.compute_txid();
        let input = match tx.input.as_slice() {
            [i] => i,
            _ => return Err(tx_err!(txid, InvalidCoinbase, "Coinbase must have 1 input")),
        };

        // The prevout input of a coinbase must be all zeroes
        if input.previous_output.txid != Txid::all_zeros() {
            return Err(tx_err!(txid, InvalidCoinbase, "Invalid Coinbase PrevOut"));
        }

        // The scriptsig size must be between 2 and 100 bytes
        // https://github.com/bitcoin/bitcoin/blob/v28.0/src/consensus/tx_check.cpp#L49
        let size = input.script_sig.len();
        if !(2..=100).contains(&size) {
            return Err(tx_err!(txid, InvalidCoinbase, "Invalid ScriptSig size"));
        }

        // Finally check all the output scripts
        for output in tx.output.iter() {
            Self::validate_script_size(&output.script_pubkey, txid)?;
        }

        Ok(())
    }

    /// Calculates the next target for the proof of work algorithm, given the
    /// current target and the time it took to mine the last 2016 blocks.
    pub fn calc_next_work_required(
        last_block: &BlockHeader,
        first_block: &BlockHeader,
        params: ChainParams,
    ) -> Target {
        let actual_timespan = last_block.time - first_block.time;

        CompactTarget::from_next_work_required(first_block.bits, actual_timespan as u64, params)
            .into()
    }

    /// Updates our accumulator with the new block. This is done by calculating the new
    /// root hash of the accumulator, and then verifying the proof of inclusion of the
    /// deleted nodes. If the proof is valid, we return the new accumulator. Otherwise,
    /// we return an error.
    /// This function is pure, it doesn't modify the accumulator, but returns a new one.
    pub fn update_acc(
        acc: &Stump,
        block: &Block,
        height: u32,
        proof: Proof,
        del_hashes: Vec<sha256::Hash>,
    ) -> Result<Stump, BlockchainError> {
        let block_hash = block.block_hash();
        // Convert to BitcoinNodeHashes, from rustreexo
        let del_hashes: Vec<_> = del_hashes.into_iter().map(Into::into).collect();

        let adds = udata::proof_util::get_block_adds(block, height, block_hash);

        // Update the accumulator
        let acc = acc.modify(&adds, &del_hashes, &proof)?.0;
        Ok(acc)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::sha256d::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::Amount;
    use bitcoin::OutPoint;
    use bitcoin::ScriptBuf;
    use bitcoin::Sequence;
    use bitcoin::Transaction;
    use bitcoin::TxIn;
    use bitcoin::TxOut;
    use bitcoin::Txid;
    use bitcoin::Witness;

    use super::*;

    fn coinbase(is_valid: bool) -> Transaction {
        // This coinbase transactions was retrieved from https://learnmeabitcoin.com/explorer/block/0000000000000a0f82f8be9ec24ebfca3d5373fde8dc4d9b9a949d538e9ff679
        // Create inputs
        let input_txid = Txid::from_raw_hash(Hash::from_str(&format!("{:0>64}", "")).unwrap());

        let input_vout = 0;
        let input_outpoint = OutPoint::new(input_txid, input_vout);
        let input_script_sig = if is_valid {
            ScriptBuf::from_hex("03f0a2a4d9f0a2").unwrap()
        } else {
            // This should invalidate the coinbase transaction since is a big, really big, script.
            ScriptBuf::from_hex(&format!("{:0>420}", "")).unwrap()
        };

        let input_sequence = Sequence::MAX;
        let input = TxIn {
            previous_output: input_outpoint,
            script_sig: input_script_sig,
            sequence: input_sequence,
            witness: Witness::new(),
        };

        // Create outputs
        let output_value = Amount::from_sat(5_000_350_000);
        let output_script_pubkey = ScriptBuf::from_hex("41047eda6bd04fb27cab6e7c28c99b94977f073e912f25d1ff7165d9c95cd9bbe6da7e7ad7f2acb09e0ced91705f7616af53bee51a238b7dc527f2be0aa60469d140ac").unwrap();
        let output = TxOut {
            value: output_value,
            script_pubkey: output_script_pubkey,
        };

        // Create transaction
        let version = Version(1);
        let lock_time = LockTime::from_height(150_007).unwrap();

        Transaction {
            version,
            lock_time,
            input: vec![input],
            output: vec![output],
        }
    }

    #[test]
    fn test_validate_script_size() {
        use bitcoin::hashes::Hash;
        let dummy_txid = || Txid::all_zeros();

        // Generate a script larger than 10,000 bytes (e.g., 10,001 bytes)
        let large_script = ScriptBuf::from_hex(&format!("{:0>20002}", "")).unwrap();
        assert_eq!(large_script.len(), 10_001);

        let small_script =
            ScriptBuf::from_hex("76a9149206a30c09cc853bb03bd917a4f9f29b089c1bc788ac").unwrap();

        assert!(Consensus::validate_script_size(&small_script, dummy_txid).is_ok());
        assert!(Consensus::validate_script_size(&large_script, dummy_txid).is_err());
    }

    #[test]
    fn test_validate_coinbase() {
        let valid_one = coinbase(true);
        let invalid_one = coinbase(false);
        // The case that should be valid
        assert!(Consensus::verify_coinbase(&valid_one).is_ok());
        // Invalid coinbase script
        assert_eq!(
            Consensus::verify_coinbase(&invalid_one)
                .unwrap_err()
                .error
                .to_string(),
            "Invalid coinbase: \"Invalid ScriptSig size\""
        );
    }

    #[test]
    #[cfg(feature = "bitcoinconsensus")]
    fn test_consume_utxos() {
        // Transaction extracted from https://learnmeabitcoin.com/explorer/tx/0094492b6f010a5e39c2aacc97396ce9b6082dc733a7b4151ccdbd580f789278
        // Mock data for testing

        let mut utxos = HashMap::new();
        let tx: Transaction = bitcoin::consensus::deserialize(
            &hex::decode("0100000001bd597773d03dcf6e22ba832f2387152c9ab69d250a8d86792bdfeb690764af5b010000006c493046022100841d4f503f44dd6cef8781270e7260db73d0e3c26c4f1eea61d008760000b01e022100bc2675b8598773984bcf0bb1a7cad054c649e8a34cb522a118b072a453de1bf6012102de023224486b81d3761edcd32cedda7cbb30a4263e666c87607883197c914022ffffffff021ee16700000000001976a9144883bb595608dcfe882aea5f7c579ef107a4fb5b88ac52a0aa00000000001976a914782231de72adb5c9df7367ab0c21c7b44bbd743188ac00000000").unwrap()
        ).unwrap();

        assert_eq!(
            tx.input.len(),
            1,
            "We only spend one utxo in this transaction"
        );
        let outpoint = tx.input[0].previous_output;

        let txout = TxOut {
            value: Amount::from_sat(18000000),
            script_pubkey: ScriptBuf::from_hex(
                "76a9149206a30c09cc853bb03bd917a4f9f29b089c1bc788ac",
            )
            .unwrap(),
        };
        utxos.insert(outpoint, txout);

        // Test consuming UTXOs
        let flags = bitcoinconsensus::VERIFY_P2SH;
        tx.verify_with_flags(|outpoint| utxos.remove(outpoint), flags)
            .unwrap();

        assert!(utxos.is_empty(), "Utxo should have been consumed");
        // Test double consuming UTXOs
        assert_eq!(
            tx.verify_with_flags(|outpoint| utxos.remove(outpoint), flags),
            Err(bitcoin::transaction::TxVerifyError::UnknownSpentOutput(
                outpoint
            )),
        );
    }
}
