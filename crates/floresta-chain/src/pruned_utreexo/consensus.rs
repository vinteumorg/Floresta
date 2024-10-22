//! A collection of functions that implement the consensus rules for the Bitcoin Network.
//! This module contains functions that are used to verify blocks and transactions, and doesn't
//! assume anything about the chainstate, so it can be used in any context.
//! We use this to avoid code reuse among the different implementations of the chainstate.
extern crate alloc;
use core::ffi::c_uint;
use core::ops::Mul;

use bitcoin::absolute::Height;
use bitcoin::absolute::Time;
use bitcoin::block::Header as BlockHeader;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use bitcoin::pow::U256;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::ScriptBuf;
use bitcoin::Target;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoin::WitnessVersion;
use floresta_common::prelude::*;
use rustreexo::accumulator::node_hash::NodeHash;
use rustreexo::accumulator::proof::Proof;
use rustreexo::accumulator::stump::Stump;
use sha2::Digest;
use sha2::Sha512_256;

use super::chainparams::ChainParams;
use super::error::BlockValidationErrors;
use super::error::BlockchainError;
use super::utxo_data::UtxoMap;
use crate::TransactionError;
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
        let mut subsidy = 50 * self.parameters.coin_value;
        // Subsidy is cut in half every 210,000 blocks which will occur approximately every 4 years.
        subsidy >>= halvings;
        subsidy
    }

    /// Returns the hash of a leaf node in the utreexo accumulator.
    #[inline]
    fn get_leaf_hashes(
        transaction: &Transaction,
        vout: u32,
        height: u32,
        block_hash: BlockHash,
    ) -> sha256::Hash {
        let header_code = height << 1;
        let mut ser_utxo = Vec::new();
        let utxo = transaction.output.get(vout as usize).unwrap();
        utxo.consensus_encode(&mut ser_utxo).unwrap();
        let header_code = if transaction.is_coinbase() {
            header_code | 1
        } else {
            header_code
        };

        let leaf_hash = Sha512_256::new()
            .chain_update(UTREEXO_TAG_V1)
            .chain_update(UTREEXO_TAG_V1)
            .chain_update(block_hash)
            .chain_update(transaction.txid())
            .chain_update(vout.to_le_bytes())
            .chain_update(header_code.to_le_bytes())
            .chain_update(ser_utxo)
            .finalize();
        sha256::Hash::from_slice(leaf_hash.as_slice())
            .expect("parent_hash: Engines shouldn't be Err")
    }

    /// Check whether a block is valid
    ///
    /// This function is divided into two parts:
    ///
    /// Header validation with [`Consensus::validate_header`]
    ///
    /// Transaction validation with [`Consensus::validate_block_transactions`]
    pub fn validate_block(
        &self,
        block: &bitcoin::Block,
        ancestor: &BlockHeader,
        height: u32,
        utxo_data: UtxoMap,
        flags: c_uint,
        validate_script: bool,
    ) -> Result<(), BlockchainError> {
        //Check if the block declared merkle root is the same as the one calculated.
        if !block.check_merkle_root() {
            return Err(BlockchainError::BlockValidation(
                BlockValidationErrors::BadMerkleRoot,
            ));
        }

        //Check bip34 activation and presence
        if height >= self.parameters.bip34_activation_height
            && block.bip34_block_height() != Ok(height as u64)
        {
            return Err(BlockchainError::BlockValidation(
                BlockValidationErrors::BadBip34,
            ));
        }

        //Check if the block witness commitment is valid
        if !block.check_witness_commitment() {
            return Err(BlockchainError::BlockValidation(
                BlockValidationErrors::BadWitnessCommitment,
            ));
        }

        //Check if the block version is valid accordingly with the height
        //and bip activation.
        if !self.verify_block_version(height, block.header.version.to_consensus()) {
            return Err(BlockchainError::BlockValidation(
                BlockValidationErrors::BadBlockVersion,
            ));
        }

        //Here is important to check that the declared previous block hash is
        //the same as the actual previous block hash from the chain.
        if block.header.prev_blockhash != ancestor.block_hash() {
            return Err(BlockchainError::BlockValidation(
                BlockValidationErrors::BlockExtendsAnOrphanChain,
            ));
        }

        #[cfg(not(feature = "bitcoinconsensus"))]
        let flags = 0;
        self.verify_block_transactions(height, utxo_data, &block.txdata, flags, validate_script)?;
        Ok(())
    }
    /// Returns true if the given version is compatible at the given height.
    const fn verify_block_version(&self, height: u32, version: i32) -> bool {
        match version {
            0 => false,
            1 => height < self.parameters.bip34_activation_height + 1000,
            2 => {
                height >= self.parameters.bip34_activation_height
                    && height < self.parameters.bip66_activation_height + 1000
            }
            3 => {
                height >= self.parameters.bip66_activation_height
                    && height < self.parameters.bip65_activation_height + 1000
            }
            4 => height >= self.parameters.bip65_activation_height,
            _ => {
                // The case where miners are "voting"
                true
            }
        }
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
    pub fn verify_block_transactions(
        &self,
        height: u32,
        mut utxos: UtxoMap,
        transactions: &[Transaction],
        flags: c_uint,
        validate_script: bool,
    ) -> Result<(), BlockchainError> {
        let subsidy = self.get_subsidy(height);

        if transactions.is_empty() {
            return Err(BlockValidationErrors::EmptyBlock.into());
        }

        let mut fee = 0;
        let mut wu: u64 = self.parameters.block_header_wu;

        for (n, transaction) in transactions.iter().enumerate() {
            // We don't need to verify the coinbase inputs, as it spends newly generated coins
            if transaction.is_coinbase() && n == 0 {
                Self::verify_coinbase(transaction.clone(), n as u16).map_err(|err| {
                    TransactionError {
                        txid: transaction.txid(),
                        error: err,
                    }
                })?;
                continue;
            }

            // Amount of all outputs
            let mut output_value = 0;

            for output in transaction.output.iter() {
                Self::get_out_value(output, &mut output_value)
            }
            // Validate Scripts
            //
            // NOTE: This should be verified before `Self::consume_utxos()` since its nature of removing the
            // utxo from the map. Calling this on a removed or non-existent utxo will result in undefined behavior.
            // (mostly will do nothing :D)
            #[cfg(feature = "bitcoinconsensus")]
            if validate_script {
                Self::validate_script(transaction, flags, &utxos).map_err(|err| {
                    TransactionError {
                        txid: transaction.txid(),
                        error: err,
                    }
                })?;
            }
            // Amount of all inputs
            let mut in_value = 0;

            for input in transaction.input.iter() {
                Self::consume_utxos(input, &mut utxos, &mut in_value).map_err(|err| {
                    TransactionError {
                        txid: transaction.txid(),
                        error: err,
                    }
                })?;

                Self::validate_locktime(input, transaction, &utxos, height, 0).map_err(|err| {
                    TransactionError {
                        txid: transaction.txid(),
                        error: err,
                    }
                })?;
            }

            // Value in should be greater or equal to value out. Otherwise, inflation.
            if output_value > in_value {
                return Err(TransactionError {
                    txid: transaction.txid(),
                    error: BlockValidationErrors::NotEnoughMoney,
                }
                .into());
            }

            // Check if the transaction is not creating more coins than can possibly exist in the chain.
            if output_value > self.parameters.coin_value * 21_000_000 {
                return Err(BlockValidationErrors::TooManyCoins.into());
            }

            // Fee is the difference between inputs and outputs
            fee += in_value - output_value;

            //After all the checks, we sum the transaction weight to the block weight
            wu += transaction.weight().to_wu();
        }

        //checks if the block weight isnt too big.
        if wu > self.parameters.max_block_wu {
            return Err(BlockValidationErrors::BlockTooBig.into());
        }

        // Checks if the miner isn't trying to create inflation
        if fee + subsidy
            < transactions[0]
                .output
                .iter()
                .fold(0, |acc, out| acc + out.value.to_sat())
        {
            return Err(BlockValidationErrors::BadCoinbaseOutValue.into());
        }

        Ok(())
    }

    fn validate_script(
        tx: &Transaction,
        flags: c_uint,
        utxo_map: &UtxoMap,
    ) -> Result<(), BlockValidationErrors> {
        if Self::validate_script_size(tx, utxo_map).is_ok() {
            return match tx.verify_with_flags(
                |outpoint| utxo_map.get(outpoint).map(|obj| obj.txout.clone()),
                flags,
            ) {
                Ok(_) => Ok(()),
                Err(e) => Err(BlockValidationErrors::InvalidScript(e)),
            };
        };
        Ok(())
    }

    /// Consumes the UTXOs from the hashmap, and returns the value of the consumed UTXOs.
    /// If we do not find the UTXO, we return an error invalidating the input that tried to
    /// consume that UTXO.
    fn consume_utxos(
        input: &TxIn,
        utxos: &mut UtxoMap,
        value_var: &mut u64,
    ) -> Result<(), BlockValidationErrors> {
        match utxos.get(&input.previous_output) {
            Some(utxo_data) => {
                *value_var += utxo_data.txout.value.to_sat();
                utxos.remove(&input.previous_output);
            }
            None => {
                return Err(BlockValidationErrors::UtxoAlreadySpent(
                    //This is the case when the spender:
                    // - Spends an UTXO that doesn't exist
                    // - Spends an UTXO that was already spent
                    input.previous_output.txid,
                ));
            }
        };
        Ok(())
    }
    /// Validate Locktime. if mtp is 0, skip the validation.
    fn validate_locktime(
        input: &TxIn,
        transaction: &Transaction,
        out_map: &UtxoMap,
        height: u32,
        mtp: u32,
    ) -> Result<(), BlockValidationErrors> {
        if mtp == 0 {
            return Ok(());
        }
        if input.sequence.is_relative_lock_time() {
            //validate lock time
            let prevout = out_map.get(&input.previous_output).unwrap();
            if input.sequence.is_height_locked() {
                let commited_height = prevout.get_height();
                //to retrieve the span contained in the sequence we have to just get the u32 value that the sequence contains.
                let height_span = input.sequence.0;

                // if the commited height + the span is greater than the current height, the transaction is invalid.
                if commited_height + height_span > height {
                    return Err(BlockValidationErrors::BadRelativeLockTime);
                }
            }
            if input.sequence.is_time_locked() {
                let commited_time = prevout.get_time();
                // here we have to shift the sequence 16 bits to the left and 16 to the right get the time lock without the flag messing with us.
                let time_lock = ((input.sequence.0 << 16) >> 16) * 512_u32;

                if commited_time + time_lock > mtp {
                    return Err(BlockValidationErrors::BadRelativeLockTime);
                }
            }
        }
        if input.sequence.enables_absolute_lock_time()
            && !transaction.is_absolute_timelock_satisfied(
                Height::from_consensus(height).unwrap(),
                Time::from_consensus(mtp).unwrap(),
            )
        {
            return Err(BlockValidationErrors::BadAbsoluteLockTime);
        }
        Ok(())
    }

    /// Validates the script size and the number of sigops in a script.
    fn validate_script_size(
        tx: &Transaction,
        utxo_map: &UtxoMap,
    ) -> Result<(), BlockValidationErrors> {
        for input in tx.input.iter() {
            let script_sig = &input.script_sig;
            let scrip_sig_size = script_sig.len();

            let script_pub = match utxo_map.get(&input.previous_output) {
                Some(obj) => obj.txout.script_pubkey.clone(),
                _ => {
                    return Err(BlockValidationErrors::UtxoAlreadySpent(
                        input.previous_output.txid,
                    ))
                }
            };

            let concat_script =
                ScriptBuf::from_bytes([script_sig.to_bytes(), script_pub.to_bytes()].concat());

            let is_taproot =
                script_pub.witness_version() == Some(WitnessVersion::V1) && script_pub.len() == 32;

            if !(2..=1650).contains(&scrip_sig_size) && !is_taproot {
                return Err(BlockValidationErrors::ScriptError);
            };
            if concat_script.count_sigops() > 80_000 || concat_script.len() < 10_000 {
                return Err(BlockValidationErrors::ScriptError);
            }
        }

        Ok(())
    }
    fn get_out_value(out: &TxOut, value_var: &mut u64) {
        *value_var += out.value.to_sat()
    }

    fn verify_coinbase(transaction: Transaction, index: u16) -> Result<(), BlockValidationErrors> {
        if index != 0 {
            // A block must contain only one coinbase, and it should be the fist thing inside it
            return Err(BlockValidationErrors::FirstTxIsnNotCoinbase);
        }
        //the prevout input of a coinbase must be all zeroes
        if transaction.input[0].previous_output.txid != Txid::all_zeros() {
            return Err(BlockValidationErrors::InvalidCoinbase(
                "Invalid coinbase txid".to_string(),
            ));
        }
        let scriptsig = transaction.input[0].script_sig.clone();
        let scriptsigsize = scriptsig.clone().into_bytes().len();
        if !(2..=100).contains(&scriptsigsize) {
            //the scriptsig size must be between 2 and 100 bytes
            return Err(BlockValidationErrors::InvalidCoinbase(
                "Invalid ScriptSig size".to_string(),
            ));
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
        let cur_target = last_block.target().0;

        let expected_timespan = U256::from(params.pow_target_timespan);
        let mut actual_timespan = last_block.time - first_block.time;

        // Difficulty adjustments are limited, to prevent large swings in difficulty
        // caused by malicious miners.
        if actual_timespan < params.pow_target_timespan as u32 / 4 {
            actual_timespan = params.pow_target_timespan as u32 / 4;
        }
        if actual_timespan > params.pow_target_timespan as u32 * 4 {
            actual_timespan = params.pow_target_timespan as u32 * 4;
        }

        let new_target = cur_target.mul(actual_timespan.into());
        let new_target = new_target / expected_timespan;
        Target(new_target)
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
        let mut leaf_hashes = Vec::new();
        let del_hashes = del_hashes
            .iter()
            .map(|hash| NodeHash::from(hash.as_byte_array()))
            .collect::<Vec<_>>();
        // Get inputs from the block, we'll need this HashSet to check if an output is spent
        // in the same block. If it is, we don't need to add it to the accumulator.
        let mut block_inputs = HashSet::new();
        for transaction in block.txdata.iter() {
            for input in transaction.input.iter() {
                block_inputs.insert((input.previous_output.txid, input.previous_output.vout));
            }
        }

        // Get all leaf hashes that will be added to the accumulator
        for transaction in block.txdata.iter() {
            for (i, output) in transaction.output.iter().enumerate() {
                if !Self::is_unspendable(&output.script_pubkey)
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
        // Convert the leaf hashes to NodeHashes used in Rustreexo
        let hashes: Vec<NodeHash> = leaf_hashes
            .iter()
            .map(|&hash| NodeHash::from(hash.as_byte_array()))
            .collect();
        // Update the accumulator
        let acc = acc.modify(&hashes, &del_hashes, &proof)?.0;
        Ok(acc)
    }

    fn is_unspendable(script: &ScriptBuf) -> bool {
        if script.len() > 10_000 {
            return true;
        }

        if !script.is_empty() && script.as_bytes()[0] == 0x6a {
            return true;
        }

        false
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
    use crate::pruned_utreexo::utxo_data::UtxoData;
    use crate::pruned_utreexo::utxo_data::UtxoMap;

    fn coinbase(is_valid: bool) -> Transaction {
        //This coinbase transactions was retrieved from https://learnmeabitcoin.com/explorer/block/0000000000000a0f82f8be9ec24ebfca3d5373fde8dc4d9b9a949d538e9ff679
        // Create inputs
        let input_txid = Txid::from_raw_hash(Hash::from_str(&format!("{:0>64}", "")).unwrap());

        let input_vout = 0;
        let input_outpoint = OutPoint::new(input_txid, input_vout);
        let input_script_sig = if is_valid {
            ScriptBuf::from_hex("03f0a2a4d9f0a2").unwrap()
        } else {
            //This should invalidate the coinbase transaction since is a big, really big, script.
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
        let version = Version(2);
        let lock_time = LockTime::from_height(150_007).unwrap();

        Transaction {
            version,
            lock_time,
            input: vec![input],
            output: vec![output],
        }
    }

    #[test]
    fn test_validate_script() {
        let transaction = Transaction {
            version: Version(1),
            lock_time: LockTime::from_height(0).unwrap(),
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str(
                        "10ddd830599b17cc690535f7df28a84466eaca3c22f0d55b79023b6570f4fbc5",
                    )
                    .unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::from_hex("00473044022100d0ed946330182916da16a6149cd313a4b1a7b41591ee52fb3e79d64e36139d66021f6ccf173040ef24cb45c4db3e9c771c938a1ba2cf8d2404416f70886e360af401475121022afc20bf379bc96a2f4e9e63ffceb8652b2b6a097f63fbee6ecec2a49a48010e2103a767c7221e9f15f870f1ad9311f5ab937d79fcaeee15bb2c722bca515581b4c052ae")
                    .unwrap(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_hex(
                    "76a9146f34d3811aded1df870359f311c2a11a015e945388ac",
                )
                .unwrap(),
            }],
        };

        let txout = TxOut {
            value: Amount::from_sat(5_000_350_000),
            script_pubkey: ScriptBuf::from_hex("a914748284390f9e263a4b766a75d0633c50426eb87587")
                .unwrap(),
        };

        let utxo_data = UtxoData::new(txout, 0, 0);

        let mut utxo_map = HashMap::new();

        utxo_map.insert(transaction.input[0].previous_output, utxo_data.clone());

        assert!(dbg!(Consensus::validate_script(&transaction, 0, &utxo_map)).is_ok());
    }

    #[test]
    fn test_validate_get_out_value() {
        let output = TxOut {
            value: Amount::from_sat(5_000_350_000),
            script_pubkey: ScriptBuf::from_hex("41047eda6bd04fb27cab6e7c28c99b94977f073e912f25d1ff7165d9c95cd9bbe6da7e7ad7f2acb09e0ced91705f7616af53bee51a238b7dc527f2be0aa60469d140ac").unwrap(),
        };
        let mut value_var = 0;
        Consensus::get_out_value(&output, &mut value_var);
        assert_eq!(value_var, 5_000_350_000);
    }

    #[test]
    fn test_validate_coinbase() {
        let valid_one = coinbase(true);
        let invalid_one = coinbase(false);
        //The case that should be valid
        assert!(Consensus::verify_coinbase(valid_one.clone(), 0).is_ok());
        //Coinbase at wrong index
        assert_eq!(
            Consensus::verify_coinbase(valid_one, 1)
                .unwrap_err()
                .to_string(),
            "The first transaction in a block isn't a coinbase"
        );
        //Invalid coinbase script
        assert_eq!(
            Consensus::verify_coinbase(invalid_one, 0)
                .unwrap_err()
                .to_string(),
            "Invalid coinbase: \"Invalid ScriptSig size\""
        );
    }
    #[test]
    fn test_consume_utxos() {
        // Transaction extracted from https://learnmeabitcoin.com/explorer/tx/0094492b6f010a5e39c2aacc97396ce9b6082dc733a7b4151ccdbd580f789278
        // Mock data for testing

        let mut utxos = UtxoMap::new();
        let outpoint1 = OutPoint::new(
            Txid::from_raw_hash(
                Hash::from_str("5baf640769ebdf2b79868d0a259db69a2c1587232f83ba226ecf3dd0737759bd")
                    .unwrap(),
            ),
            1,
        );
        let input = TxIn {
            previous_output: outpoint1,
            script_sig: ScriptBuf::from_hex("493046022100841d4f503f44dd6cef8781270e7260db73d0e3c26c4f1eea61d008760000b01e022100bc2675b8598773984bcf0bb1a7cad054c649e8a34cb522a118b072a453de1bf6012102de023224486b81d3761edcd32cedda7cbb30a4263e666c87607883197c914022").unwrap(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };
        let prevout = TxOut {
            value: Amount::from_sat(18000000),
            script_pubkey: ScriptBuf::from_hex(
                "76a9149206a30c09cc853bb03bd917a4f9f29b089c1bc788ac",
            )
            .unwrap(),
        };

        utxos.insert(outpoint1, UtxoData::new(prevout.clone(), 0, 0));

        // Test consuming UTXOs
        let mut value_var: u64 = 0;
        assert!(Consensus::consume_utxos(&input, &mut utxos, &mut value_var).is_ok());
        assert_eq!(value_var, prevout.value.to_sat());

        // Test double consuming UTXOs
        assert_eq!(
            Consensus::consume_utxos(&input, &mut utxos, &mut value_var)
                .unwrap_err()
                .to_string(),
            "Utxo 0x5baf640769ebdf2b79868d0a259db69a2c1587232f83ba226ecf3dd0737759bd already spent"
        );
    }
    #[test]
    fn test_validate_locktime_absolute() {
        // Locktime absolute

        // the actual height of the chain.
        let actual_height: u32 = 100_001;
        // the locktime of the transaction with a locktime of 100_000(less than the actual height)
        let lock = LockTime::from_height(actual_height - 1).unwrap();
        // the transaction with the locktime
        let mut tx = Transaction {
            version: Version(1),
            lock_time: lock,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        // Since were are not validating any relative locktime, the map doesnt matter
        let out_map = UtxoMap::new();
        // since where not validating the locktime, the locktime does not matter(random timestamp)
        let mtp = 1725307760; // Mtp::new_from_value(1725307760);
        assert!(
            Consensus::validate_locktime(&tx.input[0], &tx, &out_map, actual_height, mtp).is_ok()
        );

        // the locktime of the transaction with a locktime of 100_011(more than the actual height, the validate should fail)
        tx.lock_time = LockTime::from_height(actual_height + 10).unwrap();
        assert!(
            Consensus::validate_locktime(&tx.input[0], &tx, &out_map, actual_height, mtp).is_err()
        );

        // The mtp of the chain. can be any u32 value(unix timestamp).
        let mtp = 1725307760; //Mtp::new_from_value(1725307760);
                              // The locktime locked by time of the transaction with a locktime of mtp - 1 (less than the actual height)
        let lock = LockTime::from_time(mtp - 1).unwrap();
        // The transaction with the locktime
        let mut tx = Transaction {
            // all transactions that use the sequence field are version 2.
            version: Version(1),
            lock_time: lock,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        // Since were are not validating any relative locktime, the map doesnt matter
        let out_map = UtxoMap::new();
        // since where not validating the height, the height does not matter
        let height = 0;
        assert!(Consensus::validate_locktime(&tx.input[0], &tx, &out_map, height, mtp).is_ok());
        // If the locktime is greater than the chain time, the transaction is invalid and validate_locktime should return an error
        let new_time = LockTime::from_time(mtp + 1).unwrap();
        tx.lock_time = new_time;

        assert!(Consensus::validate_locktime(&tx.input[0], &tx, &out_map, height, mtp).is_err());
    }
    #[test]
    fn test_validate_locktime_relative_height() {
        // The span that the input has to wait until be included in the chain
        let height_span: u16 = 100;
        // the actual height of the transaction with a locktime of 30_000
        let actual_height: u32 = 30_000;
        //The height that the prevout was mined
        let prevout_height = actual_height - height_span as u32;

        // since were not validating time, the time of the chain does not matter(random unistimestamp).
        let mtp = 1725307760; //Mtp::new_from_value(1725307760);

        // the outpoint that the transaction is spending
        let outpoint1 = OutPoint::new(
            Txid::from_raw_hash(
                Hash::from_str("5baf640769ebdf2b79868d0a259db69a2c1587232f83ba226ecf3dd0737759bd")
                    .unwrap(),
            ),
            1,
        );
        // the utxo that the transaction is spending that was commited 100 blocks ago
        let utxo = UtxoData::new(
            TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::new(),
            },
            //"The height that the utxo was created at"
            prevout_height,
            0,
        );
        //now we need context to validate the relative locktime.
        let mut out_map = UtxoMap::new();
        out_map.insert(outpoint1, utxo);
        // the transaction with the locktime
        let mut tx = Transaction {
            // all transactions that use the sequence field are version 2.
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint1,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_height(height_span),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        assert!(
            Consensus::validate_locktime(&tx.input[0], &tx, &out_map, actual_height, mtp).is_ok()
        );

        //The locktime is 100 blocks after the utxo was created, so the transaction is invalid and validate_locktime should return an error
        tx.input[0].sequence = Sequence::from_height(height_span + 1);

        assert!(
            Consensus::validate_locktime(&tx.input[0], &tx, &out_map, actual_height, mtp).is_err()
        );
    }
    #[test]
    fn test_validate_locktime_relative_time() {
        // the time of the chain. A random unix timestamp
        let mtp = 1725307760; // Mtp::new_from_value(1725307760);

        // The span is how many intervals of 512 seconds the input has to wait until be included in the chain
        let span: u16 = 2;
        // the outpoint that the input is spending
        let prevout_mtp = mtp - (span as u32 * 512);

        // the outpoint that the transaction is spending
        let outpoint1 = OutPoint::new(
            Txid::from_raw_hash(
                Hash::from_str("5baf640769ebdf2b79868d0a259db69a2c1587232f83ba226ecf3dd0737759bd")
                    .unwrap(),
            ),
            1,
        );
        // the utxo that the transaction is spending that was commited mtp - 1025 seconds ago
        let utxo = UtxoData::new(
            TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::new(),
            },
            0,
            //The time that the utxo was created at
            prevout_mtp,
        );
        //now we need context to validate the relative locktime.
        let mut out_map = UtxoMap::new();
        out_map.insert(outpoint1, utxo);
        // the transaction with the locktime
        let mut tx = Transaction {
            version: Version(2),
            //Relative locktime is set by sequence, the locktime of the transactions isnt used.
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint1,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_512_second_intervals(span),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        assert!(Consensus::validate_locktime(&tx.input[0], &tx, &out_map, 0_u32, mtp).is_ok());

        //The locktime is 1 interval of 512 seconds after the utxo was created, so the transaction is invalid and validate_locktime should return an error
        tx.input[0].sequence = Sequence::from_512_second_intervals(span + 1);

        assert!(Consensus::validate_locktime(&tx.input[0], &tx, &out_map, 0_u32, mtp).is_err());
    }
}
