//! A partial chain is a chain that only contains a subset of the blocks in the
//! full chain. We use multiple partial chains to sync up with the full chain,
//! and then merge them together to get the full chain. This allows us to conduct
//! the sync in parallel.

use floresta_common::prelude::*;
extern crate alloc;
use super::{
    chainparams::ChainParams,
    consensus::Consensus,
    error::{BlockValidationErrors, BlockchainError},
};
#[cfg(feature = "bitcoinconsensus")]
use bitcoin::bitcoinconsensus;
use bitcoin::BlockHeader;
#[cfg(feature = "bitcoinconsensus")]
use core::ffi::c_uint;
use log::info;
use rustreexo::accumulator::stump::Stump;

/// A partial chain is a chain that only contains a subset of the blocks in the
/// full chain. We use multiple partial chains to sync up with the full chain,
/// and then merge them together to get the full chain. This allows us to conduct
/// the sync in parallel. To build one, we need to know the initial
/// height, the final height, and the block headers in between.
pub struct PartialChainState {
    /// The current accumulator state, it starts with a hardcoded value and
    /// gets checked against the result of the previous partial chainstate.
    current_acc: Stump,
    /// The block headers in this interval, we need this to verify the blocks
    /// and to build the accumulator. We assume this is sorted by height, and
    /// should contains all blocks in this interval.
    blocks: Vec<BlockHeader>,
    /// The height this interval starts at. This [initial_height, final_height), so
    /// if we break the interval at height 100, the first interval will be [0, 100)
    /// and the second interval will be [100, 200). And the initial height of the
    /// second interval will be 99.
    initial_height: u32,
    /// The height we are on right now, this is used to keep track of the progress
    /// of the sync.
    current_height: u32,
    /// The height we are syncing up to, trying to push more blocks than this will
    /// result in an error.
    final_height: u32,
    /// The error that occurred during validation, if any. It is here so we can
    /// pull that afterwords.
    error: Option<BlockValidationErrors>,
    /// The consensus parameters, we need this to validate the blocks.
    consensus: Consensus,
    /// Whether we assume the signatures in this interval as valid, this is used to
    /// speed up syncing, by assuming signatures in old blocks are valid.
    assume_valid: bool,
}
impl PartialChainState {
    /// Returns the height we started syncing from
    pub fn initial_height(&self) -> u32 {
        self.initial_height
    }
    /// Is this interval valid?
    pub fn is_valid(&self) -> bool {
        self.is_sync() && self.error.is_none()
    }
    /// Returns the validation error, if any
    pub fn error(&self) -> Option<BlockValidationErrors> {
        self.error.clone()
    }
    /// Returns the height we have synced up to so far
    pub fn current_height(&self) -> u32 {
        self.current_height
    }
    /// Whether or not we have synced up to the final height
    pub fn is_sync(&self) -> bool {
        self.current_height == self.final_height
    }
    pub fn get_block(&self, height: u32) -> Option<&BlockHeader> {
        let index = height - self.initial_height;
        self.blocks.get(index as usize)
    }
    #[cfg(feature = "bitcoinconsensus")]
    /// Returns the validation flags, given the current block height
    fn get_validation_flags(&self, height: u32) -> c_uint {
        let chains_params = &self.consensus.parameters;
        let hash = self.get_block(height).unwrap().block_hash();
        if let Some(flag) = chains_params.exceptions.get(&hash) {
            return *flag;
        }
        // From Bitcoin Core:
        // BIP16 didn't become active until Apr 1 2012 (on mainnet, and
        // retroactively applied to testnet)
        // However, only one historical block violated the P2SH rules (on both
        // mainnet and testnet).
        // Similarly, only one historical block violated the TAPROOT rules on
        // mainnet.
        // For simplicity, always leave P2SH+WITNESS+TAPROOT on except for the two
        // violating blocks.
        let mut flags = bitcoinconsensus::VERIFY_P2SH | bitcoinconsensus::VERIFY_WITNESS;

        if height >= chains_params.bip65_activation_height {
            flags |= bitcoinconsensus::VERIFY_CHECKLOCKTIMEVERIFY;
        }
        if height >= chains_params.bip66_activation_height {
            flags |= bitcoinconsensus::VERIFY_DERSIG;
        }
        if height >= chains_params.csv_activation_height {
            flags |= bitcoinconsensus::VERIFY_CHECKSEQUENCEVERIFY;
        }
        if height >= chains_params.segwit_activation_height {
            flags |= bitcoinconsensus::VERIFY_NULLDUMMY;
        }
        flags
    }

    #[inline]
    /// Update our internal state, given a new height and accumulator
    fn update_state(&mut self, height: u32, acc: Stump) {
        self.current_height = height;
        self.current_acc = acc;
    }
    #[inline]
    /// Returns the parameters for this chain
    fn chain_params(&self) -> ChainParams {
        self.consensus.parameters.clone()
    }
    #[inline]
    /// Returns the ancestor for a given block header
    fn get_ancestor(&self, height: u32) -> Result<BlockHeader, BlockchainError> {
        let prev = self.get_block(height - 1).unwrap();
        Ok(*prev)
    }
    /// Process a block, given the proof, inputs, and deleted hashes. If we find an error,
    /// we save it.
    pub fn process_block(
        &mut self,
        block: &bitcoin::Block,
        proof: rustreexo::accumulator::proof::Proof,
        inputs: HashMap<bitcoin::OutPoint, bitcoin::TxOut>,
        del_hashes: Vec<bitcoin::hashes::sha256::Hash>,
    ) -> bool {
        let height = self.current_height + 1;
        if let Err(BlockchainError::BlockValidation(e)) = self.validate_block(block, height, inputs)
        {
            self.error = Some(e);
            return false;
        }
        let acc = match Consensus::update_acc(&self.current_acc, block, height, proof, del_hashes) {
            Ok(acc) => acc,
            Err(_) => {
                self.error = Some(BlockValidationErrors::InvalidProof);
                return false;
            }
        };

        // ... If we came this far, we consider this block valid ...

        if height % 10_000 == 0 {
            info!(
                "Downloading blocks: height={height} hash={}",
                block.block_hash()
            );
        }
        self.update_state(height, acc);

        true
    }
    /// Is the current accumulator what we expect?
    pub fn is_expected(&self, acc: Stump) -> bool {
        self.current_acc == acc
    }
    /// Check whether a block is valid
    fn validate_block(
        &self,
        block: &bitcoin::Block,
        height: u32,
        inputs: HashMap<bitcoin::OutPoint, bitcoin::TxOut>,
    ) -> Result<(), BlockchainError> {
        if !block.check_merkle_root() {
            return Err(BlockchainError::BlockValidation(
                BlockValidationErrors::BadMerkleRoot,
            ));
        }
        if height >= self.chain_params().bip34_activation_height
            && block.bip34_block_height() != Ok(height as u64)
        {
            return Err(BlockchainError::BlockValidation(
                BlockValidationErrors::BadBip34,
            ));
        }
        if !block.check_witness_commitment() {
            return Err(BlockchainError::BlockValidation(
                BlockValidationErrors::BadWitnessCommitment,
            ));
        }
        let prev_block = self.get_ancestor(height)?;
        if block.header.prev_blockhash != prev_block.block_hash() {
            return Err(BlockchainError::BlockValidation(
                BlockValidationErrors::BlockExtendsAnOrphanChain,
            ));
        }
        // Validate block transactions
        let subsidy = self.consensus.get_subsidy(height);
        let verify_script = self.assume_valid;
        #[cfg(feature = "bitcoinconsensus")]
        let flags = self.get_validation_flags(height);
        #[cfg(not(feature = "bitcoinconsensus"))]
        let flags = 0;
        let valid = Consensus::verify_block_transactions(
            inputs,
            &block.txdata,
            subsidy,
            verify_script,
            flags,
        )?;
        if !valid {
            return Err(BlockchainError::BlockValidation(
                BlockValidationErrors::InvalidTx(String::from("invalid block transactions")),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;
    use std::collections::HashMap;

    use bitcoin::{consensus::deserialize, Block};
    use rustreexo::accumulator::{node_hash::NodeHash, proof::Proof, stump::Stump};

    use crate::{
        pruned_utreexo::{
            chainparams::ChainParams, consensus::Consensus, error::BlockValidationErrors,
        },
        Network,
    };

    use super::PartialChainState;
    #[test]
    fn test_with_invalid_block() {
        fn run(block: &str, reason: BlockValidationErrors) {
            let genesis = parse_block("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f20020000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000");
            let block = parse_block(block);

            let mut chainstate = get_empty_pchain(vec![genesis.header, block.header]);

            assert!(!chainstate.process_block(&block, Proof::default(), HashMap::new(), vec![]));
            assert!(!chainstate.is_valid());
            assert_eq!(chainstate.error, Some(reason));
        }
        run("0000002000226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f39adbcd7823048d34357bdca86cd47172afe2a4af8366b5b34db36df89386d49b23ec964ffff7f20000000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff165108feddb99c6b8435060b2f503253482f627463642fffffffff0100f2052a01000000160014806cef41295922d32ddfca09c26cc4acd36c3ed000000000",super::BlockValidationErrors::BlockExtendsAnOrphanChain);
        run("0000002000226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f40adbcd7823048d34357bdca86cd47172afe2a4af8366b5b34db36df89386d49b23ec964ffff7f20000000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff165108feddb99c6b8435060b2f503253482f627463642fffffffff0100f2052a01000000160014806cef41295922d32ddfca09c26cc4acd36c3ed000000000", BlockValidationErrors::BadMerkleRoot);
    }
    fn parse_block(hex: &str) -> Block {
        let block = hex::decode(hex).unwrap();
        deserialize(&block).unwrap()
    }
    fn get_empty_pchain(blocks: Vec<bitcoin::BlockHeader>) -> PartialChainState {
        PartialChainState {
            assume_valid: true,
            consensus: Consensus {
                parameters: ChainParams::from(Network::Regtest),
            },
            current_height: 0,
            current_acc: Stump::default(),
            final_height: 1,
            blocks,
            error: None,
            initial_height: 0,
        }
    }
    #[test]
    fn test_updating_single_chain() {
        let blocks = include_str!("./testdata/blocks.txt");
        let mut parsed_blocks = vec![];
        for (i, block) in blocks.lines().enumerate() {
            if i > 100 {
                break;
            }
            let block: Block = deserialize(&hex::decode(block).unwrap()).unwrap();
            parsed_blocks.push(block);
        }
        let mut chainstate = PartialChainState {
            assume_valid: true,
            consensus: Consensus {
                parameters: ChainParams::from(Network::Regtest),
            },
            current_height: 0,
            current_acc: Stump::default(),
            final_height: 100,
            blocks: parsed_blocks.iter().map(|block| block.header).collect(),
            error: None,
            initial_height: 0,
        };
        parsed_blocks.remove(0);
        for block in parsed_blocks {
            let proof = Proof::default();
            let inputs = HashMap::new();
            let del_hashes = vec![];
            chainstate.process_block(&block, proof, inputs, del_hashes);
        }
        assert_eq!(chainstate.current_height, 100);
        assert!(chainstate.is_valid());
    }
    #[test]
    fn test_updating_multiple_chains() {
        // We have two chains, one with 100 blocks, one with 50 blocks. We expect the
        // accumulator to be what we expect after 100 blocks and after 150 blocks.
        let blocks = include_str!("./testdata/blocks.txt");
        let mut parsed_blocks = vec![];
        for block in blocks.lines() {
            let block: Block = deserialize(&hex::decode(block).unwrap()).unwrap();
            parsed_blocks.push(block);
        }
        // The file contains 150 blocks, we split them into two chains.
        let (blocks1, blocks2) = parsed_blocks.split_at(101);
        let mut chainstate1 = PartialChainState {
            assume_valid: true,
            consensus: Consensus {
                parameters: ChainParams::from(Network::Regtest),
            },
            current_height: 0,
            current_acc: Stump::default(),
            final_height: 100,
            blocks: blocks1.iter().map(|block| block.header).collect(),
            error: None,
            initial_height: 0,
        };
        // We need to add the last block of the first chain to the second chain, so that
        // the second chain can validate all its blocks.
        let mut blocks2_headers = vec![blocks1.last().unwrap()];
        blocks2_headers.extend(blocks2);

        let blocks2_headers = blocks2_headers.iter().map(|block| block.header).collect();

        let mut blocks1 = blocks1.iter();
        blocks1.next();

        for block in blocks1 {
            let proof = Proof::default();
            let inputs = HashMap::new();
            let del_hashes = vec![];
            chainstate1.process_block(block, proof, inputs, del_hashes);
        }
        // The state after 100 blocks, computed ahead of time.
        let roots = [
            "52a2ca409852acda9e194fbf2d8d9b10159bb4cee56248b3f3affdceaa294865",
            "87b871d9c268eca95114929d619cf23399371248d350dc88e91ca33074341faf",
            "480563375e4013e5ac1238fe0d85f8d997d93f626a0772ad76be6900f85b66c3",
        ]
        .iter()
        .map(|hash| NodeHash::from_str(hash).unwrap())
        .collect();

        let acc2 = Stump { roots, leaves: 100 };

        // acc2 is hard-coded, while chainstate1.current_acc is calculated.
        // after catching up in the first half, the accumulator should be the same.
        // We can have the speedup of doing it in parallel, without needing to trust
        // the hard-coded values.
        assert_eq!(chainstate1.current_acc, acc2);

        let mut chainstate2 = PartialChainState {
            assume_valid: true,
            consensus: Consensus {
                parameters: ChainParams::from(Network::Regtest),
            },
            current_height: 100,
            current_acc: acc2,
            final_height: 150,
            blocks: blocks2_headers,
            error: None,
            initial_height: 100,
        };

        for block in blocks2 {
            let proof = Proof::default();
            let inputs = HashMap::new();
            let del_hashes = vec![];
            chainstate2.process_block(block, proof, inputs, del_hashes);
        }

        let roots = [
            "f5fbbfca687f84f363a790ac26953bbc541e8864987a788083511c5dd5adae87",
            "062221add29798889f62519b8b1de3ffb19b1349baea730a07aec8c6eaacb4e9",
            "9f5cc264618d85b719a1738cdf3169355aac7033ff24f56361db34dfb9e6bbfd",
            "350686755287afe78c33a27b187d83df1cd3c99ea93f4dd66781ecdedcc7d5b2",
        ]
        .iter()
        .map(|x| NodeHash::try_from(hex::decode(x).unwrap().as_slice()).unwrap())
        .collect::<Vec<_>>();

        let expected_acc: Stump = Stump { leaves: 150, roots };

        assert_eq!(chainstate2.current_height, 150);
        assert_eq!(chainstate2.current_acc, expected_acc);

        assert!(chainstate2.is_valid());
    }
}
