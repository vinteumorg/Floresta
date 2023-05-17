use super::{
    chainparams::ChainParams,
    chainstore::{ChainStore, DiskBlockHeader, KvChainStore},
    error::{BlockValidationErrors, BlockchainError},
    BlockchainInterface, BlockchainProviderInterface, Notification,
};
use crate::{read_lock, write_lock};
use async_std::channel::Sender;
use bitcoin::{
    bitcoinconsensus,
    blockdata::constants::{genesis_block, COIN_VALUE},
    consensus::{deserialize_partial, Decodable, Encodable},
    hashes::{hex::FromHex, sha256, Hash},
    util::uint::Uint256,
    Block, BlockHash, BlockHeader, Network, OutPoint, Transaction, TxOut,
};
use log::{info, trace};
use rustreexo::accumulator::{proof::Proof, stump::Stump};
use sha2::{Digest, Sha512_256};
use std::sync::RwLock;
use std::{
    collections::{HashMap, HashSet},
    ffi::c_uint,
    io::Write,
};
pub struct ChainStateInner<PersistedState: ChainStore> {
    /// The acc we use for validation.
    acc: Stump,
    /// All data is persisted here.
    chainstore: PersistedState,
    /// Best known block, cached in a specific field to faster access.
    best_block: BestChain,
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
    /// Global parameter of the chain we are in
    chain_params: ChainParams,
    /// Assume valid is a Core-specific config that tells the node to not validate signatures
    /// in blocks before this one. Note that we only skip signature validation, everything else
    /// is still validated.
    assume_valid: (BlockHash, u32),
}

pub struct ChainState<PersistedState: ChainStore> {
    inner: RwLock<ChainStateInner<PersistedState>>,
}

impl<PersistedState: ChainStore> ChainState<PersistedState> {
    // TODO: Move to LeafData
    pub fn get_leaf_hashes(
        transaction: &Transaction,
        vout: u32,
        height: u32,
        block_hash: BlockHash,
    ) -> sha256::Hash {
        let header_code = height << 1;

        let mut ser_utxo = vec![];
        let utxo = transaction.output.get(vout as usize).unwrap();
        utxo.consensus_encode(&mut ser_utxo).unwrap();
        let header_code = if transaction.is_coin_base() {
            header_code | 1
        } else {
            header_code
        };

        let leaf_hash = Sha512_256::new()
            .chain_update(block_hash)
            .chain_update(transaction.txid())
            .chain_update(vout.to_le_bytes())
            .chain_update(header_code.to_le_bytes())
            .chain_update(ser_utxo)
            .finalize();
        sha256::Hash::from_slice(leaf_hash.as_slice())
            .expect("parent_hash: Engines shouldn't be Err")
    }
    /// Returns the validation flags, given the current block height
    fn get_validation_flags(&self, height: u32) -> c_uint {
        let chains_params = read_lock!(self).chain_params.clone();
        let hash = read_lock!(self)
            .chainstore
            .get_block_hash(height)
            .unwrap()
            .unwrap();
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
    /// Returns the amount of block subsidy to be paid in a block, given it's height.
    /// Bitcoin Core source: https://github.com/bitcoin/bitcoin/blob/2b211b41e36f914b8d0487e698b619039cc3c8e2/src/validation.cpp#L1501-L1512
    fn get_subsidy(&self, height: u32) -> u64 {
        let halvings = height / read_lock!(self).chain_params.subsidy_halving_interval as u32;
        // Force block reward to zero when right shift is undefined.
        if halvings >= 64 {
            return 0;
        }
        let mut subsidy = 50 * COIN_VALUE;
        // Subsidy is cut in half every 210,000 blocks which will occur approximately every 4 years.
        subsidy >>= halvings;
        subsidy
    }
    fn update_header(&self, header: &DiskBlockHeader) -> Result<(), BlockchainError> {
        Ok(read_lock!(self).chainstore.save_header(header)?)
    }
    fn validate_header(&self, block_header: &BlockHeader) -> Result<BlockHash, BlockchainError> {
        let prev_block = self.get_disk_block_header(&block_header.prev_blockhash)?;
        let prev_block_height = prev_block.height();
        if prev_block_height.is_none() {
            return Err(BlockValidationErrors::BlockExtendsAnOrphanChain.into());
        }
        let height = prev_block_height.unwrap() + 1;

        // Check pow
        let expected_target = self.get_next_required_work(&prev_block, height, block_header);

        let actual_target = block_header.target();
        if actual_target > expected_target {
            return Err(BlockValidationErrors::NotEnoughPow.into());
        }

        let block_hash = block_header.validate_pow(&actual_target).map_err(|_| {
            BlockchainError::BlockValidationError(BlockValidationErrors::NotEnoughPow)
        })?;
        Ok(block_hash)
    }
    fn verify_block_transactions(
        mut utxos: HashMap<OutPoint, TxOut>,
        transactions: &[Transaction],
        subsidy: u64,
        verify_script: bool,
        flags: c_uint,
    ) -> Result<bool, crate::error::Error> {
        // Blocks must contain at least one transaction
        if transactions.is_empty() {
            return Err(BlockValidationErrors::EmptyBlock.into());
        }
        let mut fee = 0;
        // Skip the coinbase tx
        for (n, transaction) in transactions.iter().enumerate() {
            // We don't need to verify the coinbase inputs, as it spends newly generated coins
            if transaction.is_coin_base() {
                if n == 0 {
                    continue;
                }
                // A block must contain only one coinbase, and it should be the fist thing inside it
                return Err(BlockValidationErrors::FirstTxIsnNotCoinbase.into());
            }
            // Amount of all outputs
            let output_value = transaction.output.iter().fold(0, |acc, tx| acc + tx.value);
            // Amount of all inputs
            let in_value = transaction.input.iter().fold(0, |acc, input| {
                acc + utxos
                    .get(&input.previous_output)
                    .expect("We have all prevouts here")
                    .value
            });
            // Value in should be greater or equal to value out. Otherwise, inflation.
            if output_value > in_value {
                return Err(BlockValidationErrors::NotEnoughMoney.into());
            }
            // Fee is the difference between inputs and outputs
            fee += in_value - output_value;
            // Verify the tx script
            if verify_script {
                transaction.verify_with_flags(|outpoint| utxos.remove(outpoint), flags)?;
            }
        }
        // In each block, the first transaction, and only the first, should be coinbase
        if !transactions[0].is_coin_base() {
            return Err(BlockValidationErrors::FirstTxIsnNotCoinbase.into());
        }
        // Checks if the miner isn't trying to create inflation
        if fee + subsidy
            < transactions[0]
                .output
                .iter()
                .fold(0, |acc, out| acc + out.value)
        {
            return Err(BlockValidationErrors::BadCoinbaseOutValue.into());
        }
        Ok(true)
    }
    #[inline]
    /// Whether a node is the genesis block for this net
    fn is_genesis(&self, header: &BlockHeader) -> bool {
        header.block_hash() == self.chain_params().genesis.block_hash()
    }
    #[inline]
    /// Returns the ancestor of a given block
    fn get_ancestor(&self, header: &BlockHeader) -> Result<DiskBlockHeader, BlockchainError> {
        self.get_disk_block_header(&header.prev_blockhash)
    }
    /// Returns the cumulative work in this branch
    fn get_branch_work(&self, header: &BlockHeader) -> Result<Uint256, BlockchainError> {
        let mut header = *header;
        let mut work = Uint256::from_u64(0).unwrap();
        while !self.is_genesis(&header) {
            work = work + header.work();
            header = *self.get_ancestor(&header)?;
        }

        Ok(work)
    }
    /// Checks if a branch is valid (i.e. all ancestors are known)
    fn check_branch(&self, branch_tip: &BlockHeader) -> Result<(), BlockchainError> {
        let mut header = *branch_tip;

        while !self.is_genesis(&header) {
            let _header = self.get_ancestor(&header)?;
            if let DiskBlockHeader::Orphan(block) = _header {
                return Err(BlockchainError::InvalidTip(format!(
                    "Block {} doesn't have a known ancestor (i.e an orphan block)",
                    block.block_hash()
                )));
            }
            header = *_header;
        }

        Ok(())
    }
    /// Returns the depth of a branch (i.e. how many blocks are in the branch)
    fn get_chain_depth(&self, branch_tip: &BlockHeader) -> Result<u32, BlockchainError> {
        let mut header = *branch_tip;

        let mut counter = 0;
        while !self.is_genesis(&header) {
            header = *self.get_ancestor(&header)?;
            counter += 1;
        }

        Ok(counter)
    }
    /// Mark the current index as active, because we are in the middle of a reorg
    fn mark_chain_as_active(
        &self,
        new_tip: &BlockHeader,
        fork_point: BlockHash,
    ) -> Result<(), BlockchainError> {
        let mut height = self.get_chain_depth(new_tip)?;
        let mut header = DiskBlockHeader::HeadersOnly(*new_tip, height);

        let inner = read_lock!(self);

        while !self.is_genesis(&header) || header.block_hash() == fork_point {
            inner
                .chainstore
                .update_block_index(height, header.block_hash())?;
            let new_header = DiskBlockHeader::HeadersOnly(*header, height);
            inner.chainstore.save_header(&new_header)?;
            header = self.get_ancestor(&header)?;
            height -= 1;
        }
        Ok(())
    }
    /// Mark the current index as inactive, either because we found an invalid ancestor,
    /// or we are in the middle of reorg
    fn mark_chain_as_inactive(
        &self,
        old_tip: &BlockHeader,
        fork_point: BlockHash,
    ) -> Result<(), BlockchainError> {
        let mut header = *old_tip;
        let mut height = self.get_chain_depth(old_tip)?;

        let inner = read_lock!(self);
        while !self.is_genesis(&header) || header.block_hash() == fork_point {
            let new_header = DiskBlockHeader::InFork(header, height);
            inner.chainstore.save_header(&new_header)?;
            header = *self.get_ancestor(&header)?;
            height -= 1;
        }

        Ok(())
    }
    /// Finds where in the current index, a given branch forks out.
    fn find_fork_point(&self, header: &BlockHeader) -> Result<BlockHeader, BlockchainError> {
        let mut header = *self.get_ancestor(header)?;
        let inner = read_lock!(self);
        while !self.is_genesis(&header) {
            match inner.chainstore.get_header(&header.block_hash())? {
                Some(DiskBlockHeader::HeadersOnly(block, _)) => {
                    return Ok(block);
                }
                Some(DiskBlockHeader::FullyValid(block, _)) => {
                    return Ok(block);
                }
                Some(DiskBlockHeader::InFork(block, _)) => {
                    header = *self.get_ancestor(&block)?;
                    continue;
                }
                Some(DiskBlockHeader::Orphan(header)) => {
                    return Err(BlockchainError::InvalidTip(format!(
                        "Block {} doesn't have a known ancestor (i.e an orphan block)",
                        header.block_hash()
                    )));
                }
                Some(DiskBlockHeader::InvalidChain(header)) => {
                    return Err(BlockchainError::InvalidTip(format!(
                        "Block {} is invalid",
                        header.block_hash()
                    )));
                }
                None => {
                    return Err(BlockchainError::InvalidTip(format!(
                        "Block {} isn't in our storage",
                        header.block_hash()
                    )));
                }
            }
        }
        Err(BlockchainError::InvalidTip(
            "Couldn't find a fork point".to_string(),
        ))
    }
    // This method should only be called after we validate the new branch
    fn reorg(&self, new_tip: BlockHeader) -> Result<(), BlockchainError> {
        let current_best_block = self.get_best_block().unwrap().1;
        let current_best_block = self.get_block_header(&current_best_block)?;
        let fork_point = self.find_fork_point(&new_tip)?;

        self.mark_chain_as_inactive(&current_best_block, fork_point.block_hash())?;
        self.mark_chain_as_active(&new_tip, fork_point.block_hash())?;

        let validation_index = self.get_last_valid_block(&new_tip)?;
        let depth = self.get_chain_depth(&new_tip)?;
        self.change_active_chain(&new_tip, validation_index, depth);

        Ok(())
    }
    /// Changes the active chain to the new branch during a reorg
    fn change_active_chain(&self, new_tip: &BlockHeader, last_valid: BlockHash, depth: u32) {
        let mut inner = self.inner.write().unwrap();
        inner.best_block.best_block = new_tip.block_hash();
        inner.best_block.validation_index = last_valid;
        inner.best_block.depth = depth;
        inner.acc = Stump::new();
    }
    /// Grabs the last block we validated in this branch. We don't validate a fork, unless it
    /// becomes the best chain. This function technically finds out what is the last common block
    /// between two branches.
    fn get_last_valid_block(&self, header: &BlockHeader) -> Result<BlockHash, BlockchainError> {
        let mut header = *header;

        while !self.is_genesis(&header) {
            let _header = self.get_ancestor(&header)?;
            match _header {
                DiskBlockHeader::FullyValid(_, _) => return Ok(header.block_hash()),
                DiskBlockHeader::Orphan(_) => {
                    return Err(BlockchainError::InvalidTip(format!(
                        "Block {} doesn't have a known ancestor (i.e an orphan block)",
                        header.block_hash()
                    )))
                }
                DiskBlockHeader::HeadersOnly(_, _) | DiskBlockHeader::InFork(_, _) => {}
                DiskBlockHeader::InvalidChain(_) => {
                    return Err(BlockchainError::InvalidTip(format!(
                        "Block {} is in an invalid chain",
                        header.block_hash()
                    )))
                }
            }

            header = *_header;
        }
        Ok(header.block_hash())
    }
    /// If we get a header that doesn't build on top of our best chain, it may cause a reorganization.
    /// We check this here.
    fn maybe_reorg(&self, branch_tip: BlockHeader) -> Result<(), BlockchainError> {
        let current_tip = self.get_block_header(&self.get_best_block().unwrap().1)?;
        self.check_branch(&branch_tip)?;

        let current_work = self.get_branch_work(&current_tip)?;
        let new_work = self.get_branch_work(&branch_tip)?;
        // If the new branch has more work, it becomes the new best chain
        if new_work > current_work {
            self.reorg(branch_tip)?;
            return Ok(());
        }
        // If the new branch has less work, we just store it as an alternative branch
        // that might become the best chain in the future.
        self.push_alt_tip(&branch_tip)?;
        let ancestor = self.get_ancestor(&branch_tip)?.height().unwrap();
        read_lock!(self)
            .chainstore
            .save_header(&super::chainstore::DiskBlockHeader::InFork(
                branch_tip, ancestor,
            ))?;
        Ok(())
    }
    /// Stores a new tip for a branch that is not the best one
    fn push_alt_tip(&self, branch_tip: &BlockHeader) -> Result<(), BlockchainError> {
        let ancestor = self.get_ancestor(branch_tip);
        let ancestor = match ancestor {
            Ok(ancestor) => Some(ancestor),
            Err(BlockchainError::BlockNotPresent) => None,
            Err(e) => return Err(e),
        };
        let mut inner = write_lock!(self);
        if let Some(ancestor) = ancestor {
            let ancestor_hash = ancestor.block_hash();
            if let Some(idx) = inner
                .best_block
                .alternative_tips
                .iter()
                .position(|hash| ancestor_hash == *hash)
            {
                inner.best_block.alternative_tips.remove(idx);
            }
        }
        inner
            .best_block
            .alternative_tips
            .push(branch_tip.block_hash());
        Ok(())
    }
    /// Calculates the next target for the proof of work algorithm, given the
    /// current target and the time it took to mine the last 2016 blocks.
    fn calc_next_work_required(
        last_block: &BlockHeader,
        first_block: &BlockHeader,
        params: ChainParams,
    ) -> u32 {
        let cur_target = last_block.target();

        let expected_timespan = Uint256::from_u64(params.pow_target_timespan).unwrap();
        let mut actual_timespan = last_block.time - first_block.time;
        // Difficulty adjustments are limited, to prevent large swings in difficulty
        // caused by malicious miners.
        if actual_timespan < params.pow_target_timespan as u32 / 4 {
            actual_timespan = params.pow_target_timespan as u32 / 4;
        }
        if actual_timespan > params.pow_target_timespan as u32 * 4 {
            actual_timespan = params.pow_target_timespan as u32 * 4;
        }
        let new_target = cur_target.mul_u32(actual_timespan);
        let new_target = new_target / expected_timespan;

        BlockHeader::compact_target_from_u256(&new_target)
    }
    /// Returns the next required work for the next block, usually it's just the last block's target
    /// but if we are in a retarget period, it's calculated from the last 2016 blocks.
    fn get_next_required_work(
        &self,
        last_block: &BlockHeader,
        next_height: u32,
        next_header: &BlockHeader,
    ) -> Uint256 {
        let params: ChainParams = self.chain_params();
        // Special testnet rule, if a block takes more than 20 minutes to mine, we can
        // mine a block with diff 1
        if params.pow_allow_min_diff
            && last_block.time + params.pow_target_spacing as u32 * 2 < next_header.time
        {
            return params.max_target;
        }
        // Regtest don't have retarget
        if !params.pow_allow_no_retarget && (next_height) % 2016 == 0 {
            // First block in this epoch
            let first_block = self.get_block_header_by_height(next_height - 2016);
            let last_block = self.get_block_header_by_height(next_height - 1);

            let next_bits =
                Self::calc_next_work_required(&last_block, &first_block, self.chain_params());
            let target = BlockHeader::u256_from_compact_target(next_bits);
            if target < params.max_target {
                return target;
            }
            return params.max_target;
        }
        last_block.target()
    }
    /// Returns the chain_params struct for the current network
    fn chain_params(&self) -> ChainParams {
        let inner = read_lock!(self);
        inner.chain_params.clone()
    }
    // This function should be only called if a block is guaranteed to be on chain
    fn get_block_header_by_height(&self, height: u32) -> BlockHeader {
        let block = self
            .get_block_hash(height)
            .expect("This block should be present");
        self.get_block_header(&block)
            .expect("This block should also be present")
    }
    fn update_acc(
        acc: &Stump,
        block: &Block,
        height: u32,
        proof: Proof,
        del_hashes: Vec<sha256::Hash>,
    ) -> Result<Stump, BlockchainError> {
        let block_hash = block.block_hash();
        let mut leaf_hashes = vec![];
        if !proof.verify(&del_hashes, acc)? {
            return Err(BlockchainError::InvalidProof);
        }
        let mut block_inputs = HashSet::new();
        for transaction in block.txdata.iter() {
            for input in transaction.input.iter() {
                block_inputs.insert((input.previous_output.txid, input.previous_output.vout));
            }
        }

        for transaction in block.txdata.iter() {
            for (i, output) in transaction.output.iter().enumerate() {
                if !output.script_pubkey.is_provably_unspendable()
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
        let acc = acc.modify(&leaf_hashes, &del_hashes, &proof)?.0;

        Ok(acc)
    }

    fn save_acc(&self) -> Result<(), bitcoin::consensus::encode::Error> {
        let inner = read_lock!(self);
        let mut ser_acc: Vec<u8> = vec![];
        inner.acc.leafs.consensus_encode(&mut ser_acc)?;
        #[allow(clippy::significant_drop_in_scrutinee)]
        for root in inner.acc.roots.iter() {
            ser_acc
                .write_all(root)
                .expect("String formatting should not err");
        }

        inner
            .chainstore
            .save_roots(ser_acc)
            .expect("Chain store is not working");
        Ok(())
    }
    #[allow(clippy::await_holding_lock)]
    async fn notify(&self, what: Notification) {
        //TODO: Use async-std::RwLock not std::RwLock
        let inner = self.inner.read().unwrap();
        let subs = inner.subscribers.iter();
        for client in subs {
            let _ = client.send(what.clone()).await;
        }
    }

    pub fn new(
        chainstore: KvChainStore,
        network: Network,
        assume_valid: Option<BlockHash>,
    ) -> ChainState<KvChainStore> {
        let genesis = genesis_block(network);
        chainstore
            .save_header(&super::chainstore::DiskBlockHeader::FullyValid(
                genesis.header,
                0,
            ))
            .expect("Error while saving genesis");
        chainstore
            .update_block_index(0, genesis.block_hash())
            .expect("Error updating index");

        let assume_valid_hash = Self::get_assume_valid_value(network, assume_valid);
        ChainState {
            inner: RwLock::new(ChainStateInner {
                chainstore,
                acc: Stump::new(),
                best_block: BestChain {
                    best_block: genesis.block_hash(),
                    depth: 0,
                    validation_index: genesis.block_hash(),
                    rescan_index: None,
                    alternative_tips: vec![],
                    assume_valid_index: 0,
                },
                broadcast_queue: vec![],
                subscribers: vec![],
                fee_estimation: (1_f64, 1_f64, 1_f64),
                ibd: true,
                chain_params: network.into(),
                assume_valid: (assume_valid_hash, 0),
            }),
        }
    }
    fn get_assume_valid_value(network: Network, arg: Option<BlockHash>) -> BlockHash {
        fn get_hash(hash: &str) -> BlockHash {
            BlockHash::from_hex(hash).expect("hardcoded hash should not fail")
        }
        if let Some(assume_valid_hash) = arg {
            assume_valid_hash
        } else {
            match network {
                Network::Bitcoin => {
                    get_hash("00000000000000000009c97098b5295f7e5f183ac811fb5d1534040adb93cabd")
                }
                Network::Testnet => {
                    get_hash("0000000000000004877fa2d36316398528de4f347df2f8a96f76613a298ce060")
                }
                Network::Signet => {
                    get_hash("000000d1a0e224fa4679d2fb2187ba55431c284fa1b74cbc8cfda866fd4d2c09")
                }
                Network::Regtest => {
                    get_hash("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")
                }
            }
        }
    }
    fn get_disk_block_header(&self, hash: &BlockHash) -> super::Result<DiskBlockHeader> {
        let inner = read_lock!(self);
        if let Some(header) = inner.chainstore.get_header(hash)? {
            return Ok(header);
        }
        Err(BlockchainError::BlockNotPresent)
    }
    /// If we ever find ourselves in an undefined state, with one of our chain pointers
    /// pointing to an invalid block, we'll find out what blocks do we have, and start from this
    /// point.
    fn reindex_chain(&self) -> BestChain {
        let inner = read_lock!(self);

        let mut height = 0;
        let mut hash = inner
            .chainstore
            .get_block_hash(0)
            .expect("No genesis block")
            .unwrap();
        while let Ok(Some(_hash)) = inner.chainstore.get_block_hash(height) {
            height += 1;
            hash = _hash;
        }
        BestChain {
            best_block: hash,
            depth: height,
            validation_index: hash,
            rescan_index: None,
            alternative_tips: vec![],
            assume_valid_index: 0,
        }
    }
    pub fn load_chain_state(
        chainstore: KvChainStore,
        network: Network,
        assume_valid_hash: Option<BlockHash>,
    ) -> Result<ChainState<KvChainStore>, BlockchainError> {
        let acc = Self::load_acc(&chainstore);

        let best_chain = chainstore.load_height()?;
        if best_chain.is_none() {
            return Err(BlockchainError::ChainNotInitialized);
        }
        let inner = ChainStateInner {
            acc,
            best_block: best_chain.unwrap(),
            broadcast_queue: Vec::new(),
            chainstore,
            fee_estimation: (1_f64, 1_f64, 1_f64),
            subscribers: Vec::new(),
            ibd: true,
            chain_params: network.into(),
            assume_valid: (Self::get_assume_valid_value(network, assume_valid_hash), 0),
        };
        info!(
            "Chainstate loaded at height: {}, checking if we have all blocks",
            inner.best_block.best_block
        );
        let chainstate = ChainState {
            inner: RwLock::new(inner),
        };
        chainstate.reindex_chain();
        Ok(chainstate)
    }

    fn load_acc<Storage: ChainStore>(data_storage: &Storage) -> Stump {
        let acc = data_storage
            .load_roots()
            .expect("load_acc: Could not read roots");
        if acc.is_none() {
            return Stump::new();
        }
        let mut acc = acc.unwrap();
        let leaves = acc.drain(0..8).collect::<Vec<u8>>();
        let (leaves, _) =
            deserialize_partial::<u64>(&leaves).expect("load_acc: Invalid num_leaves");
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
    fn update_view(
        &self,
        height: u32,
        block: &BlockHeader,
        acc: Stump,
    ) -> Result<(), BlockchainError> {
        let mut inner = write_lock!(self);
        inner
            .chainstore
            .save_header(&super::chainstore::DiskBlockHeader::FullyValid(
                *block, height,
            ))?;
        inner
            .chainstore
            .update_block_index(height, block.block_hash())?;
        inner.chainstore.save_height(&inner.best_block)?;
        // Updates our local view of the network
        inner.acc = acc;
        inner.best_block.valid_block(block.block_hash());
        if block.block_hash() == inner.assume_valid.0 {
            inner.assume_valid.1 = height;
        }
        Ok(())
    }
    fn update_tip(&self, best_block: BlockHash, height: u32) {
        let mut inner = write_lock!(self);
        inner.best_block.best_block = best_block;
        inner.best_block.depth = height;
    }
    fn verify_script(&self, height: u32) -> bool {
        let inner = self.inner.read().unwrap();
        inner.assume_valid.1 < height
    }
    fn acc(&self) -> Stump {
        read_lock!(self).acc.to_owned()
    }
    fn validate_block(
        &self,
        block: &Block,
        height: u32,
        inputs: HashMap<OutPoint, TxOut>,
    ) -> Result<(), BlockchainError> {
        if !block.check_merkle_root() {
            return Err(BlockchainError::BlockValidationError(
                BlockValidationErrors::BadMerkleRoot,
            ));
        }
        if height >= self.chain_params().bip34_activation_height
            && block.bip34_block_height() != Ok(height as u64)
        {
            return Err(BlockchainError::BlockValidationError(
                BlockValidationErrors::BadBip34,
            ));
        }
        if !block.check_witness_commitment() {
            return Err(BlockchainError::BlockValidationError(
                BlockValidationErrors::BadWitnessCommitment,
            ));
        }
        let prev_block = self.get_ancestor(&block.header)?;
        if block.header.prev_blockhash != prev_block.block_hash() {
            return Err(BlockchainError::BlockValidationError(
                BlockValidationErrors::BlockExtendsAnOrphanChain,
            ));
        }
        // Validate block transactions
        let subsidy = self.get_subsidy(height);
        let verify_script = self.verify_script(height);
        let flags = self.get_validation_flags(height);
        Self::verify_block_transactions(inputs, &block.txdata, subsidy, verify_script, flags)
            .map_err(|_| BlockchainError::BlockValidationError(BlockValidationErrors::InvalidTx))?;
        Ok(())
    }
}

impl<PersistedState: ChainStore> BlockchainInterface for ChainState<PersistedState> {
    fn is_in_idb(&self) -> bool {
        self.inner.read().unwrap().ibd
    }

    fn get_block_hash(&self, height: u32) -> super::Result<bitcoin::BlockHash> {
        let inner = self.inner.read().expect("get_block_hash: Poisoned lock");
        if let Some(hash) = inner.chainstore.get_block_hash(height)? {
            return Ok(hash);
        }
        Err(BlockchainError::BlockNotPresent)
    }

    fn get_tx(&self, _txid: &bitcoin::Txid) -> super::Result<Option<bitcoin::Transaction>> {
        unimplemented!("This chainstate doesn't hold any tx")
    }

    fn get_height(&self) -> super::Result<u32> {
        let inner = read_lock!(self);
        Ok(inner.best_block.depth)
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
        unimplemented!("This chainstate doesn't hold full blocks")
    }

    fn get_best_block(&self) -> super::Result<(u32, BlockHash)> {
        let inner = read_lock!(self);
        Ok((inner.best_block.depth, inner.best_block.best_block))
    }

    fn get_block_header(&self, hash: &BlockHash) -> super::Result<bitcoin::BlockHeader> {
        let inner = read_lock!(self);
        if let Some(header) = inner.chainstore.get_header(hash)? {
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
    fn get_block_locator(&self) -> Result<Vec<BlockHash>, BlockchainError> {
        let top_height = self.get_height()?;
        let mut indexes = vec![];
        let mut step = 1;
        let mut index = top_height;
        while index > 0 {
            if indexes.len() >= 10 {
                step *= 2;
            }
            indexes.push(index);
            if index > step {
                index -= step;
            } else {
                break;
            }
        }
        indexes.push(0);
        let hashes = indexes
            .iter()
            .map(|idx| self.get_block_hash(*idx).unwrap())
            .collect();

        Ok(hashes)
    }
    fn invalidate_block(&self, block: BlockHash) -> super::Result<()> {
        let height = self.get_disk_block_header(&block)?.height();
        if height.is_none() {
            return Err(BlockchainError::BlockNotPresent);
        }
        let height = height.unwrap();
        let current_height = self.get_height()?;
        // Mark all blocks after this one as invalid
        for h in height..=current_height {
            let hash = self.get_block_hash(h)?;
            let header = self.get_block_header(&hash)?;
            let new_header = DiskBlockHeader::InvalidChain(header);
            self.update_header(&new_header)?;
        }
        // Row back to our previous state. Note that acc doesn't actually change in this case
        // only the currently best known block.
        self.update_tip(
            self.get_ancestor(&self.get_block_header(&block)?)?
                .block_hash(),
            height - 1,
        );
        Ok(())
    }
    fn toggle_ibd(&self, is_ibd: bool) {
        let mut inner = write_lock!(self);
        inner.ibd = is_ibd;
    }
    fn connect_block(
        &self,
        block: &Block,
        proof: Proof,
        inputs: HashMap<OutPoint, TxOut>,
        del_hashes: Vec<sha256::Hash>,
    ) -> super::Result<()> {
        let header = self.get_disk_block_header(&block.block_hash())?;
        let height = match header {
            // If it's valid or orphan, we don't validate
            DiskBlockHeader::FullyValid(_, _) => {
                self.inner
                    .write()
                    .unwrap()
                    .best_block
                    .valid_block(block.block_hash());
                return Ok(());
            }
            DiskBlockHeader::Orphan(_) | DiskBlockHeader::InFork(_, _) => return Ok(()),
            DiskBlockHeader::HeadersOnly(_, height) => height,
            DiskBlockHeader::InvalidChain(_) => return Ok(()),
        };
        self.validate_block(block, height, inputs)?;
        let acc = Self::update_acc(&self.acc(), block, height, proof, del_hashes)?;
        // ... If we came this far, we consider this block valid ...
        if self.is_in_idb() && height % 10_000 == 0 {
            info!("Downloading blocks at: {height}");
            self.flush()?;
        }
        // Notify others we have a new block
        async_std::task::block_on(self.notify(Notification::NewBlock((block.to_owned(), height))));
        self.update_view(height, &block.header, acc)?;
        self.save_acc()?;
        Ok(())
    }

    fn handle_transaction(&self) -> super::Result<()> {
        unimplemented!("This chain_state has no mempool")
    }

    fn flush(&self) -> super::Result<()> {
        self.save_acc()?;
        let inner = read_lock!(self);
        inner.chainstore.flush()?;
        inner.chainstore.save_height(&inner.best_block)?;
        Ok(())
    }
    fn get_unbroadcasted(&self) -> Vec<Transaction> {
        let mut inner = write_lock!(self);
        inner.broadcast_queue.drain(..).collect()
    }
    fn accept_header(&self, header: BlockHeader) -> super::Result<()> {
        trace!("Accepting header {header:?}");
        let _header = self.get_disk_block_header(&header.block_hash());
        if _header.is_ok() {
            return Ok(()); // We already have this header
        }
        let best_block = self.get_best_block()?;
        // Do validation in this header
        let block_hash = self.validate_header(&header)?;
        // Update our current tip
        if header.prev_blockhash == best_block.1 {
            let height = best_block.0 + 1;
            trace!("Header builds on top of our best chain");

            let mut inner = write_lock!(self);
            inner.best_block.new_block(block_hash, height);
            inner
                .chainstore
                .save_header(&super::chainstore::DiskBlockHeader::HeadersOnly(
                    header, height,
                ))?;

            inner.chainstore.update_block_index(height, block_hash)?;
            if header.block_hash() == inner.assume_valid.0 {
                inner.assume_valid.1 = height;
            }
        } else {
            trace!("Header not in the best chain");
            self.maybe_reorg(header)?;
        }
        Ok(())
    }

    fn get_validation_index(&self) -> super::Result<u32> {
        let inner = self.inner.read().unwrap();
        let validation = inner.best_block.validation_index;
        let header = self.get_disk_block_header(&validation)?;
        match header {
            DiskBlockHeader::HeadersOnly(_, height) => Ok(height),
            DiskBlockHeader::FullyValid(_, height) => Ok(height),
            _ => {
                self.reindex_chain();
                log::error!("Validation index is in an invalid state, re-indexing chainstate");
                Ok(0)
            }
        }
    }

    fn is_coinbase_mature(&self, height: u32, block: BlockHash) -> super::Result<bool> {
        let chain_params = self.chain_params();
        let current_height = self.get_disk_block_header(&block)?.height().unwrap_or(0);

        Ok(height + chain_params.coinbase_maturity <= current_height)
    }
}
#[macro_export]
/// Grabs a RwLock for reading
macro_rules! read_lock {
    ($obj: ident) => {
        $obj.inner.read().expect("get_block_hash: Poisoned lock")
    };
}
#[macro_export]
/// Grabs a RwLock for writing
macro_rules! write_lock {
    ($obj: ident) => {
        $obj.inner.write().expect("get_block_hash: Poisoned lock")
    };
}

#[derive(Clone)]
/// Internal representation of the chain we are in
pub struct BestChain {
    /// Hash of the last block in the chain we believe has more work on
    best_block: BlockHash,
    /// How many blocks are pilled on this chain?
    depth: u32,
    /// We actually validated blocks up to this point
    validation_index: BlockHash,
    /// We may rescan even after we validate all blocks, this index saves the position
    /// we are while re-scanning
    rescan_index: Option<BlockHash>,
    /// Blockchains are not fast-forward only, they might have "forks", sometimes it's useful
    /// to keep track of them, in case they become the best one. This keeps track of some
    /// tips we know about, but are not the best one. We don't keep tips that are too deep
    /// or has too little work if compared to our best one
    alternative_tips: Vec<BlockHash>,
    /// Saves the height occupied by the assume valid block
    assume_valid_index: u32,
}
impl BestChain {
    fn new_block(&mut self, block_hash: BlockHash, height: u32) {
        self.best_block = block_hash;
        self.depth = height;
    }
    fn valid_block(&mut self, block_hash: BlockHash) {
        self.validation_index = block_hash;
    }
}
impl Encodable for BestChain {
    fn consensus_encode<W: std::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, std::io::Error> {
        let mut len = 0;
        len += self.best_block.consensus_encode(writer)?;
        len += self.depth.consensus_encode(writer)?;
        len += self.validation_index.consensus_encode(writer)?;
        len += self.assume_valid_index.consensus_encode(writer)?;

        match self.rescan_index {
            Some(hash) => len += hash.consensus_encode(writer)?,
            None => len += BlockHash::all_zeros().consensus_encode(writer)?,
        }
        len += self.alternative_tips.consensus_encode(writer)?;
        Ok(len)
    }
}
impl Decodable for BestChain {
    fn consensus_decode<R: std::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let best_block = BlockHash::consensus_decode(reader)?;
        let depth = u32::consensus_decode(reader)?;
        let validation_index = BlockHash::consensus_decode(reader)?;
        let rescan_index = BlockHash::consensus_decode(reader)?;
        let assume_valid_index = u32::consensus_decode(reader)?;

        let rescan_index = if rescan_index == BlockHash::all_zeros() {
            None
        } else {
            Some(rescan_index)
        };
        let alternative_tips = <Vec<BlockHash>>::consensus_decode(reader)?;
        Ok(Self {
            alternative_tips,
            best_block,
            depth,
            rescan_index,
            validation_index,
            assume_valid_index,
        })
    }
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, io::Cursor};

    use bitcoin::{
        consensus::{deserialize, Decodable},
        hashes::hex::FromHex,
        Block, BlockHash, BlockHeader, Network,
    };
    use rustreexo::accumulator::proof::Proof;

    use crate::blockchain::{
        chainparams::ChainParams,
        chainstore::{DiskBlockHeader, KvChainStore},
        BlockchainInterface, BlockchainProviderInterface,
    };

    use super::ChainState;
    #[test]
    fn accept_mainnet_headers() {
        // Accepts the first 10235 mainnet headers
        let file = include_bytes!("./testdata/headers.zst");
        let uncompressed: Vec<u8> = zstd::decode_all(std::io::Cursor::new(file)).unwrap();
        let mut cursor = Cursor::new(uncompressed);

        let test_id = rand::random::<u64>();
        let chainstore = KvChainStore::new(format!("./data/{test_id}/")).unwrap();
        let chain = ChainState::<KvChainStore>::new(chainstore, Network::Bitcoin, None);
        while let Ok(header) = BlockHeader::consensus_decode(&mut cursor) {
            chain.accept_header(header).unwrap();
        }
    }
    #[test]
    fn accept_first_signet_headers() {
        // Accepts the first 2016 signet headers
        let file = include_bytes!("./testdata/signet_headers.zst");
        let uncompressed: Vec<u8> = zstd::decode_all(std::io::Cursor::new(file)).unwrap();
        let mut cursor = Cursor::new(uncompressed);

        let test_id = rand::random::<u64>();
        let chainstore = KvChainStore::new(format!("./data/{test_id}/")).unwrap();
        let chain = ChainState::<KvChainStore>::new(chainstore, Network::Signet, None);
        while let Ok(header) = BlockHeader::consensus_decode(&mut cursor) {
            chain.accept_header(header).unwrap();
        }
    }
    #[test]
    fn test_calc_next_work_required() {
        let first_block = Vec::from_hex("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a008f4d5fae77031e8ad22203").unwrap();
        let first_block: BlockHeader = deserialize(&first_block).unwrap();

        let last_block = Vec::from_hex("00000020dec6741f7dc5df6661bcb2d3ec2fceb14bd0e6def3db80da904ed1eeb8000000d1f308132e6a72852c04b059e92928ea891ae6d513cd3e67436f908c804ec7be51df535fae77031e4d00f800").unwrap();
        let last_block = deserialize(&last_block).unwrap();

        let next_target = super::ChainState::<KvChainStore>::calc_next_work_required(
            &last_block,
            &first_block,
            ChainParams::from(Network::Bitcoin),
        );

        assert_eq!(0x1e012fa7, next_target);
    }
    #[test]
    fn test_reorg() {
        let test_id = rand::random::<u64>();
        let chainstore = KvChainStore::new(format!("./data/{test_id}/")).unwrap();
        let chain = ChainState::<KvChainStore>::new(chainstore, Network::Regtest, None);
        let blocks = include_str!("./testdata/test_reorg.json");
        let blocks: Vec<Vec<&str>> = serde_json::from_str(blocks).unwrap();

        for block in blocks[0].iter() {
            let block = Vec::from_hex(block).unwrap();
            let block: Block = deserialize(&block).unwrap();
            chain.accept_header(block.header).unwrap();
            chain
                .connect_block(&block, Proof::default(), HashMap::new(), vec![])
                .unwrap();
        }
        assert_eq!(
            chain.get_best_block().unwrap(),
            (
                10,
                BlockHash::from_hex(
                    "6e9c49a19038f7db8d13f6c2e70566385536ea11975528b557799e08a014e784"
                )
                .unwrap()
            )
        );

        for fork in blocks[1].iter() {
            let block = Vec::from_hex(fork).unwrap();
            let block: Block = deserialize(&block).unwrap();
            chain.accept_header(block.header).unwrap();
        }
        let best_block = chain.get_best_block().unwrap();
        assert_eq!(
            best_block,
            (
                16,
                BlockHash::from_hex(
                    "4572ac401b94915dde6c4957b706abdb13b5824b000cad7f6065ebd9aea6dad1"
                )
                .unwrap()
            )
        );
        for i in 1..=chain.get_height().unwrap() {
            if let Ok(DiskBlockHeader::HeadersOnly(_, _)) =
                chain.get_disk_block_header(&chain.get_block_hash(i).unwrap())
            {
                continue;
            }
            panic!("Block {} is not in the store", i);
        }
    }
}
