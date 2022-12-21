use std::{collections::HashMap, sync::Arc, time::Duration};

use bitcoin::{
    consensus::{deserialize_partial, Encodable},
    hashes::{
        hex::{FromHex, ToHex},
        sha256,
    },
    Block, BlockHash, OutPoint,
};
use btcd_rpc::{
    client::{BTCDClient, BtcdRpc},
    json_types::VerbosityOutput,
};
use log::info;
use rustreexo::accumulator::proof::Proof;

use super::{
    chain_state::ChainState, chainstore::KvChainStore, error::BlockchainError, udata::LeafData,
    BlockchainInterface, BlockchainProviderInterface, Result,
};
use crate::try_and_log;

pub struct UtreexodBackend {
    pub rpc: Arc<BTCDClient>,
    pub chainstate: Arc<ChainState<KvChainStore>>,
}

impl UtreexodBackend {
    fn _get_block_hash(&self, height: u32) -> Result<bitcoin::BlockHash> {
        Ok(BlockHash::from_hex(
            self.rpc.getblockhash(height as usize)?.as_str(),
        )?)
    }
    fn get_height(&self) -> Result<u32> {
        let block = self.rpc.getbestblock()?;
        Ok(block.height as u32)
    }

    fn broadcast(&self, tx: &bitcoin::Transaction) -> Result<()> {
        let mut writer = Vec::new();
        let _ = tx
            .consensus_encode(&mut writer)
            .expect("Should be a valid transaction");

        self.rpc.sendrawtransaction(writer.to_hex())?;
        Ok(())
    }

    fn _estimate_fee(&self, target: usize) -> Result<f64> {
        let feerate = self.rpc.estimatefee(target as u32)?;
        Ok(feerate)
    }
    pub fn get_block(&self, height: u32) -> Result<Block> {
        let hash = self.rpc.getblockhash(height as usize)?;
        let block = self.rpc.getblock(hash, false)?;
        if let VerbosityOutput::Simple(hex) = block {
            let block = Vec::from_hex(hex.as_str())?;
            let (block, _): (Block, usize) = deserialize_partial(&block).unwrap();
            let validation = block.header.validate_pow(&block.header.target());
            assert!(validation.is_ok());
            return Ok(block);
        }
        Err(BlockchainError::BlockNotPresent)
    }
    pub fn get_proof<T: BtcdRpc>(
        rpc: &T,
        hash: &String,
    ) -> Result<(Proof, Vec<sha256::Hash>, Vec<LeafData>)> {
        let proof = rpc.getutreexoproof(hash.to_string(), true)?.get_verbose();
        let preimages: Vec<_> = proof
            .target_preimages
            .iter()
            .map(|preimage| {
                deserialize_partial::<LeafData>(&Vec::from_hex(preimage).unwrap())
                    .unwrap()
                    .0
            })
            .collect();

        let proof_hashes: Vec<_> = proof
            .proofhashes
            .iter()
            .map(|hash| sha256::Hash::from_hex(hash).unwrap())
            .collect();
        let targets = proof.prooftargets;

        let targethashes: Vec<_> = proof
            .targethashes
            .iter()
            .map(|hash| sha256::Hash::from_hex(hash).unwrap())
            .collect();
        let proof = Proof::new(targets, proof_hashes);

        Ok((proof, targethashes, preimages))
    }

    pub fn handle_broadcast(&self) -> Result<()> {
        let tx_list = self.chainstate.get_unbroadcasted();
        for tx in tx_list {
            self.broadcast(&tx)?;
        }
        Ok(())
    }
    pub fn handle_tip_update(&self) -> Result<()> {
        let height = self.get_height()?;
        let local_best = self.chainstate.get_best_block().unwrap().0;
        if height > local_best {
            for block_height in (local_best + 1)..=height {
                self.process_block(block_height)?;
            }
        }
        Ok(())
    }
    fn process_block(&self, block_height: u32) -> Result<()> {
        let block = self.get_block(block_height)?;
        let (proof, del_hashes, leaf_data) =
            Self::get_proof(&*self.rpc, &block.block_hash().to_string())?;
        let mut inputs = HashMap::new();
        for tx in block.txdata.iter() {
            for (vout, out) in tx.output.iter().enumerate() {
                inputs.insert(
                    OutPoint {
                        txid: tx.txid(),
                        vout: vout as u32,
                    },
                    out.clone(),
                );
            }
        }
        for leaf in leaf_data {
            inputs.insert(leaf.prevout, leaf.utxo);
        }
        self.chainstate
            .connect_block(&block, proof, inputs, del_hashes, block_height)?;
        Ok(())
    }
    fn start_ibd(&self) -> Result<()> {
        let height = self.get_height()?;
        let current = self.chainstate.get_best_block()?.0;
        info!("Start Initial Block Download at height {current} of {height}");
        for block_height in (current + 1)..=height {
            if block_height % 2016 == 0 {
                info!("Sync at block {block_height}");
                if block_height % 100_000 == 0 {
                    self.chainstate.flush()?;
                }
            }
            self.process_block(block_height)?;
        }
        info!("Leaving Initial Block Download at height {height}");
        self.chainstate.toggle_ibd(false);
        self.chainstate.flush()?;

        Ok(())
    }

    pub async fn run(self) -> ! {
        try_and_log!(self.start_ibd());
        loop {
            async_std::task::sleep(Duration::from_secs(1)).await;

            try_and_log!(self.handle_broadcast());
            try_and_log!(self.handle_tip_update());
            try_and_log!(self.chainstate.flush());
        }
    }
}
#[macro_export]
macro_rules! try_and_log {
    ($what: expr) => {
        let result = $what;
        if let Err(error) = result {
            log::error!("{:?}", error);
        }
    };
}
