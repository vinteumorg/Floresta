#![allow(unused)]
use std::{
    collections::{HashMap, HashSet},
    ops::RangeInclusive,
    sync::Arc,
    thread,
};

use bitcoin::{
    consensus::{deserialize_partial, Decodable, Encodable},
    hashes::{
        hex::{FromHex, ToHex},
        sha256, Hash,
    },
    Block, BlockHash, OutPoint, Transaction, TxOut,
};
use btcd_rpc::{
    client::{BTCDClient, BtcdRpc},
    json_types::VerbosityOutput,
};
use rustreexo::accumulator::{proof::Proof, stump::Stump};
use sha2::{Digest, Sha512_256};

use super::{
    chain_state::ChainState,
    chainstore::{ChainStore, KvChainStore},
    error::BlockchainError,
    udata::LeafData,
    Result,
};

pub struct UtreexodBackend {
    pub rpc: Arc<BTCDClient>,
    pub chainstate: ChainState<KvChainStore>,
}

impl UtreexodBackend {
    fn get_block_hash(&self, height: u32) -> Result<bitcoin::BlockHash> {
        Ok(BlockHash::from_hex(
            self.rpc.getblockhash(height as usize)?.as_str(),
        )?)
    }
    fn get_tx(&self, txid: &bitcoin::Txid) -> Result<Option<bitcoin::Transaction>> {
        let tx = self.rpc.getrawtransaction(txid.to_hex(), false).unwrap();
        if let VerbosityOutput::Simple(hex) = tx {
            let tx = Transaction::consensus_decode(&mut hex.as_bytes())
                .map_err(|err| BlockchainError::UnknownError(Box::new(err)))?;
            return Ok(Some(tx));
        }
        Err(BlockchainError::TxNotFound)
    }
    fn get_height(&self) -> Result<u32> {
        if let Ok(block) = self.rpc.getbestblock() {
            Ok(block.height as u32)
        } else {
            Ok(0)
        }
    }

    fn broadcast(&self, tx: &bitcoin::Transaction) -> Result<()> {
        let mut writer = Vec::new();
        let _ = tx
            .consensus_encode(&mut writer)
            .expect("Should be a valid transaction");

        self.rpc.sendrawtransaction(writer.to_hex())?;
        Ok(())
    }

    fn estimate_fee(&self, target: usize) -> Result<f64> {
        let feerate = self.rpc.estimatefee(target as u32)?;
        Ok(feerate)
    }
}
impl UtreexodBackend {
    pub fn get_block<T: BtcdRpc>(rpc: &T, height: u32) -> Result<Block> {
        let hash = rpc.getblockhash(height as usize)?;
        let block = rpc.getblock(hash, false)?;
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
    pub async fn run(self) {
        loop {
            // Awaits a couple of seconds before refreshing data
            async_std::task::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
    pub fn verify_block_transactions(
        mut utxos: HashMap<OutPoint, TxOut>,
        transactions: &[Transaction],
    ) -> Result<bool> {
        for transaction in transactions {
            if !transaction.is_coin_base() {
                transaction.verify(|outpoint| utxos.remove(outpoint))?;
            }
        }
        Ok(true)
    }
}
