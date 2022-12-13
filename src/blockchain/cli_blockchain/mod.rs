#![allow(unused)]
use std::{
    collections::{HashMap, HashSet},
    ops::RangeInclusive,
    sync::Arc,
};

use bitcoin::{
    consensus::{deserialize_partial, Encodable},
    hashes::{hex::FromHex, sha256, Hash},
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
// impl BlockchainInterface for UtreexodBackend {
//     fn get_block_hash(&self, height: u32) -> Result<bitcoin::BlockHash> {
//         Ok(BlockHash::from_hex(
//             self.rpc.getblockhash(height as usize)?.as_str(),
//         )?)
//     }
//     fn get_tx(&self, txid: &bitcoin::Txid) -> Result<Option<bitcoin::Transaction>> {
//         let tx = self.rpc.getrawtransaction(txid.to_hex(), false).unwrap();
//         if let VerbosityOutput::Simple(hex) = tx {
//             let tx = Transaction::consensus_decode(&mut hex.as_bytes())
//                 .map_err(|err| BlockchainError::UnknownError(Box::new(err)))?;
//             return Ok(Some(tx));
//         }
//         Err(BlockchainError::TxNotFound)
//     }
//     fn get_height(&self) -> Result<u32> {
//         if let Ok(block) = self.rpc.getbestblock() {
//             Ok(block.height as u32)
//         } else {
//             Ok(0)
//         }
//     }

//     fn broadcast(&self, tx: &bitcoin::Transaction) -> Result<()> {
//         let mut writer = Vec::new();
//         let _ = tx
//             .consensus_encode(&mut writer)
//             .expect("Should be a valid transaction");

//         self.rpc.sendrawtransaction(writer.to_hex())?;
//         Ok(())
//     }

//     fn estimate_fee(&self, target: usize) -> Result<f64> {
//         let feerate = self.rpc.estimatefee(target as u32)?;
//         Ok(feerate)
//     }

//     fn get_block(&self, _hash: &BlockHash) -> Result<Block> {
//         todo!()
//     }

//     fn connect_block(&self, block: bitcoin::Block) -> super::Result<u32> {
//         todo!()
//     }

//     fn get_best_block(&self) -> super::Result<(u32, bitcoin::BlockHash)> {
//         todo!()
//     }

//     fn get_block_header(&self, hash: &bitcoin::BlockHash) -> super::Result<bitcoin::BlockHeader> {
//         todo!()
//     }
//     fn subscribe<F: Fn(Block) -> ()>(&self, callback: F) {
//         todo!()
//     }
// }
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

    pub fn sync_range<T: BtcdRpc, S: ChainStore>(
        _rpc: &T,
        _range: RangeInclusive<u32>,
        _ibd: bool,
    ) -> Result<()> {
        // let current_height = *range.end();
        // for block_height in range {
        //     let block = Self::get_block(rpc, block_height)?;

        //     let (proof, del_hashes, utxos) = Self::get_proof(rpc, &block.block_hash().to_string())
        //         .expect("Could not get block proof");
        //     let mut utxo_map = HashMap::new();
        //     for utxo in utxos {
        //         utxo_map.insert(utxo.prevout, utxo.utxo);
        //     }
        //     for transaction in block.txdata.iter() {
        //         for (idx, out) in transaction.output.iter().enumerate() {
        //             utxo_map.insert(
        //                 OutPoint {
        //                     txid: transaction.txid(),
        //                     vout: idx as u32,
        //                 },
        //                 out.clone(),
        //             );
        //         }
        //     }
        //     Self::verify_block_transactions(utxo_map, &block.txdata)?;
        //     address_cache.block_process(&block, block_height, proof, del_hashes);

        //     if block_height % 1000 == 0 && ibd {
        //         info!(
        //             "height {block_height:2.0} progress: {progress:<2}%",
        //             progress =
        //                 ((block_height as f32 / current_height as f32) * 100_f32).round() as u32,
        //         );
        //         // These operations involves expensive db calls, only make it after some
        //         // substantial progress
        //         address_cache.save_acc();
        //         address_cache.bump_height(block_height);
        //     }
        // }
        // if !ibd {
        //     info!("New block height {current_height}");
        // }
        // address_cache.save_acc();
        // address_cache.bump_height(current_height);
        // Ok(())
        todo!()
    }
    // TODO: Move to LeafData
    fn get_leaf_hashes(
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

    pub fn update_acc(
        acc: &Stump,
        block: &Block,
        height: u32,
        proof: Proof,
        del_hashes: Vec<sha256::Hash>,
    ) -> Result<Stump> {
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
}
