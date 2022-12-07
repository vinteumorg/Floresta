use std::collections::{HashMap, HashSet};
use std::ops::RangeInclusive;
use std::vec;

use super::chainstore::ChainStore;
use super::udata::LeafData;
use crate::address_cache::{AddressCache, AddressCacheDatabase};
use crate::error::Error;
use bitcoin::consensus::{deserialize, deserialize_partial, Encodable};
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{Block, BlockHash};
use bitcoin::{OutPoint, Transaction, TxOut};
use btcd_rpc::client::BtcdRpc;
use btcd_rpc::json_types::VerbosityOutput;
use rustreexo::accumulator::proof::Proof;
use rustreexo::accumulator::stump::Stump;
use sha2::{Digest, Sha512_256};

#[derive(Debug, Default)]
pub struct BlockchainSync;
impl BlockchainSync {
    pub fn get_block<T: BtcdRpc>(rpc: &T, height: u32) -> Result<Block, crate::error::Error> {
        let hash = rpc.getblockhash(height as usize)?;
        let block = rpc.getblock(hash, false)?;
        if let VerbosityOutput::Simple(hex) = block {
            let block = Vec::from_hex(hex.as_str())?;
            let (block, _): (Block, usize) = deserialize_partial(&block).unwrap();
            let validation = block.header.validate_pow(&block.header.target());
            assert!(validation.is_ok());
            return Ok(block);
        }
        Err(Error::BlockNotFound)
    }
    pub fn verify_block_transactions(
        mut utxos: HashMap<OutPoint, TxOut>,
        transactions: &[Transaction],
    ) -> Result<bool, crate::error::Error> {
        for transaction in transactions {
            if !transaction.is_coin_base() {
                transaction.verify(|outpoint| utxos.remove(outpoint))?;
            }
        }
        Ok(true)
    }
    pub fn _sync_all<D: AddressCacheDatabase, Rpc: BtcdRpc, S: ChainStore>(
        rpc: &Rpc,
        address_cache: &mut AddressCache<D, S>,
    ) -> Result<(), crate::error::Error> {
        let height = rpc.getbestblock().expect("sync_all: Rpc failed").height as u32;
        Self::sync_range(rpc, address_cache, 1..=height)?;
        Ok(())
    }
    pub fn sync_range<T: BtcdRpc, D: AddressCacheDatabase, S: ChainStore>(
        rpc: &T,
        address_cache: &mut AddressCache<D, S>,
        range: RangeInclusive<u32>,
    ) -> Result<(), crate::error::Error> {
        let current_height = *range.end();
        for block_height in range {
            let block = BlockchainSync::get_block(rpc, block_height)?;

            let (proof, del_hashes, utxos) = Self::get_proof(rpc, &block.block_hash().to_string())
                .expect("Could not get block proof");
            let mut utxo_map = HashMap::new();
            for utxo in utxos {
                utxo_map.insert(utxo.prevout, utxo.utxo);
            }
            for transaction in block.txdata.iter() {
                for (idx, out) in transaction.output.iter().enumerate() {
                    utxo_map.insert(
                        OutPoint {
                            txid: transaction.txid(),
                            vout: idx as u32,
                        },
                        out.clone(),
                    );
                }
            }
            Self::verify_block_transactions(utxo_map, &block.txdata)?;

            if block_height % 1000 == 0 {
                println!(
                    "Update: height {block_height} progress: {:>5}%",
                    (block_height as f32 / current_height as f32) * 100 as f32,
                );
                // These operations involves expensive db calls, only make it after some
                // substantial progress
                address_cache.save_acc();
                address_cache.bump_height(block_height);
            }
            address_cache.block_process(&block, block_height, proof, del_hashes);
        }
        address_cache.save_acc();
        address_cache.bump_height(current_height);
        Ok(())
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
    ) -> Result<Stump, crate::error::Error> {
        let block_hash = block.block_hash();
        let mut leaf_hashes = vec![];

        if !proof.verify(&del_hashes, acc)? {
            return Err(crate::error::Error::InvalidProof);
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
                    leaf_hashes.push(BlockchainSync::get_leaf_hashes(
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
    ) -> Result<(Proof, Vec<sha256::Hash>, Vec<LeafData>), crate::error::Error> {
        let proof = rpc.getutreexoproof(hash.to_string(), true)?.get_verbose();
        let preimages: Vec<_> = proof
            .target_preimages
            .iter()
            .map(|preimage| deserialize_partial::<LeafData>(&Vec::from_hex(preimage).unwrap()))
            .filter(|data| data.is_ok())
            .map(|data| data.unwrap().0)
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
    pub fn _sync_single<T: BtcdRpc, D: AddressCacheDatabase, S: ChainStore>(
        rpc: &T,
        address_cache: &mut AddressCache<D, S>,
        blocks: u32,
    ) {
        for block_height in 0..blocks {
            let block = BlockchainSync::get_block(rpc, block_height).unwrap();
            let (proof, del_hashes, _) = Self::get_proof(rpc, &block.block_hash().to_string())
                .expect("Could not get block proof");

            if block_height % 1000 == 0 {
                println!("Sync at block {block_height}: {}", block.block_hash());
            }
            let _ = address_cache.block_process(&block, block_height, proof, del_hashes);
        }
    }
}

#[test]
fn test_get_leaf_hashes() {
    use bitcoin::consensus::deserialize;
    let tx = Vec::from_hex("02000000000101d997ca3adb105089361299c6bcb79b678b79bd949f94c70d396c8813877f7ccf0000000000fdffffff01da160f0000000000160014275f567685bfe080e4789eaca36d9af30327abac0247304402201528001078868c9195ff9358a6d0b529f263e280ae86fc55617283b42ca66f8f02203deb150aeb930a1e21b792ebe50bfab60c51145447ac24a56363791b1517b730012102c97b9dd85d82fbb127bef4d6640ea6cdba460c5d092e7bfc3a7ea3777bc7523a32cc0100").unwrap();
    let tx: Transaction = deserialize(&tx).unwrap();
    let block_hash = bitcoin::hash_types::BlockHash::from_hex(
        "0000001b958a51888359f5c064593255f02a217d5ada160611f87313a27e3ec4",
    )
    .unwrap();
    let expected =
        sha256::Hash::from_hex("507d175748a1fccc83f3f79ec57414fd6601bc32b0d1ab77882a86af2cc2addb")
            .unwrap();
    let hash = BlockchainSync::get_leaf_hashes(&tx, 0, 117811, block_hash);
    assert_eq!(hash, expected)
}
