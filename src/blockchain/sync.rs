use std::io::Write;
use std::ops::RangeInclusive;
use std::vec;

use crate::address_cache::{AddressCache, AddressCacheDatabase};
use crate::error::Error;
use bitcoin::consensus::{deserialize, Encodable};
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::Transaction;
use bitcoin::{Block, BlockHash};
use btcd_rpc::client::BtcdRpc;
use btcd_rpc::json_types::VerbosityOutput;
use rustreexo::accumulator::proof::Proof;
use rustreexo::accumulator::stump::Stump;
use sha2::{Digest, Sha512_256};

#[derive(Debug, Default)]
pub struct BlockchainSync;
#[allow(unused)]
impl BlockchainSync {
    pub fn get_block<T: BtcdRpc>(rpc: &T, height: u32) -> Result<Block, crate::error::Error> {
        let hash = rpc.getblockhash(height as usize)?;

        let block = rpc.getblock(hash, false)?;
        if let VerbosityOutput::Simple(hex) = block {
            let block = Vec::from_hex(hex.as_str())?;
            let block = deserialize(&block)?;
            return Ok(block);
        }
        Err(Error::BlockNotFound)
    }
    pub fn sync_all<D: AddressCacheDatabase, Rpc: BtcdRpc>(
        rpc: &Rpc,
        address_cache: &mut AddressCache<D>,
    ) -> Result<(), crate::error::Error> {
        let height = rpc.getbestblock().expect("sync_all: Rpc failed").height;
        Self::sync_range(rpc, address_cache, 0..=100);
        Ok(())
    }

    pub fn sync_range<T: BtcdRpc, D: AddressCacheDatabase>(
        rpc: &T,
        address_cache: &mut AddressCache<D>,
        range: RangeInclusive<u32>,
        //mut acc: Stump,
    ) -> Result<(), crate::error::Error> {
        println!("==> Catching up to block {}", range.end());
        for block_height in range {
            let block = BlockchainSync::get_block(rpc, block_height)?;
            //acc = BlockchainSync::update_acc(acc, &block, block_height, Proof::default());

            if block_height % 1000 == 0 {
                println!("Sync at block {block_height}: {}", block.block_hash());
            }
            address_cache.block_process(&block, block_height);
        }
        Ok(())
    }
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

        let mut ser_leaf_data = vec![];
        ser_leaf_data.write(&block_hash).unwrap();
        ser_leaf_data.write(&transaction.txid()).unwrap();
        ser_leaf_data.write(&vout.to_le_bytes()).unwrap();
        ser_leaf_data.write(&header_code.to_le_bytes()).unwrap();
        ser_leaf_data.write(&ser_utxo).unwrap();

        let leaf_hash = Sha512_256::new().chain_update(ser_leaf_data).finalize();
        sha256::Hash::from_slice(leaf_hash.as_slice())
            .expect("parent_hash: Engines shouldn't be Err")
    }
    pub fn update_acc(acc: Stump, block: &Block, height: u32, proof: Proof) -> Stump {
        let block_hash = block.block_hash();
        let mut leaf_hashes = vec![];
        for transaction in block.txdata.iter() {
            for (i, _) in transaction.output.iter().enumerate() {
                leaf_hashes.push(BlockchainSync::get_leaf_hashes(
                    transaction,
                    i as u32,
                    height,
                    block_hash,
                ))
            }
        }
        let acc = acc.modify(&leaf_hashes, &vec![], &proof).unwrap();
        acc
    }
    pub fn sync_single<T: BtcdRpc, D: AddressCacheDatabase>(
        rpc: T,
        address_cache: &mut AddressCache<D>,
        blocks: u32,
    ) {
        for block_height in 0..blocks {
            let block = BlockchainSync::get_block(&rpc, block_height).unwrap();

            if block_height % 1000 == 0 {
                println!("Sync at block {block_height}: {}", block.block_hash());
            }
            address_cache.block_process(&block, block_height);
        }
    }
}
