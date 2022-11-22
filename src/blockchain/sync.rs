use std::collections::HashSet;
use std::io::Write;
use std::ops::Range;
use std::sync::Arc;
use std::vec;

use bdk::bitcoin::consensus::{deserialize, Encodable};
use bdk::bitcoin::hashes::hex::FromHex;
use bdk::bitcoin::hashes::{sha256, Hash};
use bdk::bitcoin::{Block, BlockHash, OutPoint};
use bdk::bitcoin::{Script, Transaction};
use bdk::{BlockTime, KeychainKind, LocalUtxo, TransactionDetails};
use btcd_rpc::client::BtcdRpc;
use btcd_rpc::json_types::transaction::VerbosityOutput;
use rustreexo::accumulator::proof::Proof;
use rustreexo::accumulator::stump::Stump;
use sha2::{Digest, Sha512_256};

#[derive(Debug, Default)]
pub struct BlockchainSync;

impl BlockchainSync {
    pub fn get_block<T: BtcdRpc>(
        rpc: &T,
        height: u32,
    ) -> Result<Block, Box<dyn std::error::Error>> {
        let hash = rpc
            .getblockhash(height as usize)
            .map_err(|_| bdk::Error::Generic("RPC Error".into()))?;

        let block = rpc
            .getblock(hash, false)
            .map_err(|_| bdk::Error::Generic("RPC Error".into()))?;
        if let VerbosityOutput::Simple(hex) = block {
            let block = Vec::from_hex(hex.as_str())?;
            let block = deserialize(&block)?;
            return Ok(block);
        }
        Err("Block not found".into())
    }
    pub fn filter_block<'a>(
        block: &'a Block,
        spks: &HashSet<Script>,
        height: u32,
    ) -> Vec<(LocalUtxo, TransactionDetails)> {
        let mut my_utxos = vec![];
        for transaction in block.txdata.iter() {
            for (outpoint, vout) in transaction.output.iter().enumerate() {
                if spks.contains(&vout.script_pubkey) {
                    let outpoint = OutPoint {
                        txid: transaction.txid(),
                        vout: outpoint as u32,
                    };

                    let utxo = LocalUtxo {
                        is_spent: false,
                        keychain: KeychainKind::External,
                        outpoint,
                        txout: vout.clone(),
                    };
                    let transaction = TransactionDetails {
                        confirmation_time: Some(BlockTime {
                            height,
                            timestamp: block.header.time as u64,
                        }),
                        transaction: Some(transaction.clone()),
                        txid: transaction.txid(),
                        received: utxo.txout.value,
                        sent: 0,
                        fee: None,
                    };
                    my_utxos.push((utxo, transaction.clone()));
                    break;
                }
            }
        }

        my_utxos
    }
    pub fn sync_range<T: BtcdRpc>(
        rpc: Arc<T>,
        range: Range<u32>,
        pk_hash_set: HashSet<Script>,
        mut acc: Stump,
    ) -> Vec<(LocalUtxo, TransactionDetails)> {
        let mut transactions = vec![];
        println!("==> Catching up to block {}", range.end);
        for block_height in range {
            let block = BlockchainSync::get_block(&*rpc, block_height).unwrap();
            acc = BlockchainSync::update_acc(acc, &block, block_height, Proof::default());

            if block_height % 1000 == 0 {
                println!("Sync at block {block_height}: {}", block.block_hash());
            }
            let my_outs = BlockchainSync::filter_block(&block, &pk_hash_set, block_height);
            transactions.extend(my_outs);
        }
        println!("{:?}", acc);

        transactions
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
    pub fn _sync_single<T: BtcdRpc>(
        rpc: Arc<T>,
        blocks: u32,
        pk_hash_set: HashSet<Script>,
        acc: Stump,
    ) -> Vec<(LocalUtxo, TransactionDetails)> {
        let mut transactions = vec![];
        for block_height in 0..blocks {
            let block = BlockchainSync::get_block(&*rpc, block_height).unwrap();

            if block_height % 1000 == 0 {
                println!("Sync at block {block_height}: {}", block.block_hash());
            }
            let my_outs = BlockchainSync::filter_block(&block, &pk_hash_set, block_height);
            transactions.extend(my_outs);
        }
        println!("{:?}", acc);
        transactions
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use bdk::bitcoin::{consensus::deserialize, hashes::hex::FromHex, BlockHash};
    use btcd_rpc::{
        client::{BTCDClient, BTCDConfigs, BtcdRpc},
        json_types::transaction::VerbosityOutput,
    };

    #[test]
    fn test() {
        use super::BlockchainSync;
        let config = BTCDConfigs::new(
            false,
            Some("SomeUsername".into()),
            Some("CorrectHorseBattleStaple".into()),
            Some("localhost".into()),
            Some(38332),
        );
        let rpc = BTCDClient::new(config).unwrap();
        let tx = rpc
            .getrawtransaction(
                "e3b2dc0ffd26cb87e9207d1333ed7d192d63c8d6a7d23090f1134d1424ea3b4d".into(),
                false,
            )
            .unwrap();
        if let VerbosityOutput::Simple(tx) = tx {
            let tx = Vec::from_hex(tx.as_str()).unwrap();
            let tx = deserialize(&tx).unwrap();
            let hash = BlockchainSync::get_leaf_hashes(
                &tx,
                0,
                49007,
                BlockHash::from_str(
                    "000000e2e71a8a731f8ad9171d5d3f6346924aaa25311ac0df30ecc0c13770bf",
                )
                .unwrap(),
            );
            println!("{:?}", hash)
        }
    }
}
