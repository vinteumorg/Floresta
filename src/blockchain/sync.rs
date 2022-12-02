use std::ops::RangeInclusive;
use std::vec;

use crate::address_cache::{AddressCache, AddressCacheDatabase};
use crate::error::Error;
use bitcoin::consensus::{deserialize, Encodable};
use bitcoin::hashes::hex::{FromHex, ToHex};
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
    pub fn _sync_all<D: AddressCacheDatabase, Rpc: BtcdRpc>(
        rpc: &Rpc,
        address_cache: &mut AddressCache<D>,
    ) -> Result<(), crate::error::Error> {
        let height = rpc.getbestblock().expect("sync_all: Rpc failed").height as u32;
        Self::sync_range(rpc, address_cache, 1..=height)?;
        Ok(())
    }

    pub fn sync_range<T: BtcdRpc, D: AddressCacheDatabase>(
        rpc: &T,
        address_cache: &mut AddressCache<D>,
        range: RangeInclusive<u32>,
    ) -> Result<(), crate::error::Error> {
        println!("==> Catching up to block {}", range.end());
        for block_height in range {
            let block = BlockchainSync::get_block(rpc, block_height)?;
            let (proof, del_hashes) = Self::get_proof(rpc, &block.block_hash().to_string())
                .expect("Could not get block proof");
            if block_height % 1000 == 0 {
                println!("Sync at block {block_height}: {}", block.block_hash());
            }
            address_cache.block_process(&block, block_height, proof, del_hashes);
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
        let res = proof.verify(&del_hashes, acc);
        assert_eq!(
            res,
            Ok(true),
            "Block: {height} {:?} \n Hashes: {:?}",
            acc,
            proof
        );
        for transaction in block.txdata.iter() {
            for (i, output) in transaction.output.iter().enumerate() {
                if !output.script_pubkey.is_provably_unspendable() {
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
    ) -> Result<(Proof, Vec<sha256::Hash>), crate::error::Error> {
        let proof = rpc.getutreexoproof(hash.to_string(), true)?.get_verbose();
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
        Ok((proof, targethashes))
    }
    pub fn _sync_single<T: BtcdRpc, D: AddressCacheDatabase>(
        rpc: &T,
        address_cache: &mut AddressCache<D>,
        blocks: u32,
    ) {
        for block_height in 0..blocks {
            let block = BlockchainSync::get_block(rpc, block_height).unwrap();
            let (proof, del_hashes) = Self::get_proof(rpc, &block.block_hash().to_string())
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
#[test]
fn test() {
    let roots = vec![
        "340fb65799279ca2329323eff0cfe5e0295e82c0794783890fb738da1bd21f30",
        "8d7d381820c107b3a0b0ae4d78040ca64f75bc029b26cead9c6980f334034ffc",
        "ba0144238ab56e717931b99ae385eb8c9a40104328a39a8002abf269265198f1",
        "fe3bb5ce3786eea7ceabc8c47055a6899c039284536f7d24c39134b9ef39f874",
    ];
    let roots = roots
        .into_iter()
        .map(|h| sha256::Hash::from_hex(h).unwrap())
        .collect::<Vec<sha256::Hash>>();
    let stump = Stump { leafs: 102, roots };
    let hashes = vec![
        "12994ae7e11accaf39ed08aa1e92e8d9994acce2c9ff69ff5fd1672c77173e50",
        "1e1c3ad5c2f4f1110107565f5ef3bff75676efba896d747c22514d27cad11ad3",
        "187d7c1a5a504f3e4389c776941061df01a8b8c567b01e49b818287702370d09",
        "2af0cffdb07b40bdb845e67259752e663156ad328585268abf62845c8c69b106",
        "ab93cac29e663a31a78abbd00e77d9bb9235350aa48d43d42cca4b663212c22b",
        "c8fa9a172229fcd21d1aaa437451575bf9f2077a4036af7acc4145f4b02e93c5",
    ];
    let hashes = hashes
        .into_iter()
        .map(|h| sha256::Hash::from_hex(h).unwrap())
        .collect::<Vec<sha256::Hash>>();

    let proof = Proof::new(vec![0], hashes);

    let del_hash = vec!["788e30eb9b7e80dcf76eba077489982563dfcf37ed83f47c2d864fb312fbcc4d"];
    let del_hash = del_hash
        .into_iter()
        .map(|h| sha256::Hash::from_hex(h).unwrap())
        .collect::<Vec<sha256::Hash>>();
}
