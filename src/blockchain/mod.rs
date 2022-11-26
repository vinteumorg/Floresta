use std::sync::Arc;
pub mod sync;

use bdk::bitcoin::{
    consensus::{Decodable, Encodable},
    hashes::hex::{FromHex, ToHex},
    BlockHash, Transaction,
};
use btcd_rpc::{
    client::{BTCDClient, BtcdRpc},
    json_types::{transaction::BestBlock, VerbosityOutput},
};
use rustreexo::accumulator::stump::Stump;

pub struct UtreexodBackend {
    pub rpc: Arc<BTCDClient>,
    pub accumulator: Stump,
}
#[allow(unused)]
impl UtreexodBackend {
    pub fn get_block_hash(&self, height: u64) -> Result<bdk::bitcoin::BlockHash, bdk::Error> {
        Ok(BlockHash::from_hex(
            self.rpc
                .getblockhash(height as usize)
                .map_err(|_| bdk::Error::Generic("Error".into()))?
                .as_str(),
        )?)
    }
    pub fn get_tx(
        &self,
        txid: &bdk::bitcoin::Txid,
    ) -> Result<Option<bdk::bitcoin::Transaction>, bdk::Error> {
        let tx = self.rpc.getrawtransaction(txid.to_hex(), false).unwrap();
        if let VerbosityOutput::Simple(hex) = tx {
            let tx = Transaction::consensus_decode(&mut hex.as_bytes())?;
            return Ok(Some(tx));
        }
        Err(bdk::Error::TransactionNotFound)
    }
    pub fn get_height(&self) -> Result<u32, bdk::Error> {
        if let Ok(block) = self.rpc.getbestblock() {
            Ok(block.height as u32)
        } else {
            Ok(0)
        }
    }

    pub fn broadcast(&self, tx: &bdk::bitcoin::Transaction) -> Result<(), bdk::Error> {
        let mut writer = Vec::new();
        let _ = tx
            .consensus_encode(&mut writer)
            .expect("Should be a valid transaction");

        self.rpc
            .sendrawtransaction(writer.to_hex())
            .map_err(|_| bdk::Error::Generic("UtreexodError".into()))
    }

    pub fn estimate_fee(&self, target: usize) -> Result<bdk::FeeRate, bdk::Error> {
        let feerate = self
            .rpc
            .estimatefee(target as u32)
            .map_err(|_| bdk::Error::Generic("UtreexodError".into()))?;

        Ok(bdk::FeeRate::from_btc_per_kvb(feerate as f32))
    }
}

pub struct ChainWatch;

impl ChainWatch {
    pub fn get_block(rpc: &Arc<BTCDClient>) -> u64 {
        rpc.getbestblock()
            .unwrap_or(BestBlock {
                height: 0,
                hash: "".into(),
            })
            .height
    }
}
