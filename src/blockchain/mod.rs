use std::sync::Arc;
pub mod chainstore;
pub mod sync;
pub mod udata;

use bitcoin::{
    consensus::{Decodable, Encodable},
    hashes::hex::{FromHex, ToHex},
    Block, BlockHash, Transaction,
};
use btcd_rpc::{
    client::{BTCDClient, BtcdRpc},
    json_types::{transaction::BestBlock, VerbosityOutput},
};
use rustreexo::accumulator::stump::Stump;

use crate::error::Error;
/// This trait is the main interface between our blockchain backend and other services.
/// It'll be useful for transitioning from rpc to a p2p based node
pub trait Blockchain {
    /// Returns the block with a given height in our current tip.
    fn get_block_hash(&self, height: u64) -> Result<bitcoin::BlockHash, Error>;
    /// Returns a bitcoin [Transaction] given it's txid.
    fn get_tx(&self, txid: &bitcoin::Txid) -> Result<Option<bitcoin::Transaction>, Error>;
    /// Get the height of our best know chain.
    fn get_height(&self) -> Result<u32, Error>;
    /// Broadcasts a transaction to the network.
    fn broadcast(&self, tx: &bitcoin::Transaction) -> Result<(), Error>;
    /// Returns fee estimation for inclusion in `target` blocks.
    fn estimate_fee(&self, target: usize) -> Result<f64, Error>;
    /// Returns a block with a given `hash` if any.
    fn get_block(&self, hash: &BlockHash) -> Result<Block, Error>;
}

pub struct UtreexodBackend {
    pub rpc: Arc<BTCDClient>,
    pub accumulator: Stump,
}
impl Blockchain for UtreexodBackend {
    fn get_block_hash(&self, height: u64) -> Result<bitcoin::BlockHash, Error> {
        Ok(BlockHash::from_hex(
            self.rpc.getblockhash(height as usize)?.as_str(),
        )?)
    }
    fn get_tx(&self, txid: &bitcoin::Txid) -> Result<Option<bitcoin::Transaction>, Error> {
        let tx = self.rpc.getrawtransaction(txid.to_hex(), false).unwrap();
        if let VerbosityOutput::Simple(hex) = tx {
            let tx = Transaction::consensus_decode(&mut hex.as_bytes())?;
            return Ok(Some(tx));
        }
        Err(Error::TxNotFound)
    }
    fn get_height(&self) -> Result<u32, Error> {
        if let Ok(block) = self.rpc.getbestblock() {
            Ok(block.height as u32)
        } else {
            Ok(0)
        }
    }

    fn broadcast(&self, tx: &bitcoin::Transaction) -> Result<(), Error> {
        let mut writer = Vec::new();
        let _ = tx
            .consensus_encode(&mut writer)
            .expect("Should be a valid transaction");

        self.rpc.sendrawtransaction(writer.to_hex())?;
        Ok(())
    }

    fn estimate_fee(&self, target: usize) -> Result<f64, Error> {
        let feerate = self.rpc.estimatefee(target as u32)?;
        Ok(feerate)
    }

    fn get_block(&self, _hash: &BlockHash) -> Result<Block, Error> {
        todo!()
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
