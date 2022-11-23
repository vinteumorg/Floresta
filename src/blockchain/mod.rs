use std::{collections::HashSet, sync::Arc};
mod sync;

use bdk::{
    bitcoin::{
        consensus::{Decodable, Encodable},
        hashes::hex::{FromHex, ToHex},
        BlockHash, Script, Transaction,
    },
    blockchain::{Blockchain, Capability, GetBlockHash, GetHeight, GetTx, WalletSync},
    database::SyncTime,
    wallet::time::get_timestamp,
    BlockTime, KeychainKind,
};
use btcd_rpc::{
    client::{BTCDClient, BtcdRpc},
    json_types::{transaction::BestBlock, VerbosityOutput},
};
use rustreexo::accumulator::stump::Stump;

use self::sync::BlockchainSync;
pub struct UtreexodBackend {
    pub rpc: Arc<BTCDClient>,
    pub accumulator: Stump,
}

impl GetBlockHash for UtreexodBackend {
    fn get_block_hash(&self, height: u64) -> Result<bdk::bitcoin::BlockHash, bdk::Error> {
        Ok(BlockHash::from_hex(
            self.rpc
                .getblockhash(height as usize)
                .map_err(|_| bdk::Error::Generic("Error".into()))?
                .as_str(),
        )?)
    }
}
impl GetTx for UtreexodBackend {
    fn get_tx(
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
}
impl GetHeight for UtreexodBackend {
    fn get_height(&self) -> Result<u32, bdk::Error> {
        Ok(self.rpc.getbestblock().unwrap().height as u32)
    }
}
impl WalletSync for UtreexodBackend {
    fn wallet_setup<D: bdk::database::BatchDatabase>(
        &self,
        database: &mut D,
        progress_update: Box<dyn bdk::blockchain::Progress>,
    ) -> Result<(), bdk::Error> {
        self.wallet_sync(database, progress_update)
    }
    fn wallet_sync<D: bdk::database::BatchDatabase>(
        &self,
        database: &mut D,
        _progress_update: Box<dyn bdk::blockchain::Progress>,
    ) -> Result<(), bdk::Error> {
        let current_height = self.get_height()?;

        let pk_hash_set: HashSet<Script> = database
            .iter_script_pubkeys(Some(KeychainKind::External))?
            .into_iter()
            .collect();

        let sync_height = database
            .get_sync_time()
            .unwrap_or_default()
            .unwrap_or(SyncTime {
                block_time: BlockTime {
                    height: 0,
                    timestamp: 0,
                },
            })
            .block_time
            .height;
        let my_utxos = BlockchainSync::sync_range(
            self.rpc.clone(),
            sync_height..current_height,
            pk_hash_set,
            self.accumulator.clone(),
        );
        database.set_sync_time(SyncTime {
            block_time: BlockTime {
                height: current_height,
                timestamp: get_timestamp(),
            },
        })?;
        for (utxo, transaction) in my_utxos {
            database.set_utxo(&utxo)?;
            database.set_tx(&transaction)?;
        }
        Ok(())
    }
}
impl Blockchain for UtreexodBackend {
    fn get_capabilities(&self) -> std::collections::HashSet<bdk::blockchain::Capability> {
        let mut capabilities = HashSet::new();
        capabilities.insert(Capability::FullHistory);
        capabilities
    }

    fn broadcast(&self, tx: &bdk::bitcoin::Transaction) -> Result<(), bdk::Error> {
        let mut writer = Vec::new();
        let _ = tx
            .consensus_encode(&mut writer)
            .expect("Should be a valid transaction");

        self.rpc
            .sendrawtransaction(writer.to_hex())
            .map_err(|_| bdk::Error::Generic("UtreexodError".into()))
    }

    fn estimate_fee(&self, target: usize) -> Result<bdk::FeeRate, bdk::Error> {
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
