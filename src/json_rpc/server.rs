use crate::blockchain::{
    error::BlockchainError,
    p2p_blockchain::node_interface::{NodeInterface, NodeMethods, PeerInfo},
    BlockchainProviderInterface,
};
use async_std::sync::RwLock;
use bitcoin::{
    consensus::{deserialize, serialize},
    hashes::hex::{FromHex, ToHex},
    BlockHash, BlockHeader, Network, Transaction, TxOut, Txid,
};
use futures::executor::block_on;
use jsonrpc_core::Result;
use jsonrpc_derive::rpc;
use jsonrpc_http_server::ServerBuilder;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::{
    address_cache::{kv_database::KvDatabase, AddressCache},
    blockchain::{chain_state::ChainState, chainstore::KvChainStore, BlockchainInterface},
};

use super::res::{Error, GetBlockchainInfoRes};

#[rpc]
pub trait Rpc {
    #[rpc(name = "getblockchaininfo")]
    fn get_blockchain_info(&self) -> Result<GetBlockchainInfoRes>;
    #[rpc(name = "getblockhash")]
    fn get_block_hash(&self, height: u32) -> Result<BlockHash>;
    #[rpc(name = "getblockheader")]
    fn get_block_header(&self, hash: BlockHash) -> Result<BlockHeader>;
    #[rpc(name = "gettransaction")]
    fn get_transaction(&self, tx_id: Txid) -> Result<Transaction>;
    #[rpc(name = "gettxproof")]
    fn get_tx_proof(&self, tx_id: Txid) -> Result<Vec<String>>;
    #[rpc(name = "gettxout")]
    fn get_tx_out(&self, tx_id: Txid, outpoint: usize) -> Result<TxOut>;
    #[rpc(name = "loaddescriptor")]
    fn load_descriptor(&self, descriptor: String, rescan: Option<u32>) -> Result<()>;
    #[rpc(name = "rescan")]
    fn rescan(&self, rescan: u32) -> Result<bool>;
    #[rpc(name = "getheight")]
    fn get_height(&self) -> Result<u32>;
    #[rpc(name = "sendrawtransaction")]
    fn send_raw_transaction(&self, tx: String) -> Result<Txid>;
    #[rpc(name = "getroots")]
    fn get_roots(&self) -> Result<Vec<String>>;
    #[rpc(name = "getpeerinfo")]
    fn get_peer_info(&self) -> Result<Vec<PeerInfo>>;
    #[rpc(name = "getblock")]
    fn get_block(&self, hash: BlockHash, verbosity: Option<u8>) -> Result<Value>;
    #[rpc(name = "findtxout")]
    fn find_tx_out(&self, block_height: u32, tx_id: Txid, outpoint: usize) -> Result<TxOut>;
    #[rpc(name = "stop")]
    fn stop(&self) -> Result<bool>;
}

pub struct RpcImpl {
    chain: Arc<ChainState<KvChainStore>>,
    wallet: Arc<RwLock<AddressCache<KvDatabase>>>,
    node: Arc<NodeInterface>,
    kill_signal: Arc<RwLock<bool>>,
}
impl Rpc for RpcImpl {
    fn get_height(&self) -> Result<u32> {
        Ok(self.chain.get_best_block().unwrap().0)
    }

    fn get_blockchain_info(&self) -> Result<GetBlockchainInfoRes> {
        let (height, hash) = self.chain.get_best_block().unwrap();
        let validated = self.chain.get_validation_index().unwrap();
        let ibd = self.chain.is_in_idb();
        Ok(GetBlockchainInfoRes {
            best_block: hash.to_string(),
            height,
            ibd,
            validated,
        })
    }

    fn get_roots(&self) -> Result<Vec<String>> {
        let ret = self.chain.get_root_hashes();
        if let Ok(hashes) = ret {
            return Ok(hashes.iter().map(|h| h.to_string()).collect());
        }
        Err(Error::ChainError.into())
    }

    fn get_block_hash(&self, height: u32) -> Result<BlockHash> {
        if let Ok(hash) = self.chain.get_block_hash(height) {
            return Ok(hash);
        }
        Err(Error::BlockNotFound.into())
    }

    fn get_block_header(&self, hash: BlockHash) -> Result<BlockHeader> {
        if let Ok(header) = self.chain.get_block_header(&hash) {
            return Ok(header);
        }
        Err(Error::BlockNotFound.into())
    }

    fn get_transaction(&self, tx_id: Txid) -> Result<Transaction> {
        let wallet = block_on(self.wallet.read());
        if let Some(tx) = wallet.get_transaction(&tx_id) {
            return Ok(tx.tx);
        }
        if let Ok(Some(tx)) = self.node.get_mempool_transaction(tx_id) {
            return Ok(tx);
        }
        Err(Error::TxNotFound.into())
    }

    fn load_descriptor(&self, descriptor: String, rescan: Option<u32>) -> Result<()> {
        let wallet = block_on(self.wallet.write());
        let result = wallet.push_descriptor(&descriptor).and_then(|_| {
            if let Some(rescan) = rescan {
                self.chain.rescan(rescan)?;
            }
            Ok(())
        });
        if result.is_err() {
            return Err(Error::InvalidDescriptor.into());
        }
        Ok(())
    }

    fn rescan(&self, rescan: u32) -> Result<bool> {
        let result = self.chain.rescan(rescan);
        if result.is_err() {
            return Err(Error::ChainError.into());
        }
        Ok(true)
    }

    fn send_raw_transaction(&self, tx: String) -> Result<Txid> {
        let tx_hex = Vec::from_hex(&tx).map_err(|_| jsonrpc_core::Error {
            code: 3.into(),
            message: "Invalid hex".into(),
            data: None,
        })?;
        let tx = deserialize(&tx_hex).map_err(|e| jsonrpc_core::Error {
            code: 2.into(),
            message: format!("{:?}", e),
            data: None,
        })?;
        if self.chain.broadcast(&tx).is_ok() {
            return Ok(tx.txid());
        }
        Err(Error::ChainError.into())
    }

    fn get_tx_out(&self, tx_id: Txid, outpoint: usize) -> Result<TxOut> {
        let tx = block_on(self.wallet.read()).get_transaction(&tx_id);
        if let Some(tx) = tx {
            return Ok(tx.tx.output[outpoint].clone());
        }
        Err(Error::TxNotFound.into())
    }

    fn get_tx_proof(&self, tx_id: Txid) -> Result<Vec<String>> {
        if let Some((proof, _)) = block_on(self.wallet.read()).get_merkle_proof(&tx_id) {
            return Ok(proof);
        }
        Err(Error::TxNotFound.into())
    }

    fn get_block(&self, hash: BlockHash, verbosity: Option<u8>) -> Result<Value> {
        let verbosity = verbosity.unwrap_or(1);
        if let Ok(Some(block)) = self.node.get_block(hash) {
            if verbosity == 1 {
                return Ok(serde_json::to_value(block).unwrap());
            }
            return Ok(json!(serialize(&block).to_hex()));
        }
        Err(Error::BlockNotFound.into())
    }

    fn find_tx_out(&self, block_height: u32, tx_id: Txid, outpoint: usize) -> Result<TxOut> {
        let block_hash = self.chain.get_block_hash(block_height)?;
        let block = self
            .node
            .get_block(block_hash)
            .map_err(|_| jsonrpc_core::Error {
                code: 5.into(),
                message: "Block not found".into(),
                data: None,
            })?;
        let tx = block.and_then(|block| block.txdata.iter().find(|tx| tx.txid() == tx_id).cloned());
        if let Some(tx) = tx {
            return Ok(tx.output[outpoint].clone());
        }
        Err(Error::TxNotFound.into())
    }

    fn get_peer_info(&self) -> Result<Vec<PeerInfo>> {
        let peers = self.node.get_peer_info();
        if let Ok(peers) = peers {
            return Ok(peers);
        }
        Err(Error::TxNotFound.into())
    }

    fn stop(&self) -> Result<bool> {
        *async_std::task::block_on(self.kill_signal.write()) = true;
        Ok(true)
    }
}
impl RpcImpl {
    fn get_port(net: &Network) -> u16 {
        match net {
            Network::Bitcoin => 8332,
            Network::Testnet => 18332,
            Network::Signet => 38332,
            Network::Regtest => 18442,
        }
    }
    pub fn create(
        chain: Arc<ChainState<KvChainStore>>,
        wallet: Arc<RwLock<AddressCache<KvDatabase>>>,
        net: &Network,
        node: Arc<NodeInterface>,
        kill_signal: Arc<RwLock<bool>>,
    ) -> jsonrpc_http_server::Server {
        let mut io = jsonrpc_core::IoHandler::new();
        let rpc_impl = RpcImpl {
            chain,
            wallet,
            node,
            kill_signal,
        };
        io.extend_with(rpc_impl.to_delegate());

        ServerBuilder::new(io)
            .threads(1)
            .start_http(
                &format!("127.0.0.1:{}", Self::get_port(net))
                    .parse()
                    .unwrap(),
            )
            .unwrap()
    }
}

impl From<BlockchainError> for jsonrpc_core::Error {
    fn from(e: BlockchainError) -> Self {
        jsonrpc_core::Error {
            code: 1.into(),
            message: format!("{:?}", e),
            data: None,
        }
    }
}
