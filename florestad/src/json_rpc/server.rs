use async_std::sync::RwLock;
use bitcoin::{
    consensus::{deserialize, serialize},
    hashes::{
        hex::{FromHex, ToHex},
        Hash,
    },
    Address, BlockHash, BlockHeader, Network, Script, TxIn, TxOut, Txid,
};
use floresta_chain::{
    pruned_utreexo::{BlockchainInterface, UpdatableChainstate},
    ChainState, KvChainStore,
};
use floresta_watch_only::{kv_database::KvDatabase, AddressCache, CachedTransaction};
use floresta_wire::node_interface::{NodeInterface, NodeMethods, PeerInfo};
use futures::executor::block_on;
use jsonrpc_core::Result;
use jsonrpc_derive::rpc;
use jsonrpc_http_server::ServerBuilder;
use serde_json::{json, Value};
use std::sync::Arc;

use super::res::{
    BlockJson, Error, GetBlockchainInfoRes, RawTxJson, ScriptPubKeyJson, ScriptSigJson, TxInJson,
    TxOutJson,
};

#[rpc]
pub trait Rpc {
    #[rpc(name = "getblockchaininfo")]
    fn get_blockchain_info(&self) -> Result<GetBlockchainInfoRes>;
    #[rpc(name = "getblockhash")]
    fn get_block_hash(&self, height: u32) -> Result<BlockHash>;
    #[rpc(name = "getblockheader")]
    fn get_block_header(&self, hash: BlockHash) -> Result<BlockHeader>;
    #[rpc(name = "gettransaction")]
    fn get_transaction(&self, tx_id: Txid, verbosity: Option<bool>) -> Result<Value>;
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
    #[rpc(name = "addnode")]
    fn add_node(&self, node: String) -> Result<bool>;
}

pub struct RpcImpl {
    network: Network,
    chain: Arc<ChainState<KvChainStore>>,
    wallet: Arc<RwLock<AddressCache<KvDatabase>>>,
    node: Arc<NodeInterface>,
    kill_signal: Arc<RwLock<bool>>,
}
impl Rpc for RpcImpl {
    fn get_height(&self) -> Result<u32> {
        Ok(self.chain.get_best_block().unwrap().0)
    }

    fn add_node(&self, node: String) -> Result<bool> {
        let node = node.split(':').collect::<Vec<&str>>();
        let (ip, port) = if node.len() == 2 {
            (node[0], node[1].parse().map_err(|_| Error::InvalidPort)?)
        } else {
            match self.network {
                Network::Bitcoin => (node[0], 8333),
                Network::Testnet => (node[0], 18333),
                Network::Regtest => (node[0], 18444),
                Network::Signet => (node[0], 38333),
            }
        };
        let node = ip.parse().map_err(|_| Error::InvalidAddress)?;
        self.node.connect(node, port).unwrap();
        Ok(true)
    }

    fn get_blockchain_info(&self) -> Result<GetBlockchainInfoRes> {
        let (height, hash) = self.chain.get_best_block().unwrap();
        let validated = self.chain.get_validation_index().unwrap();
        let ibd = self.chain.is_in_idb();
        let latest_header = self.chain.get_block_header(&hash).unwrap();
        let latest_work = latest_header.work();
        let latest_block_time = latest_header.time;
        let leaf_count = self.chain.acc().leaves as u32;
        let root_count = self.chain.acc().roots.len() as u32;
        let root_hashes = self
            .chain
            .acc()
            .roots
            .into_iter()
            .map(|r| r.to_string())
            .collect();
        let validated_blocks = self.chain.get_validation_index().unwrap();
        Ok(GetBlockchainInfoRes {
            best_block: hash.to_string(),
            height,
            ibd,
            validated,
            latest_work: latest_work.to_string(),
            latest_block_time,
            leaf_count,
            root_count,
            root_hashes,
            chain: self.network.to_string(),
            difficulty: latest_header.difficulty(self.network),
            progress: validated_blocks as f32 / height as f32,
        })
    }

    fn get_roots(&self) -> Result<Vec<String>> {
        let hashes = self.chain.get_root_hashes();
        return Ok(hashes.iter().map(|h| h.to_string()).collect());
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

    fn get_transaction(&self, tx_id: Txid, verbosity: Option<bool>) -> Result<Value> {
        let wallet = block_on(self.wallet.read());
        if verbosity == Some(true) {
            if let Some(tx) = wallet.get_transaction(&tx_id) {
                return Ok(serde_json::to_value(serialize(&tx.tx)).unwrap());
            }
            return Err(Error::TxNotFound.into());
        }
        if let Some(tx) = wallet.get_transaction(&tx_id) {
            return Ok(serde_json::to_value(self.make_raw_transaction(tx)).unwrap());
        }
        Err(Error::TxNotFound.into())
    }

    fn load_descriptor(&self, descriptor: String, rescan: Option<u32>) -> Result<()> {
        let wallet = block_on(self.wallet.write());
        let result = wallet.push_descriptor(&descriptor);
        if let Some(rescan) = rescan {
            self.chain
                .rescan(rescan)
                .map_err(|_| jsonrpc_core::Error::internal_error())?;
        }
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
                let tip = self.chain.get_height().map_err(|_| Error::ChainError)?;
                let height = self
                    .chain
                    .get_block_height(&hash)
                    .map_err(|_| Error::ChainError)?
                    .unwrap();
                let mut last_block_times: Vec<_> = ((height - 11)..height)
                    .into_iter()
                    .map(|h| {
                        self.chain
                            .get_block_header(&self.chain.get_block_hash(h).unwrap())
                            .unwrap()
                            .time
                    })
                    .collect();
                last_block_times.sort();

                let median_time_past = last_block_times[5];

                let block = BlockJson {
                    bits: block.header.bits.to_hex(),
                    chainwork: block.header.work().to_string(),
                    confirmations: (tip - height) + 1,
                    difficulty: block.header.difficulty(self.network),
                    hash: block.header.block_hash().to_string(),
                    height: height,
                    merkleroot: block.header.merkle_root.to_string(),
                    nonce: block.header.nonce,
                    previousblockhash: block.header.prev_blockhash.to_string(),
                    size: block.size(),
                    time: block.header.time,
                    tx: block
                        .txdata
                        .iter()
                        .map(|tx| tx.txid().to_string())
                        .collect(),
                    version: block.header.version,
                    version_hex: format!("{:x}", block.header.version),
                    weight: block.weight(),
                    mediantime: median_time_past,
                    n_tx: block.txdata.len(),
                    nextblockhash: self
                        .chain
                        .get_block_hash(height + 1)
                        .ok()
                        .map(|h| h.to_string()),
                    strippedsize: block.strippedsize(),
                };

                return Ok(serde_json::to_value(block).unwrap());
            }
            return Ok(json!(serialize(&block).to_hex()));
        }
        Err(Error::BlockNotFound.into())
    }

    fn find_tx_out(&self, block_height: u32, tx_id: Txid, outpoint: usize) -> Result<TxOut> {
        let block_hash = self
            .chain
            .get_block_hash(block_height)
            .map_err(|_| Error::ChainError)?;
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
    fn make_vin(&self, input: TxIn) -> TxInJson {
        let txid = input.previous_output.txid.to_hex();
        let vout = input.previous_output.vout;
        let sequence = input.sequence.0;
        TxInJson {
            txid,
            vout,
            script_sig: ScriptSigJson {
                asm: input.script_sig.asm(),
                hex: input.script_sig.to_hex(),
            },
            witness: input.witness.iter().map(|w| w.to_hex()).collect(),
            sequence,
        }
    }
    fn get_script_type(script: Script) -> Option<&'static str> {
        if script.is_p2pkh() {
            return Some("p2pkh");
        }
        if script.is_p2sh() {
            return Some("p2sh");
        }
        if script.is_v0_p2wpkh() {
            return Some("v0_p2wpkh");
        }
        if script.is_v0_p2wsh() {
            return Some("v0_p2wsh");
        }
        None
    }
    fn make_vout(&self, output: TxOut, n: u32) -> TxOutJson {
        let value = output.value;
        TxOutJson {
            value,
            n,
            script_pub_key: ScriptPubKeyJson {
                asm: output.script_pubkey.asm(),
                hex: output.script_pubkey.to_hex(),
                req_sigs: 0, // This field is deprecated
                address: Address::from_script(&output.script_pubkey, self.network)
                    .map(|a| a.to_string())
                    .unwrap(),
                type_: Self::get_script_type(output.script_pubkey)
                    .or(Some("nonstandard"))
                    .unwrap()
                    .to_string(),
            },
        }
    }
    fn make_raw_transaction(&self, tx: CachedTransaction) -> RawTxJson {
        let raw_tx = tx.tx;
        let in_active_chain = tx.height != 0;
        let hex = serialize(&raw_tx).to_hex();
        let txid = raw_tx.txid().to_hex();
        let block_hash = self
            .chain
            .get_block_hash(tx.height)
            .unwrap_or(BlockHash::all_zeros());
        let tip = self.chain.get_height().unwrap();
        let confirmations = if in_active_chain {
            tip - tx.height + 1
        } else {
            0
        };

        RawTxJson {
            in_active_chain,
            hex,
            txid,
            hash: raw_tx.wtxid().to_hex(),
            size: raw_tx.size() as u32,
            vsize: raw_tx.vsize() as u32,
            weight: raw_tx.weight() as u32,
            version: raw_tx.version as u32,
            locktime: raw_tx.lock_time.0,
            vin: raw_tx
                .input
                .iter()
                .map(|input| self.make_vin(input.clone()))
                .collect(),
            vout: raw_tx
                .output
                .into_iter()
                .enumerate()
                .map(|(i, output)| self.make_vout(output, i as u32))
                .collect(),
            blockhash: block_hash.to_hex(),
            confirmations,
            blocktime: self
                .chain
                .get_block_header(&block_hash)
                .map(|h| h.time)
                .unwrap_or(0),
            time: self
                .chain
                .get_block_header(&block_hash)
                .map(|h| h.time)
                .unwrap_or(0),
        }
    }
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
        network: Network,
    ) -> jsonrpc_http_server::Server {
        let mut io = jsonrpc_core::IoHandler::new();
        let rpc_impl = RpcImpl {
            network,
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
