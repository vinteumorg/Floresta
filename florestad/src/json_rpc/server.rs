use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::Method;
use axum::routing::post;
use axum::Json;
use axum::Router;
use bitcoin::block::Header as BlockHeader;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::consensus::serialize;
use bitcoin::constants::genesis_block;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::Address;
use bitcoin::BlockHash;
use bitcoin::Network;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Txid;
use floresta_chain::pruned_utreexo::BlockchainInterface;
use floresta_chain::pruned_utreexo::UpdatableChainstate;
use floresta_chain::ChainState;
use floresta_chain::KvChainStore;
use floresta_common::parse_descriptors;
use floresta_compact_filters::flat_filters_store::FlatFiltersStore;
use floresta_compact_filters::network_filters::NetworkFilters;
use floresta_watch_only::kv_database::KvDatabase;
use floresta_watch_only::AddressCache;
use floresta_watch_only::CachedTransaction;
use floresta_wire::node_interface::NodeInterface;
use floresta_wire::node_interface::NodeMethods;
use floresta_wire::node_interface::PeerInfo;
use log::debug;
use log::error;
use log::info;
use serde_json::json;
use serde_json::Value;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;

use super::res::BlockJson;
use super::res::Error;
use super::res::GetBlockchainInfoRes;
use super::res::RawTxJson;
use super::res::ScriptPubKeyJson;
use super::res::ScriptSigJson;
use super::res::TxInJson;
use super::res::TxOutJson;

pub struct RpcImpl {
    block_filter_storage: Option<Arc<NetworkFilters<FlatFiltersStore>>>,
    network: Network,
    chain: Arc<ChainState<KvChainStore<'static>>>,
    wallet: Arc<AddressCache<KvDatabase>>,
    node: Arc<NodeInterface>,
    kill_signal: Arc<RwLock<bool>>,
}

type Result<T> = std::result::Result<T, Error>;
impl RpcImpl {
    fn get_tx_out(&self, txid: Txid, outpoint: u32) -> Result<Value> {
        let utxo = self.wallet.get_utxo(&OutPoint {
            txid,
            vout: outpoint,
        });

        let res = match utxo {
            Some(utxo) => ::serde_json::to_value(utxo),
            None => Ok(json!({})),
        };

        res.map_err(|_e| Error::Encode)
    }

    fn find_tx_out(&self, txid: Txid, vout: u32, script: ScriptBuf, height: u32) -> Result<Value> {
        if let Some(txout) = self.wallet.get_utxo(&OutPoint { txid, vout }) {
            return Ok(serde_json::to_value(txout).unwrap());
        }

        if self.chain.is_in_idb() {
            return Err(Error::InInitialBlockDownload);
        }

        // can't proceed without block filters
        let Some(cfilters) = self.block_filter_storage.as_ref() else {
            return Err(Error::NoBlockFilters);
        };

        self.wallet.cache_address(script.clone());
        let filter_key = script.to_bytes();
        let candidates = cfilters.match_any(
            vec![filter_key.as_slice()],
            Some(height as usize),
            self.chain.clone(),
        );

        let candidates = candidates
            .unwrap_or_default()
            .into_iter()
            .map(|hash| self.node.get_block(hash));

        for candidate in candidates {
            let candidate = match candidate {
                Err(e) => {
                    return Err(Error::Node(e.to_string()));
                }
                Ok(None) => {
                    return Err(Error::Node(format!(
                        "BUG: block {candidate:?} is a match in our filters, but we can't get it?"
                    )));
                }
                Ok(Some(candidate)) => candidate,
            };

            let Ok(Some(height)) = self.chain.get_block_height(&candidate.block_hash()) else {
                return Err(Error::BlockNotFound);
            };

            self.wallet.block_process(&candidate, height);
        }

        self.get_tx_out(txid, vout)
    }

    fn get_height(&self) -> Result<u32> {
        Ok(self.chain.get_best_block().unwrap().0)
    }

    fn add_node(&self, node: String) -> Result<bool> {
        if self.chain.is_in_idb() {
            return Err(Error::InInitialBlockDownload);
        }

        let node = node.split(':').collect::<Vec<&str>>();
        let (ip, port) = if node.len() == 2 {
            (node[0], node[1].parse().map_err(|_| Error::InvalidPort)?)
        } else {
            match self.network {
                Network::Bitcoin => (node[0], 8333),
                Network::Testnet => (node[0], 18333),
                Network::Regtest => (node[0], 18444),
                Network::Signet => (node[0], 38333),
                _ => return Err(Error::InvalidNetwork),
            }
        };
        let node = ip.parse().map_err(|_| Error::InvalidAddress)?;
        self.node.connect(node, port).unwrap();
        Ok(true)
    }

    fn get_roots(&self) -> Result<Vec<String>> {
        let hashes = self.chain.get_root_hashes();
        Ok(hashes.iter().map(|h| h.to_string()).collect())
    }

    fn get_block_hash(&self, height: u32) -> Result<BlockHash> {
        self.chain
            .get_block_hash(height)
            .map_err(|_| Error::BlockNotFound)
    }

    fn get_block_header(&self, hash: BlockHash) -> Result<BlockHeader> {
        self.chain
            .get_block_header(&hash)
            .map_err(|_| Error::BlockNotFound)
    }

    fn get_transaction(&self, tx_id: Txid, verbosity: Option<bool>) -> Result<Value> {
        if verbosity == Some(true) {
            let tx = self.wallet.get_transaction(&tx_id).ok_or(Error::TxNotFound);
            return tx.map(|tx| serde_json::to_value(self.make_raw_transaction(tx)).unwrap());
        }

        self.wallet
            .get_transaction(&tx_id)
            .and_then(|tx| serde_json::to_value(self.make_raw_transaction(tx)).ok())
            .ok_or(Error::TxNotFound)
    }

    fn load_descriptor(&self, descriptor: String) -> Result<bool> {
        if self.chain.is_in_idb() {
            return Err(Error::InInitialBlockDownload);
        }

        let Ok(mut parsed) = parse_descriptors(&[descriptor.clone()]) else {
            return Err(Error::InvalidDescriptor);
        };

        // It's ok to unwrap because we know there is at least one element in the vector
        let addresses = parsed.pop().unwrap();
        let addresses = (0..100)
            .map(|index| {
                let address = addresses
                    .at_derivation_index(index)
                    .unwrap()
                    .script_pubkey();
                self.wallet.cache_address(address.clone());
                address
            })
            .collect::<Vec<_>>();

        debug!(
            "Rescanning with block filters for addresses: {:?}",
            addresses
        );

        let addresses = self.wallet.get_cached_addresses();
        let wallet = self.wallet.clone();
        if self.block_filter_storage.is_none() {
            return Err(Error::InInitialBlockDownload);
        };

        let cfilters = self.block_filter_storage.as_ref().unwrap().clone();
        let node = self.node.clone();
        let chain = self.chain.clone();
        std::thread::spawn(move || {
            match Self::rescan_with_block_filters(&addresses, chain, wallet, cfilters, node) {
                Ok(_) => info!("rescan completed"),
                Err(e) => error!("error while rescaning {e:?}"),
            }
        });

        Ok(true)
    }

    fn rescan(&self, _rescan: u32) -> Result<bool> {
        if self.chain.is_in_idb() {
            return Err(Error::InInitialBlockDownload);
        }

        let addresses = self.wallet.get_cached_addresses();
        let wallet = self.wallet.clone();
        if self.block_filter_storage.is_none() {
            return Err(Error::InInitialBlockDownload);
        };
        let cfilters = self.block_filter_storage.as_ref().unwrap().clone();
        let node = self.node.clone();
        let chain = self.chain.clone();
        std::thread::spawn(move || {
            match Self::rescan_with_block_filters(&addresses, chain, wallet, cfilters, node) {
                Ok(_) => info!("rescan completed"),
                Err(e) => error!("error while rescaning {e:?}"),
            }
        });
        Ok(true)
    }

    fn send_raw_transaction(&self, tx: String) -> Result<Txid> {
        let tx_hex = Vec::from_hex(&tx).map_err(|_| Error::InvalidHex)?;
        let tx = deserialize(&tx_hex).map_err(|e| Error::Decode(e.to_string()))?;
        self.chain.broadcast(&tx).map_err(|_| Error::Chain)?;

        Ok(tx.compute_txid())
    }

    fn get_tx_proof(&self, tx_id: Txid) -> Result<Vec<String>> {
        Ok(self
            .wallet
            .get_merkle_proof(&tx_id)
            .ok_or(Error::TxNotFound)?
            .0)
    }

    fn get_block(&self, hash: BlockHash, verbosity: Option<u8>) -> Result<Value> {
        let is_genesis = self.chain.get_block_hash(0).unwrap().eq(&hash);
        if self.chain.is_in_idb() && !is_genesis {
            return Err(Error::InInitialBlockDownload);
        }

        let verbosity = verbosity.unwrap_or(1);

        let block = if is_genesis {
            Some(genesis_block(self.network))
        } else {
            self.node.get_block(hash).map_err(|_| Error::Chain)?
        };

        if let Some(block) = block {
            if verbosity == 1 {
                let tip = self.chain.get_height().map_err(|_| Error::Chain)?;
                let height = self
                    .chain
                    .get_block_height(&hash)
                    .map_err(|_| Error::Chain)?
                    .unwrap();

                let median_time_past = if height > 11 {
                    let mut last_block_times: Vec<_> = ((height - 11)..height)
                        .map(|h| {
                            self.chain
                                .get_block_header(&self.chain.get_block_hash(h).unwrap())
                                .unwrap()
                                .time
                        })
                        .collect();
                    last_block_times.sort();
                    last_block_times[5]
                } else {
                    block.header.time
                };

                let block = BlockJson {
                    bits: serialize_hex(&block.header.bits),
                    chainwork: block.header.work().to_string(),
                    confirmations: (tip - height) + 1,
                    difficulty: block.header.difficulty(self.chain.get_params()),
                    hash: block.header.block_hash().to_string(),
                    height,
                    merkleroot: block.header.merkle_root.to_string(),
                    nonce: block.header.nonce,
                    previousblockhash: block.header.prev_blockhash.to_string(),
                    size: block.total_size(),
                    time: block.header.time,
                    tx: block
                        .txdata
                        .iter()
                        .map(|tx| tx.compute_txid().to_string())
                        .collect(),
                    version: block.header.version.to_consensus(),
                    version_hex: serialize_hex(&block.header.version),
                    weight: block.weight().to_wu() as usize,
                    mediantime: median_time_past,
                    n_tx: block.txdata.len(),
                    nextblockhash: self
                        .chain
                        .get_block_hash(height + 1)
                        .ok()
                        .map(|h| h.to_string()),
                    strippedsize: block.total_size(),
                };
                return Ok(serde_json::to_value(block).unwrap());
            }
            return Ok(json!(serialize(&block).to_vec()));
        }

        Err(Error::BlockNotFound)
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
            difficulty: latest_header.difficulty(self.chain.get_params()) as u64,
            progress: validated_blocks as f32 / height as f32,
        })
    }

    async fn get_peer_info(&self) -> Result<Vec<PeerInfo>> {
        if self.chain.is_in_idb() {
            return Err(Error::InInitialBlockDownload);
        }

        let node = self.node.clone();
        tokio::task::spawn_blocking(move || {
            node.get_peer_info()
                .map_err(|_| Error::Node("Failed to get peer info".to_string()))
        })
        .await
        .map_err(|e| Error::Node(e.to_string()))?
    }

    async fn stop(&self) -> Result<bool> {
        *self.kill_signal.write().await = true;
        Ok(true)
    }
}

async fn handle_json_rpc_request(req: Value, state: Arc<RpcImpl>) -> Result<serde_json::Value> {
    let method = req["method"].as_str().ok_or(Error::MethodNotFound)?;
    let params = req["params"].as_array().ok_or(Error::MissingParams)?;
    let version = req["jsonrpc"].as_str().ok_or(Error::MissingReq)?;

    if version != "2.0" {
        return Err(Error::InvalidRequest);
    }

    match method {
        "getblock" => {
            let hash = BlockHash::from_str(params[0].as_str().ok_or(Error::InvalidHash)?)
                .map_err(|_| Error::InvalidHash)?;
            let verbosity = params.get(1).map(|v| v.as_u64().unwrap() as u8);
            state
                .get_block(hash, verbosity)
                .map(|v| ::serde_json::to_value(v).unwrap())
        }
        "getblockhash" => {
            let height = params[0].as_u64().ok_or(Error::InvalidHeight)? as u32;
            state
                .get_block_hash(height)
                .map(|h| ::serde_json::to_value(h).unwrap())
        }
        "getblockheader" => {
            let hash = BlockHash::from_str(params[0].as_str().ok_or(Error::InvalidHash)?)
                .map_err(|_| Error::InvalidHash)?;
            state
                .get_block_header(hash)
                .map(|h| ::serde_json::to_value(h).unwrap())
        }
        "getblockchaininfo" => state
            .get_blockchain_info()
            .map(|v| ::serde_json::to_value(v).unwrap()),
        "getrawtransaction" => {
            let txid = Txid::from_str(params[0].as_str().ok_or(Error::InvalidHash)?)
                .map_err(|_| Error::InvalidHash)?;
            let verbosity = params.get(1).map(|v| v.as_bool().unwrap());
            state
                .get_transaction(txid, verbosity)
                .map(|v| ::serde_json::to_value(v).unwrap())
        }
        "gettxout" => {
            let txid = Txid::from_str(params[0].as_str().ok_or(Error::InvalidHash)?)
                .map_err(|_| Error::InvalidHash)?;
            let vout = params[1].as_u64().ok_or(Error::InvalidVout)? as u32;
            state
                .get_tx_out(txid, vout)
                .map(|v| ::serde_json::to_value(v).unwrap())
        }
        "gettxoutproof" => {
            let txid = Txid::from_str(params[0].as_str().ok_or(Error::InvalidHash)?)
                .map_err(|_| Error::InvalidHash)?;
            state
                .get_tx_proof(txid)
                .map(|v| ::serde_json::to_value(v).unwrap())
        }
        "getpeerinfo" => state
            .get_peer_info()
            .await
            .map(|v| ::serde_json::to_value(v).unwrap()),
        "getroots" => state
            .get_roots()
            .map(|v| ::serde_json::to_value(v).unwrap()),
        "addnode" => {
            let node = params[0].as_str().ok_or(Error::InvalidAddress)?;
            state
                .add_node(node.to_string())
                .map(|v| ::serde_json::to_value(v).unwrap())
        }
        "loaddescriptor" => {
            let descriptor = params[0].as_str().ok_or(Error::InvalidDescriptor)?;
            state
                .load_descriptor(descriptor.to_string())
                .map(|v| ::serde_json::to_value(v).unwrap())
        }
        "rescanblockchain" => {
            let rescan = params[0].as_u64().ok_or(Error::InvalidHeight)?;
            state
                .rescan(rescan as u32)
                .map(|v| ::serde_json::to_value(v).unwrap())
        }
        "sendrawtransaction" => {
            let tx = params[0].as_str().ok_or(Error::InvalidHex)?;
            state
                .send_raw_transaction(tx.to_string())
                .map(|v| ::serde_json::to_value(v).unwrap())
        }
        "stop" => state
            .stop()
            .await
            .map(|v| ::serde_json::to_value(v).unwrap()),
        "getheight" => state
            .get_height()
            .map(|v| ::serde_json::to_value(v).unwrap()),
        "findtxout" => {
            let txid = Txid::from_str(params[0].as_str().ok_or(Error::InvalidHash)?)
                .map_err(|_| Error::InvalidHash)?;
            let vout = params[1].as_u64().ok_or(Error::InvalidVout)? as u32;
            let script = ScriptBuf::from_hex(params[2].as_str().ok_or(Error::InvalidHex)?)
                .map_err(|_| Error::InvalidScript)?;
            let height = params[3].as_u64().ok_or(Error::InvalidHeight)? as u32;

            state
                .find_tx_out(txid, vout, script, height)
                .map(|v| ::serde_json::to_value(v).unwrap())
        }
        _ => {
            let error = Error::MethodNotFound;
            Err(error)
        }
    }
}

async fn json_rpc_request(
    State(state): State<Arc<RpcImpl>>,
    Json(req): Json<serde_json::Value>,
) -> axum::http::Response<axum::body::Body> {
    let Some(id) = req.get("id").cloned() else {
        let body = serde_json::json!({
            "error": "id field is required",
            "result": serde_json::Value::Null,
            "id": serde_json::Value::Null,
        });

        return axum::http::Response::builder()
            .status(axum::http::StatusCode::BAD_REQUEST)
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
    };

    let res = handle_json_rpc_request(req, state).await;

    match res {
        Ok(res) => {
            let body = serde_json::json!({
                "error": serde_json::Value::Null,
                "result": res,
                "id": id,
            });

            axum::http::Response::builder()
                .status(axum::http::StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap()
        }
        Err(e) => {
            let body = serde_json::json!({
                "error": e.to_string(),
                "result": serde_json::Value::Null,
                "id": id,
            });

            axum::http::Response::builder()
                .status(axum::http::StatusCode::BAD_REQUEST)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap()
        }
    }
}

async fn cannot_get(_state: State<Arc<RpcImpl>>) -> Json<serde_json::Value> {
    Json(json!({
        "error": "Cannot get on this route",
    }))
}

impl RpcImpl {
    fn rescan_with_block_filters(
        addresses: &[ScriptBuf],
        chain: Arc<ChainState<KvChainStore<'static>>>,
        wallet: Arc<AddressCache<KvDatabase>>,
        cfilters: Arc<NetworkFilters<FlatFiltersStore>>,
        node: Arc<NodeInterface>,
    ) -> Result<()> {
        let blocks = cfilters
            .match_any(
                addresses.iter().map(|a| a.as_bytes()).collect(),
                Some(0),
                chain.clone(),
            )
            .unwrap();

        info!("rescan filter hits: {:?}", blocks);

        for block in blocks {
            if let Ok(Some(block)) = node.get_block(block) {
                let height = chain
                    .get_block_height(&block.block_hash())
                    .unwrap()
                    .unwrap();
                wallet.block_process(&block, height);
            }
        }

        Ok(())
    }

    fn make_vin(&self, input: TxIn) -> TxInJson {
        let txid = serialize_hex(&input.previous_output.txid);
        let vout = input.previous_output.vout;
        let sequence = input.sequence.0;
        TxInJson {
            txid,
            vout,
            script_sig: ScriptSigJson {
                asm: input.script_sig.to_asm_string(),
                hex: input.script_sig.to_hex_string(),
            },
            witness: input
                .witness
                .iter()
                .map(|w| w.to_hex_string(bitcoin::hex::Case::Upper))
                .collect(),
            sequence,
        }
    }

    fn get_script_type(script: ScriptBuf) -> Option<&'static str> {
        if script.is_p2pkh() {
            return Some("p2pkh");
        }
        if script.is_p2sh() {
            return Some("p2sh");
        }
        if script.is_p2wpkh() {
            return Some("v0_p2wpkh");
        }
        if script.is_p2wsh() {
            return Some("v0_p2wsh");
        }
        None
    }

    fn make_vout(&self, output: TxOut, n: u32) -> TxOutJson {
        let value = output.value;
        TxOutJson {
            value: value.to_sat(),
            n,
            script_pub_key: ScriptPubKeyJson {
                asm: output.script_pubkey.to_asm_string(),
                hex: output.script_pubkey.to_hex_string(),
                req_sigs: 0, // This field is deprecated
                address: Address::from_script(&output.script_pubkey, self.network)
                    .map(|a| a.to_string())
                    .unwrap(),
                type_: Self::get_script_type(output.script_pubkey)
                    .unwrap_or("nonstandard")
                    .to_string(),
            },
        }
    }

    fn make_raw_transaction(&self, tx: CachedTransaction) -> RawTxJson {
        let raw_tx = tx.tx;
        let in_active_chain = tx.height != 0;
        let hex = serialize_hex(&raw_tx);
        let txid = serialize_hex(&raw_tx.compute_txid());
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
            hash: serialize_hex(&raw_tx.compute_wtxid()),
            size: raw_tx.total_size() as u32,
            vsize: raw_tx.vsize() as u32,
            weight: raw_tx.weight().to_wu() as u32,
            version: raw_tx.version.0 as u32,
            locktime: raw_tx.lock_time.to_consensus_u32(),
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
            blockhash: serialize_hex(&block_hash),
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
            _ => 8332,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        chain: Arc<ChainState<KvChainStore<'static>>>,
        wallet: Arc<AddressCache<KvDatabase>>,
        node: Arc<NodeInterface>,
        kill_signal: Arc<RwLock<bool>>,
        network: Network,
        block_filter_storage: Option<Arc<NetworkFilters<FlatFiltersStore>>>,
        address: Option<SocketAddr>,
    ) {
        let address = address.unwrap_or_else(|| {
            format!("127.0.0.1:{}", Self::get_port(&network))
                .parse()
                .unwrap()
        });

        let listener = tokio::net::TcpListener::bind(address)
            .await
            .expect("failed to bind rpc server");

        let router = Router::new()
            .route("/", post(json_rpc_request).get(cannot_get))
            .layer(
                CorsLayer::new()
                    .allow_private_network(true)
                    .allow_methods([Method::POST, Method::HEAD]),
            )
            .with_state(Arc::new(RpcImpl {
                chain,
                wallet,
                node,
                kill_signal,
                network,
                block_filter_storage,
            }));

        axum::serve(listener, router)
            .await
            .expect("failed to start rpc server");
    }
}
