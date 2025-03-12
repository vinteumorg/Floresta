use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::http::Method;
use axum::routing::post;
use axum::Json;
use axum::Router;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::Address;
use bitcoin::BlockHash;
use bitcoin::Network;
use bitcoin::ScriptBuf;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Txid;
use floresta_chain::pruned_utreexo::BlockchainInterface;
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
use tokio::task::spawn_blocking;
use tower_http::cors::CorsLayer;

use super::res::Error;
use super::res::GetBlockRes;
use super::res::RawTxJson;
use super::res::RpcError;
use super::res::ScriptPubKeyJson;
use super::res::ScriptSigJson;
use super::res::TxInJson;
use super::res::TxOutJson;

pub(super) struct InflightRpc {
    pub method: String,
    pub when: Instant,
}

pub struct RpcImpl {
    pub(super) block_filter_storage: Option<Arc<NetworkFilters<FlatFiltersStore>>>,
    pub(super) network: Network,
    pub(super) chain: Arc<ChainState<KvChainStore<'static>>>,
    pub(super) wallet: Arc<AddressCache<KvDatabase>>,
    pub(super) node: Arc<NodeInterface>,
    pub(super) kill_signal: Arc<RwLock<bool>>,
    pub(super) inflight: Arc<RwLock<HashMap<Value, InflightRpc>>>,
    pub(super) log_dir: String,
    pub(super) start_time: Instant,
}

type Result<T> = std::result::Result<T, Error>;

impl RpcImpl {
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

        let peer = ip.parse().map_err(|_| Error::InvalidAddress)?;
        let node = self.node.clone();

        spawn_blocking(move || {
            node.connect(peer, port)
                .map_err(|e| Error::Node(e.to_string()))
        });

        Ok(true)
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

        spawn_blocking(move || {
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

        spawn_blocking(move || {
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
}

async fn handle_json_rpc_request(req: Value, state: Arc<RpcImpl>) -> Result<serde_json::Value> {
    let method = req["method"].as_str().ok_or(Error::MethodNotFound)?;
    let params = req["params"].as_array().ok_or(Error::MissingParams)?;
    let version = req["jsonrpc"].as_str().ok_or(Error::MissingReq)?;
    let id = req["id"].clone();

    if version != "2.0" {
        return Err(Error::InvalidRequest);
    }

    state.inflight.write().await.insert(
        id.clone(),
        InflightRpc {
            method: req["method"].as_str().unwrap().to_string(),
            when: Instant::now(),
        },
    );

    match method {
        // blockchain
        "getbestblockhash" => {
            let hash = state.get_best_block_hash()?;
            Ok(serde_json::to_value(hash).unwrap())
        }

        "getblock" => {
            let hash = BlockHash::from_str(params[0].as_str().ok_or(Error::InvalidHash)?)
                .map_err(|_| Error::InvalidHash)?;
            let verbosity = params.get(1).map(|v| v.as_u64().unwrap() as u8);

            match verbosity {
                Some(0) => {
                    let block = state.get_block_serialized(hash).await?;

                    let block = GetBlockRes::Serialized(block);
                    Ok(serde_json::to_value(block).unwrap())
                }
                Some(1) => {
                    let block = state.get_block(hash).await?;

                    let block = GetBlockRes::Verbose(block.into());
                    Ok(serde_json::to_value(block).unwrap())
                }
                _ => Err(Error::InvalidVerbosityLevel),
            }
        }

        "getblockchaininfo" => state
            .get_blockchain_info()
            .map(|v| ::serde_json::to_value(v).unwrap()),

        "getblockcount" => state
            .get_block_count()
            .map(|v| ::serde_json::to_value(v).unwrap()),

        "getblockfrompeer" => {
            let hash = BlockHash::from_str(params[0].as_str().ok_or(Error::InvalidHash)?)
                .map_err(|_| Error::InvalidHash)?;
            state
                .get_block(hash)
                .await
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

        "getrawtransaction" => {
            let txid = Txid::from_str(params[0].as_str().ok_or(Error::InvalidHash)?)
                .map_err(|_| Error::InvalidHash)?;
            let verbosity = params.get(1).map(|v| v.as_bool().unwrap());
            state
                .get_transaction(txid, verbosity)
                .map(|v| ::serde_json::to_value(v).unwrap())
        }

        "getroots" => state
            .get_roots()
            .map(|v| ::serde_json::to_value(v).unwrap()),

        "findtxout" => {
            let txid = Txid::from_str(params[0].as_str().ok_or(Error::InvalidHash)?)
                .map_err(|_| Error::InvalidHash)?;
            let vout = params[1].as_u64().ok_or(Error::InvalidVout)? as u32;
            let script = ScriptBuf::from_hex(params[2].as_str().ok_or(Error::InvalidHex)?)
                .map_err(|_| Error::InvalidScript)?;
            let height = params[3].as_u64().ok_or(Error::InvalidHeight)? as u32;

            let state = state.clone();
            spawn_blocking(move || state.find_tx_out(txid, vout, script, height))
                .await
                .map_err(|e| Error::Node(e.to_string()))?
                .map(|v| ::serde_json::to_value(v).unwrap())
        }

        // control
        "getmemoryinfo" => {
            let mode = params.first().and_then(|v| v.as_str()).unwrap_or("stats");

            state
                .get_memory_info(mode)
                .map(|v| ::serde_json::to_value(v).unwrap())
        }

        "getrpcinfo" => state
            .get_rpc_info()
            .await
            .map(|v| ::serde_json::to_value(v).unwrap()),

        // help
        // logging
        "stop" => state
            .stop()
            .await
            .map(|v| ::serde_json::to_value(v).unwrap()),

        "uptime" => {
            let uptime = state.uptime();
            Ok(serde_json::to_value(uptime).unwrap())
        }

        // network
        "getpeerinfo" => state
            .get_peer_info()
            .await
            .map(|v| ::serde_json::to_value(v).unwrap()),

        "addnode" => {
            let node = params[0].as_str().ok_or(Error::InvalidAddress)?;
            state
                .add_node(node.to_string())
                .map(|v| ::serde_json::to_value(v).unwrap())
        }

        // wallet
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

        "listdescriptors" => state
            .list_descriptors()
            .map(|v| ::serde_json::to_value(v).unwrap()),

        _ => {
            let error = Error::MethodNotFound;
            Err(error)
        }
    }
}

fn get_http_error_code(err: &Error) -> u16 {
    match err {
        // you messed up
        Error::InvalidHex
        | Error::InvalidHash
        | Error::InvalidAddress
        | Error::InvalidScript
        | Error::InvalidRequest
        | Error::InvalidVout
        | Error::InvalidPort
        | Error::InvalidHeight
        | Error::InvalidDescriptor
        | Error::InvalidNetwork
        | Error::InvalidVerbosityLevel
        | Error::Decode(_)
        | Error::MissingParams
        | Error::MissingReq
        | Error::NoBlockFilters
        | Error::InvalidMemInfoMode => 400,
        Error::WalletError(_) => 400,

        // idunnolol
        Error::MethodNotFound | Error::BlockNotFound | Error::TxNotFound => 404,

        // we messed up, sowwy
        Error::InInitialBlockDownload | Error::Node(_) | Error::Chain | Error::Encode => 503,
    }
}

fn get_json_rpc_error_code(err: &Error) -> i32 {
    match err {
        // Parse Error
        Error::Decode(_) | Error::MissingReq | Error::MissingParams => -32700,

        // Invalid Request
        Error::InvalidHex
        | Error::InvalidHash
        | Error::InvalidAddress
        | Error::InvalidScript
        | Error::MethodNotFound
        | Error::InvalidRequest
        | Error::InvalidVout
        | Error::InvalidPort
        | Error::InvalidHeight
        | Error::InvalidDescriptor
        | Error::InvalidNetwork
        | Error::InvalidVerbosityLevel
        | Error::TxNotFound
        | Error::BlockNotFound
        | Error::InvalidMemInfoMode => -32600,
        Error::WalletError(_) => -32600,

        // server error
        Error::InInitialBlockDownload
        | Error::Node(_)
        | Error::Chain
        | Error::Encode
        | Error::NoBlockFilters => -32603,
    }
}

async fn json_rpc_request(
    State(state): State<Arc<RpcImpl>>,
    Json(req): Json<serde_json::Value>,
) -> axum::http::Response<axum::body::Body> {
    let Some(id) = req.get("id").cloned() else {
        let error = RpcError {
            code: -32600,
            message: "Invalid request".to_string(),
            data: None,
        };

        let body = serde_json::json!({
            "error": error,
            "id": serde_json::Value::Null,
        });

        return axum::http::Response::builder()
            .status(axum::http::StatusCode::BAD_REQUEST)
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
    };

    let res = handle_json_rpc_request(req, state.clone()).await;

    state.inflight.write().await.remove(&id);

    match res {
        Ok(res) => {
            let body = serde_json::json!({
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
            let http_error_code = get_http_error_code(&e);
            let json_rpc_error_code = get_json_rpc_error_code(&e);
            let error = RpcError {
                code: json_rpc_error_code,
                message: e.to_string(),
                data: None,
            };

            let body = serde_json::json!({
                "error": error,
                "id": id,
            });

            axum::http::Response::builder()
                .status(axum::http::StatusCode::from_u16(http_error_code).unwrap())
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
        log_path: String,
    ) {
        let address = address.unwrap_or_else(|| {
            format!("127.0.0.1:{}", Self::get_port(&network))
                .parse()
                .unwrap()
        });

        let listener = match tokio::net::TcpListener::bind(address).await {
            Ok(listener) => listener,
            Err(_) => {
                error!(
                    "Failed to bind to address {}. Floresta is probably already running.",
                    address
                );
                std::process::exit(-1);
            }
        };

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
                inflight: Arc::new(RwLock::new(HashMap::new())),
                log_dir: log_path,
                start_time: Instant::now(),
            }));

        axum::serve(listener, router)
            .await
            .expect("failed to start rpc server");
    }
}
