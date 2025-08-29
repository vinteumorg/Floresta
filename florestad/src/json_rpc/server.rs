use std::collections::HashMap;
use std::net::SocketAddr;
use std::slice;
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
use floresta_chain::ThreadSafeChain;
use floresta_common::parse_descriptors;
use floresta_compact_filters::flat_filters_store::FlatFiltersStore;
use floresta_compact_filters::network_filters::NetworkFilters;
use floresta_watch_only::kv_database::KvDatabase;
use floresta_watch_only::AddressCache;
use floresta_watch_only::CachedTransaction;
use floresta_wire::node_interface::NodeInterface;
use floresta_wire::node_interface::PeerInfo;
use log::debug;
use log::error;
use log::info;
use serde_json::json;
use serde_json::Value;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;

use super::res::GetBlockRes;
use super::res::JsonRpcError;
use super::res::RawTxJson;
use super::res::RpcError;
use super::res::ScriptPubKeyJson;
use super::res::ScriptSigJson;
use super::res::TxInJson;
use super::res::TxOutJson;
use crate::json_rpc::res::RescanConfidence;

pub(super) struct InflightRpc {
    pub method: String,
    pub when: Instant,
}

/// Utility trait to ensure that the chain implements all the necessary traits
///
/// Instead of using this very complex trait bound declaration on every impl block
/// and function, this trait makes sure everything we need is implemented.
pub trait RpcChain: ThreadSafeChain + Clone {}

impl<T> RpcChain for T where T: ThreadSafeChain + Clone {}

pub struct RpcImpl<Blockchain: RpcChain> {
    pub(super) block_filter_storage: Option<Arc<NetworkFilters<FlatFiltersStore>>>,
    pub(super) network: Network,
    pub(super) chain: Blockchain,
    pub(super) wallet: Arc<AddressCache<KvDatabase>>,
    pub(super) node: NodeInterface,
    pub(super) kill_signal: Arc<RwLock<bool>>,
    pub(super) inflight: Arc<RwLock<HashMap<Value, InflightRpc>>>,
    pub(super) log_path: String,
    pub(super) start_time: Instant,
}

type Result<T> = std::result::Result<T, JsonRpcError>;

impl<Blockchain: RpcChain> RpcImpl<Blockchain> {
    async fn add_node(&self, node: String, command: String, v2transport: bool) -> Result<Value> {
        let node = node.split(':').collect::<Vec<&str>>();
        let (ip, port) = if node.len() == 2 {
            (
                node[0],
                node[1].parse().map_err(|_| JsonRpcError::InvalidPort)?,
            )
        } else {
            match self.network {
                Network::Bitcoin => (node[0], 8333),
                Network::Testnet => (node[0], 18333),
                Network::Regtest => (node[0], 18444),
                Network::Signet => (node[0], 38333),
                _ => return Err(JsonRpcError::InvalidNetwork),
            }
        };

        let peer = ip.parse().map_err(|_| JsonRpcError::InvalidAddress)?;

        let _ = match command.as_str() {
            "add" => self.node.add_peer(peer, port, v2transport).await,
            "remove" => self.node.remove_peer(peer, port).await,
            "onetry" => self.node.onetry_peer(peer, port, v2transport).await,
            _ => return Err(JsonRpcError::InvalidAddnodeCommand),
        };

        Ok(json!(null))
    }

    fn get_transaction(&self, tx_id: Txid, verbosity: Option<bool>) -> Result<Value> {
        if verbosity == Some(true) {
            let tx = self
                .wallet
                .get_transaction(&tx_id)
                .ok_or(JsonRpcError::TxNotFound);
            return tx.map(|tx| serde_json::to_value(self.make_raw_transaction(tx)).unwrap());
        }

        self.wallet
            .get_transaction(&tx_id)
            .and_then(|tx| serde_json::to_value(self.make_raw_transaction(tx)).ok())
            .ok_or(JsonRpcError::TxNotFound)
    }

    fn load_descriptor(&self, descriptor: String) -> Result<bool> {
        let desc = slice::from_ref(&descriptor);
        let Ok(mut parsed) = parse_descriptors(desc) else {
            return Err(JsonRpcError::InvalidDescriptor);
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

        debug!("Rescanning with block filters for addresses: {addresses:?}");

        let addresses = self.wallet.get_cached_addresses();
        let wallet = self.wallet.clone();
        if self.block_filter_storage.is_none() {
            return Err(JsonRpcError::InInitialBlockDownload);
        };

        let cfilters = self.block_filter_storage.as_ref().unwrap().clone();
        let node = self.node.clone();
        let chain = self.chain.clone();

        tokio::task::spawn(Self::rescan_with_block_filters(
            addresses, chain, wallet, cfilters, node, None, None,
        ));

        Ok(true)
    }

    async fn rescan_blockchain(
        &self,
        start: Option<u32>,
        stop: Option<u32>,
        use_timestamp: bool,
        confidence: Option<RescanConfidence>,
    ) -> Result<bool> {
        let (start_height, stop_height) = self
            .get_rescan_interval(use_timestamp, start, stop, confidence)
            .await?;

        if stop_height != 0 && start_height >= stop_height {
            // When stop height is a non zero value it needs atleast to be greater than start_height.
            return Err(JsonRpcError::InvalidRescanVal);
        }

        // if we are on ibd, we don't have any filters to rescan
        if self.chain.is_in_ibd() {
            return Err(JsonRpcError::InInitialBlockDownload);
        }

        let addresses = self.wallet.get_cached_addresses();

        if addresses.is_empty() {
            return Err(JsonRpcError::NoAddressesToRescan);
        }

        let wallet = self.wallet.clone();

        if self.block_filter_storage.is_none() {
            return Err(JsonRpcError::NoBlockFilters);
        };

        let cfilters = self.block_filter_storage.as_ref().unwrap().clone();

        let node = self.node.clone();

        let chain = self.chain.clone();

        tokio::task::spawn(Self::rescan_with_block_filters(
            addresses,
            chain,
            wallet,
            cfilters,
            node,
            (start_height != 0).then_some(start_height), // Its ugly but to maintain the API here its necessary to recast to a Option.
            (stop_height != 0).then_some(stop_height),
        ));
        Ok(true)
    }

    fn send_raw_transaction(&self, tx: String) -> Result<Txid> {
        let tx_hex = Vec::from_hex(&tx).map_err(|_| JsonRpcError::InvalidHex)?;
        let tx = deserialize(&tx_hex).map_err(|e| JsonRpcError::Decode(e.to_string()))?;
        self.chain.broadcast(&tx).map_err(|_| JsonRpcError::Chain)?;

        Ok(tx.compute_txid())
    }

    async fn get_peer_info(&self) -> Result<Vec<PeerInfo>> {
        self.node
            .get_peer_info()
            .await
            .map_err(|_| JsonRpcError::Node("Failed to get peer info".to_string()))
    }
}

async fn handle_json_rpc_request(
    req: Value,
    state: Arc<RpcImpl<impl RpcChain>>,
) -> Result<serde_json::Value> {
    let method = req["method"].as_str().ok_or(JsonRpcError::MethodNotFound)?;
    let params = req["params"]
        .as_array()
        .ok_or(JsonRpcError::MissingParams)?;
    let version = req["jsonrpc"].as_str().ok_or(JsonRpcError::MissingReq)?;
    let id = req["id"].clone();

    if version != "2.0" {
        return Err(JsonRpcError::InvalidRequest);
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
            let hash = BlockHash::from_str(params[0].as_str().ok_or(JsonRpcError::InvalidHash)?)
                .map_err(|_| JsonRpcError::InvalidHash)?;
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
                _ => Err(JsonRpcError::InvalidVerbosityLevel),
            }
        }

        "getblockchaininfo" => state
            .get_blockchain_info()
            .map(|v| ::serde_json::to_value(v).unwrap()),

        "getblockcount" => state
            .get_block_count()
            .map(|v| ::serde_json::to_value(v).unwrap()),

        "getblockfrompeer" => {
            let hash = BlockHash::from_str(params[0].as_str().ok_or(JsonRpcError::InvalidHash)?)
                .map_err(|_| JsonRpcError::InvalidHash)?;
            state
                .get_block(hash)
                .await
                .map(|v| ::serde_json::to_value(v).unwrap())
        }

        "getblockhash" => {
            let height = params[0].as_u64().ok_or(JsonRpcError::InvalidHeight)? as u32;
            state
                .get_block_hash(height)
                .map(|h| ::serde_json::to_value(h).unwrap())
        }

        "getblockheader" => {
            let hash = BlockHash::from_str(params[0].as_str().ok_or(JsonRpcError::InvalidHash)?)
                .map_err(|_| JsonRpcError::InvalidHash)?;
            state
                .get_block_header(hash)
                .map(|h| ::serde_json::to_value(h).unwrap())
        }

        "gettxout" => {
            let txid = Txid::from_str(params[0].as_str().ok_or(JsonRpcError::InvalidHash)?)
                .map_err(|_| JsonRpcError::InvalidHash)?;
            let vout = params[1].as_u64().ok_or(JsonRpcError::InvalidVout)? as u32;
            let include_mempool = params[2].as_bool().unwrap_or(false);
            state
                .get_tx_out(txid, vout, include_mempool)
                .map(|v| ::serde_json::to_value(v).unwrap())
        }

        "gettxoutproof" => {
            let txids: Vec<Txid> =
                serde_json::from_value(params[0].clone()).map_err(|_| JsonRpcError::InvalidHash)?;

            let blockhash = params
                .get(1)
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| JsonRpcError::InvalidBlockHash)?;

            Ok(serde_json::to_value(
                state
                    .get_txout_proof(&txids, blockhash)
                    .await?
                    .0
                    .to_lower_hex_string(),
            )
            .expect("GetTxOutProof implements serde"))
        }

        "getrawtransaction" => {
            let txid = Txid::from_str(params[0].as_str().ok_or(JsonRpcError::InvalidHash)?)
                .map_err(|_| JsonRpcError::InvalidHash)?;
            let verbosity = params.get(1).map(|v| v.as_bool().unwrap());
            state
                .get_transaction(txid, verbosity)
                .map(|v| ::serde_json::to_value(v).unwrap())
        }

        "getroots" => state
            .get_roots()
            .map(|v| ::serde_json::to_value(v).unwrap()),

        "findtxout" => {
            let txid = Txid::from_str(params[0].as_str().ok_or(JsonRpcError::InvalidHash)?)
                .map_err(|_| JsonRpcError::InvalidHash)?;
            let vout = params[1].as_u64().ok_or(JsonRpcError::InvalidVout)? as u32;
            let script = ScriptBuf::from_hex(params[2].as_str().ok_or(JsonRpcError::InvalidHex)?)
                .map_err(|_| JsonRpcError::InvalidScript)?;
            let height = params[3].as_u64().ok_or(JsonRpcError::InvalidHeight)? as u32;

            let state = state.clone();
            state.find_tx_out(txid, vout, script, height).await
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
            let node = params[0].as_str().ok_or(JsonRpcError::InvalidAddress)?;
            let command = params[1]
                .as_str()
                .ok_or(JsonRpcError::InvalidAddnodeCommand)?;
            let v2transport = params[2].as_bool().unwrap_or(false);

            state
                .add_node(node.to_string(), command.to_string(), v2transport)
                .await
                .map(|v| ::serde_json::to_value(v).unwrap())
        }

        "ping" => {
            state.ping().await?;

            Ok(serde_json::json!(null))
        }

        // wallet
        "loaddescriptor" => {
            let descriptor = params[0].as_str().ok_or(JsonRpcError::InvalidDescriptor)?;
            state
                .load_descriptor(descriptor.to_string())
                .map(|v| ::serde_json::to_value(v).unwrap())
        }

        "rescanblockchain" => {
            let start_height = params.first().and_then(Value::as_u64).map(|h| h as u32);

            let stop_height = params.get(1).and_then(Value::as_u64).map(|h| h as u32);

            let use_timestamp = params.get(2).and_then(Value::as_bool).unwrap_or(false);

            let confidence_str = params.get(3).and_then(Value::as_str).unwrap_or("low");

            let confidence =
                serde_json::from_str(confidence_str).map_err(|_| JsonRpcError::InvalidRequest)?;

            state
                .rescan_blockchain(start_height, stop_height, use_timestamp, confidence)
                .await
                .map(|v| ::serde_json::to_value(v).unwrap())
        }

        "sendrawtransaction" => {
            let tx = params[0].as_str().ok_or(JsonRpcError::InvalidHex)?;
            state
                .send_raw_transaction(tx.to_string())
                .map(|v| ::serde_json::to_value(v).unwrap())
        }

        "listdescriptors" => state
            .list_descriptors()
            .map(|v| ::serde_json::to_value(v).unwrap()),

        _ => {
            let error = JsonRpcError::MethodNotFound;
            Err(error)
        }
    }
}

fn get_http_error_code(err: &JsonRpcError) -> u16 {
    match err {
        // you messed up
        JsonRpcError::InvalidHex
        | JsonRpcError::InvalidBlockHash
        | JsonRpcError::InvalidHash
        | JsonRpcError::InvalidAddress
        | JsonRpcError::InvalidScript
        | JsonRpcError::InvalidRequest
        | JsonRpcError::InvalidVout
        | JsonRpcError::InvalidPort
        | JsonRpcError::InvalidHeight
        | JsonRpcError::InvalidDescriptor
        | JsonRpcError::InvalidNetwork
        | JsonRpcError::InvalidVerbosityLevel
        | JsonRpcError::Decode(_)
        | JsonRpcError::MissingParams
        | JsonRpcError::MissingReq
        | JsonRpcError::NoBlockFilters
        | JsonRpcError::InvalidMemInfoMode
        | JsonRpcError::InvalidAddnodeCommand
        | JsonRpcError::InvalidTimestamp
        | JsonRpcError::InvalidRescanVal
        | JsonRpcError::NoAddressesToRescan
        | JsonRpcError::Wallet(_) => 400,

        // idunnolol
        JsonRpcError::MethodNotFound | JsonRpcError::BlockNotFound | JsonRpcError::TxNotFound => {
            404
        }

        // we messed up, sowwy
        JsonRpcError::InInitialBlockDownload
        | JsonRpcError::Node(_)
        | JsonRpcError::Chain
        | JsonRpcError::Filters(_) => 503,
    }
}

fn get_json_rpc_error_code(err: &JsonRpcError) -> i32 {
    match err {
        // Parse Error
        JsonRpcError::Decode(_) | JsonRpcError::MissingReq | JsonRpcError::MissingParams => -32700,

        // Invalid Request
        JsonRpcError::InvalidHex
        | JsonRpcError::InvalidBlockHash
        | JsonRpcError::InvalidHash
        | JsonRpcError::InvalidAddress
        | JsonRpcError::InvalidScript
        | JsonRpcError::MethodNotFound
        | JsonRpcError::InvalidRequest
        | JsonRpcError::InvalidVout
        | JsonRpcError::InvalidPort
        | JsonRpcError::InvalidHeight
        | JsonRpcError::InvalidDescriptor
        | JsonRpcError::InvalidNetwork
        | JsonRpcError::InvalidVerbosityLevel
        | JsonRpcError::TxNotFound
        | JsonRpcError::BlockNotFound
        | JsonRpcError::InvalidTimestamp
        | JsonRpcError::InvalidMemInfoMode
        | JsonRpcError::InvalidAddnodeCommand
        | JsonRpcError::InvalidRescanVal
        | JsonRpcError::NoAddressesToRescan
        | JsonRpcError::Wallet(_) => -32600,

        // server error
        JsonRpcError::InInitialBlockDownload
        | JsonRpcError::Node(_)
        | JsonRpcError::Chain
        | JsonRpcError::NoBlockFilters
        | JsonRpcError::Filters(_) => -32603,
    }
}

async fn json_rpc_request(
    State(state): State<Arc<RpcImpl<impl RpcChain>>>,
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

async fn cannot_get(_state: State<Arc<RpcImpl<impl RpcChain>>>) -> Json<serde_json::Value> {
    Json(json!({
        "error": "Cannot get on this route",
    }))
}

impl<Blockchain: RpcChain> RpcImpl<Blockchain> {
    async fn rescan_with_block_filters(
        addresses: Vec<ScriptBuf>,
        chain: Blockchain,
        wallet: Arc<AddressCache<KvDatabase>>,
        cfilters: Arc<NetworkFilters<FlatFiltersStore>>,
        node: NodeInterface,
        start_height: Option<u32>,
        stop_height: Option<u32>,
    ) -> Result<()> {
        let blocks = cfilters
            .match_any(
                addresses.iter().map(|a| a.as_bytes()).collect(),
                start_height,
                stop_height,
                chain.clone(),
            )
            .unwrap();

        info!("rescan filter hits: {blocks:?}");

        for block in blocks {
            if let Ok(Some(block)) = node.get_block(block).await {
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
        chain: Blockchain,
        wallet: Arc<AddressCache<KvDatabase>>,
        node: NodeInterface,
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
            Ok(listener) => {
                let local_addr = listener
                    .local_addr()
                    .expect("Infallible: listener binding was `Ok`");
                info!("RPC server is running at {local_addr}");
                listener
            }
            Err(_) => {
                error!(
                    "Failed to bind to address {address}. Floresta is probably already running.",
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
                log_path,
                start_time: Instant::now(),
            }));

        axum::serve(listener, router)
            .await
            .expect("failed to start rpc server");
    }
}
