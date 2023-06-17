use crate::request::Request;
use crate::{get_arg, json_rpc_res};
use bitcoin::hashes::hex::FromHex;
use floresta_chain::pruned_utreexo::BlockchainInterface;
use floresta_chain::Notification;
use floresta_common::{get_hash_from_u8, get_spk_hash};
use floresta_watch_only::kv_database::KvDatabase;
use floresta_watch_only::{AddressCache, CachedTransaction};
use futures::{select, FutureExt};

use async_std::sync::RwLock;
use async_std::{
    channel::{unbounded, Receiver, Sender},
    io::BufReader,
    net::{TcpListener, TcpStream},
    prelude::*,
};

use bitcoin::hashes::{hex::ToHex, sha256};
use bitcoin::{
    consensus::{deserialize, serialize},
    Script, Txid,
};
use bitcoin::{Transaction, TxOut};

use log::{info, log, trace, Level};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct Peer {
    _addresses: HashSet<Script>,
    stream: Option<Arc<TcpStream>>,
}

impl Peer {
    pub async fn write(&self, data: &[u8]) -> Result<(), std::io::Error> {
        if let Some(stream) = &self.stream {
            let mut stream = &**stream;
            let _ = stream.write(data).await;
            let _ = stream.write('\n'.to_string().as_bytes()).await;
        }

        Ok(())
    }
    pub fn new(stream: Arc<TcpStream>) -> Self {
        Peer {
            _addresses: HashSet::new(),
            stream: Some(stream),
        }
    }
}
pub struct ElectrumServer<Blockchain: BlockchainInterface> {
    pub chain: Arc<Blockchain>,
    pub address_cache: Arc<RwLock<AddressCache<KvDatabase>>>,
    pub listener: Option<Arc<TcpListener>>,
    pub peers: HashMap<u32, Arc<Peer>>,
    pub peer_accept: Receiver<Message>,
    pub notify_tx: Sender<Message>,
    pub peer_addresses: HashMap<sha256::Hash, Arc<Peer>>,
}
pub enum Message {
    NewPeer((u32, Arc<Peer>)),
    Message((u32, String)),
    Disconnect(u32),
}

impl<Blockchain: BlockchainInterface> ElectrumServer<Blockchain> {
    pub async fn new<'a>(
        address: &'static str,
        address_cache: Arc<RwLock<AddressCache<KvDatabase>>>,
        chain: Arc<Blockchain>,
    ) -> Result<ElectrumServer<Blockchain>, Box<dyn std::error::Error>> {
        let listener = Arc::new(TcpListener::bind(address).await?);
        let (tx, rx) = unbounded();
        let unconfirmed = address_cache.read().await.find_unconfirmed()?;
        for tx in unconfirmed {
            chain.broadcast(&tx).expect("Invalid chain");
        }
        Ok(ElectrumServer {
            chain,
            address_cache,
            listener: Some(listener),
            peers: HashMap::new(),
            peer_accept: rx,
            notify_tx: tx,
            peer_addresses: HashMap::new(),
        })
    }
    pub async fn handle_blockchain_request(
        &mut self,
        peer: Arc<Peer>,
        request: Request,
    ) -> Result<Value, super::error::Error> {
        // Methods are in alphabetical order
        match request.method.as_str() {
            "blockchain.block.header" => {
                let height = get_arg!(request, u64, 0);
                let hash = self
                    .chain
                    .get_block_hash(height as u32)
                    .map_err(|_| super::error::Error::InvalidParams)?;
                let header = self.chain.get_block_header(&hash).map_err(|val| {
                    println!("Error: {:?}", val);
                    super::error::Error::ChainError(val)
                })?;
                let header = serialize(&header).to_hex();
                json_rpc_res!(request, header)
            }
            "blockchain.block.headers" => {
                let start_height = get_arg!(request, u64, 0);
                let count = get_arg!(request, u64, 1);
                let mut headers = String::new();
                let count = if count < 2016 { count } else { 2016 };
                for height in start_height..(start_height + count) {
                    let hash = self
                        .chain
                        .get_block_hash(height as u32)
                        .map_err(|_| super::error::Error::InvalidParams)?;

                    let header = self.chain.get_block_header(&hash).unwrap();
                    let header = serialize(&header).to_hex();
                    headers.push_str(&header);
                }
                json_rpc_res!(request, {
                    "count": count,
                    "hex": headers,
                    "max": 2016
                })
            }
            "blockchain.estimatefee" => json_rpc_res!(request, 0.0001),
            "blockchain.headers.subscribe" => {
                let (height, hash) = self.chain.get_best_block()?;
                let header = self.chain.get_block_header(&hash)?;
                let result = json!({
                    "height": height,
                    "hex": serialize(&header).to_hex()
                });
                json_rpc_res!(request, result)
            }
            // TODO: Ask Backend for fees
            "blockchain.relayfee" => json_rpc_res!(request, 0.00001),
            "blockchain.scripthash.get_balance" => {
                let script_hash = get_arg!(request, sha256::Hash, 0);
                let balance = self
                    .address_cache
                    .read()
                    .await
                    .get_address_balance(&script_hash);
                let result = json!({
                    "confirmed": balance,
                    "unconfirmed": 0
                });
                json_rpc_res!(request, result)
            }
            "blockchain.scripthash.get_history" => {
                let script_hash = get_arg!(request, sha256::Hash, 0);
                let transactions = self
                    .address_cache
                    .read()
                    .await
                    .get_address_history(&script_hash);
                let mut res = vec![];
                for transaction in transactions {
                    let entry = if transaction.height == 0 {
                        json!({
                            "tx_hash": transaction.hash.to_hex(),
                            "height": transaction.height,
                            "fee": 2000
                        })
                    } else {
                        json!({
                            "tx_hash": transaction.hash.to_hex(),
                            "height": transaction.height,
                        })
                    };

                    res.push(entry);
                }

                json_rpc_res!(request, res)
            }
            "blockchain.scripthash.get_mempool" => json_rpc_res!(request, []),
            "blockchain.scripthash.listunspent" => {
                let hash = get_arg!(request, sha256::Hash, 0);
                let utxos = self.address_cache.read().await.get_address_utxos(&hash);
                if utxos.is_none() {
                    return Err(crate::error::Error::InvalidParams);
                }
                let mut final_utxos = vec![];
                for (utxo, prevout) in utxos.unwrap().into_iter() {
                    let height = self
                        .address_cache
                        .read()
                        .await
                        .get_height(&prevout.txid)
                        .unwrap();

                    let position = self
                        .address_cache
                        .read()
                        .await
                        .get_position(&prevout.txid)
                        .unwrap();

                    final_utxos.push(json!({
                        "height": height,
                        "tx_pos": position,
                        "tx_hash": prevout.txid,
                        "value": utxo.value
                    }));
                }

                json_rpc_res!(request, final_utxos)
            }
            "blockchain.scripthash.subscribe" => {
                let hash = get_arg!(request, sha256::Hash, 0);
                self.peer_addresses.insert(hash, peer);

                let history = self.address_cache.read().await.get_address_history(&hash);

                if history.is_empty() {
                    return json_rpc_res!(request, null);
                }
                let status_hash = get_status(history);
                json_rpc_res!(request, status_hash)
            }
            "blockchain.scripthash.unsubscribe" => {
                let address = get_arg!(request, sha256::Hash, 0);
                self.peer_addresses.remove(&address);
                json_rpc_res!(request, true)
            }
            "blockchain.transaction.broadcast" => {
                let tx = get_arg!(request, String, 0);
                let hex: Vec<_> =
                    Vec::from_hex(&tx).map_err(|_| super::error::Error::InvalidParams)?;
                let tx: Transaction =
                    deserialize(&hex).map_err(|_| super::error::Error::InvalidParams)?;
                self.chain.broadcast(&tx)?;
                let id = tx.txid();
                let updated = self
                    .address_cache
                    .write()
                    .await
                    .cache_mempool_transaction(&tx)
                    .into_iter()
                    .map(|spend| (tx.clone(), spend))
                    .collect::<Vec<_>>();
                self.wallet_notify(&updated).await;
                json_rpc_res!(request, id)
            }
            "blockchain.transaction.get" => {
                let tx_id = get_arg!(request, Txid, 0);
                let tx = self
                    .address_cache
                    .read()
                    .await
                    .get_cached_transaction(&tx_id);
                if let Some(tx) = tx {
                    return json_rpc_res!(request, tx);
                }

                Err(super::error::Error::InvalidParams)
            }
            "blockchain.transaction.get_merkle" => {
                let tx_id = get_arg!(request, Txid, 0);
                let proof = self.address_cache.read().await.get_merkle_proof(&tx_id);
                let height = self.address_cache.read().await.get_height(&tx_id);
                if let Some((proof, position)) = proof {
                    let result = json!({
                        "merkle": proof,
                        "block_height": height.unwrap_or(0),
                        "pos": position
                    });
                    return json_rpc_res!(request, result);
                }

                Err(super::error::Error::InvalidParams)
            }
            //blockchain.transaction.id_from_pos
            // TODO: Create an actual histogram
            "mempool.get_fee_histogram" => json_rpc_res!(request, []),
            "server.add_peer" => json_rpc_res!(request, true),
            "server.banner" => json_rpc_res!(request, "Welcome to Floresta's Electrum Server."),
            "server.donation_address" => {
                json_rpc_res!(request, "")
            }
            "server.features" => {
                let genesis_hash = self
                    .chain
                    .get_block_hash(0)
                    .expect("Genesis block should be present");
                let res = json!(
                    {
                        "genesis_hash": genesis_hash,
                        "hosts": {"127.0.0.1": {"tcp_port": 50001}},
                        "protocol_max": "1.4",
                        "protocol_min": "1.0",
                        "pruning": null,
                        "server_version": format!("Floresta {}", env!("CARGO_PKG_VERSION")),
                        "hash_function": "sha256"
                    }
                );
                json_rpc_res!(request, res)
            }
            // TODO: Return peers?
            "server.peers.subscribe" => json_rpc_res!(request, []),
            "server.ping" => json_rpc_res!(request, null),
            "server.version" => json_rpc_res!(
                request,
                [format!("Floresta {}", env!("CARGO_PKG_VERSION")), "1.4"]
            ),

            _ => Err(super::error::Error::InvalidParams),
        }
    }

    pub async fn main_loop(mut self) -> Result<(), crate::error::Error> {
        let (tx, mut rx) = unbounded::<Notification>();
        self.chain.subscribe(tx);
        loop {
            select! {
                notification = rx.next().fuse() => {
                    if let Some(notification) = notification {
                        self.handle_notification(notification).await;
                    }
                },
                message = self.peer_accept.next().fuse() => {
                    if let Some(message) = message {
                        self.handle_message(message).await?;
                    }
                }
            };
        }
    }
    async fn handle_notification(&mut self, notification: Notification) {
        match notification {
            Notification::NewBlock((block, height)) => {
                let result = json!({
                    "jsonrpc": "2.0",
                    "method": "blockchain.headers.subscribe",
                    "params": [{
                        "height": height,
                        "hex": serialize(&block.header).to_hex()
                    }]
                });
                if !self.chain.is_in_idb() || height % 1000 == 0 {
                    let lock = self.address_cache.write().await;
                    lock.bump_height(height);
                }
                if self.chain.get_height().unwrap() == height {
                    for peer in &mut self.peers.values() {
                        let res = peer
                            .write(serde_json::to_string(&result).unwrap().as_bytes())
                            .await;
                        if res.is_err() {
                            info!("Could not write to peer {:?}", peer);
                        }
                    }
                }
                let transactions = self
                    .address_cache
                    .write()
                    .await
                    .block_process(&block, height);

                self.wallet_notify(&transactions).await;
            }
        }
    }
    async fn handle_message(&mut self, message: Message) -> Result<(), crate::error::Error> {
        match message {
            Message::NewPeer((id, stream)) => {
                self.peers.insert(id, stream);
            }
            Message::Message((peer, msg)) => {
                trace!("Message: {msg}");
                if let Ok(req) = serde_json::from_str::<Request>(msg.as_str()) {
                    let peer = self.peers.get(&peer);
                    if peer.is_none() {
                        log!(
                            Level::Error,
                            "Peer sent a message but is not listed as peer"
                        );
                        return Ok(());
                    }
                    let peer = peer.unwrap().to_owned();
                    let id = req.id.to_owned();
                    let res = self.handle_blockchain_request(peer.clone(), req).await;

                    if let Ok(res) = res {
                        peer.write(serde_json::to_string(&res).unwrap().as_bytes())
                            .await?;
                    } else {
                        let res = json!({
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32000,
                                "message": "Internal JSON-RPC error.",
                                "data": null
                            },
                            "id": id
                        });
                        peer.write(serde_json::to_string(&res).unwrap().as_bytes())
                            .await?;
                    }
                }
            }
            Message::Disconnect(id) => {
                self.peers.remove(&id);
            }
        }
        Ok(())
    }

    async fn wallet_notify(&self, transactions: &[(Transaction, TxOut)]) {
        for (_, out) in transactions {
            let hash = get_spk_hash(&out.script_pubkey);
            if let Some(peer) = self.peer_addresses.get(&hash) {
                let history = self.address_cache.read().await.get_address_history(&hash);

                let status_hash = get_status(history);
                let notify = json!({
                    "jsonrpc": "2.0",
                    "method": "blockchain.scripthash.subscribe",
                    "params": [hash, status_hash]
                });
                if let Err(err) = peer
                    .write(serde_json::to_string(&notify).unwrap().as_bytes())
                    .await
                {
                    log!(Level::Error, "{err}");
                }
            }
        }
    }
}
/// Each peer get one reading loop
async fn peer_loop(
    stream: Arc<TcpStream>,
    id: u32,
    notify_channel: Sender<Message>,
) -> Result<(), std::io::Error> {
    let mut _stream = &*stream;
    let mut lines = BufReader::new(_stream).lines();
    while let Some(Ok(line)) = lines.next().await {
        notify_channel
            .send(Message::Message((id, line)))
            .await
            .expect("Main loop is broken");
    }
    log!(Level::Info, "Lost a peer");
    notify_channel
        .send(Message::Disconnect(id))
        .await
        .expect("Main loop is broken");
    Ok(())
}

pub async fn accept_loop(listener: Arc<TcpListener>, notify_channel: Sender<Message>) {
    let mut id_count = 0;
    loop {
        if let Ok((stream, _addr)) = listener.accept().await {
            info!("New client connection");
            let stream = Arc::new(stream);
            async_std::task::spawn(peer_loop(stream.clone(), id_count, notify_channel.clone()));
            let peer = Arc::new(Peer::new(stream));
            notify_channel
                .send(Message::NewPeer((id_count, peer)))
                .await
                .expect("Main loop is broken");
            id_count += 1;
        }
    }
}
/// As per electrum documentation:
/// ### To calculate the status of a script hash (or address):
///
/// 1. order confirmed transactions to the script hash by increasing height (and position in the block if there are more than one in a block)
///
/// 2. form a string that is the concatenation of strings "tx_hash:height:" for each
/// transaction in order, where:
///
///  tx_hash is the transaction hash in hexadecimal
///  height is the height of the block it is in.
///
/// 3. Next, with mempool transactions in any order, append a similar string for those
/// transactions, but where height is -1 if the transaction has at least one unconfirmed
/// input, and 0 if all inputs are confirmed.
///
/// 4. The status of the script hash is the sha256() hash of the full string expressed
/// as a hexadecimal string, or null if the string is empty because there are no
/// transactions.
fn get_status(transactions: Vec<CachedTransaction>) -> sha256::Hash {
    let mut status_preimage = String::new();
    for transaction in transactions {
        status_preimage.extend(format!("{}:{}:", transaction.hash, transaction.height).chars());
    }
    get_hash_from_u8(status_preimage.as_bytes())
}

#[macro_export]
/// Builds the response as defined by jsonrpc v2.0. Request should have type [Request] and the
/// response is always a [Json]
macro_rules! json_rpc_res {
    ($request: ident, $result: ident) => (
        Ok(json!({
            "jsonrpc": "2.0",
            "result": $result,
            "id": $request.id
        }))
    );
    ($request: ident, $result: literal) => (
        Ok(json!({
            "jsonrpc": "2.0",
            "result": $result,
            "id": $request.id
        }))
    );
    ($request: ident, $result: tt) => {
        Ok(json!({
            "jsonrpc": "2.0",
            "result": $result,
            "id": $request.id
        }))
    }
}
#[macro_export]
/// Returns and parses a value from the request json or fails with [super::error::Error::InvalidParams].
macro_rules! get_arg {
    ($request: ident, $arg_type: ty, $idx: literal) => {
        if let Some(arg) = $request.params.get($idx) {
            serde_json::from_value::<$arg_type>(arg.clone())?
        } else {
            return Err(super::error::Error::InvalidParams);
        }
    };
}
