use crate::address_cache::{AddressCache, CachedTransaction};
use crate::blockchain::chainstore::KvChainStore;
use crate::electrum::request::Request;
use crate::electrum::TransactionHistoryEntry;
use crate::{address_cache::kv_database::KvDatabase, blockchain::sync::BlockchainSync};
use crate::{get_arg, json_rpc_res};
use async_std::{
    io::BufReader,
    net::{TcpListener, TcpStream},
    prelude::*,
};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::{Script, Txid};

use btcd_rpc::client::{BTCDClient, BtcdRpc};
use log::{log, trace, Level};
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::{HashMap, HashSet};
use std::sync::{
    mpsc::{channel, Receiver, Sender},
    Arc,
};

#[derive(Debug, Clone)]
pub struct Peer {
    _addresses: HashSet<Script>,
    stream: Option<Arc<TcpStream>>,
}
impl Default for Peer {
    fn default() -> Self {
        Peer {
            _addresses: HashSet::new(),
            stream: None,
        }
    }
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
pub struct ElectrumServer {
    pub rpc: Arc<BTCDClient>,
    pub address_cache: AddressCache<KvDatabase, KvChainStore>,
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
    NewBlock,
}

impl ElectrumServer {
    pub async fn new<'a>(
        address: &'static str,
        rpc: Arc<BTCDClient>,
        address_cache: AddressCache<KvDatabase, KvChainStore>,
    ) -> Result<ElectrumServer, Box<dyn std::error::Error>> {
        let listener = Arc::new(TcpListener::bind(address).await?);
        let (tx, rx) = channel();
        Ok(ElectrumServer {
            rpc,
            address_cache,
            listener: Some(listener),
            peers: HashMap::new(),
            peer_accept: rx,
            notify_tx: tx,
            peer_addresses: HashMap::new(),
        })
    }
    pub fn handle_blockchain_request(
        &mut self,
        peer: Arc<Peer>,
        request: Request,
    ) -> Result<Value, super::error::Error> {
        match request.method.as_str() {
            "blockchain.estimatefee" => json_rpc_res!(request, 0.0001),
            "blockchain.headers.subscribe" => {
                let best = self.rpc.getbestblock().unwrap();
                let header = self
                    .rpc
                    .getblockheader(best.hash, false)
                    .unwrap()
                    .get_simple();
                let result = json!({
                    "height": best.height,
                    "hex": header
                });
                json_rpc_res!(request, result)
            }
            "server.version" => json_rpc_res!(request, ["ElectrumX 1.16.0", "1.4"]),
            // TODO: Create an actual histogram
            "mempool.get_fee_histogram" => json_rpc_res!(request, []),
            "blockchain.scripthash.subscribe" => {
                if let Some(hash) = request.params.get(0) {
                    let hash = serde_json::from_value::<sha256::Hash>(hash.clone())?;
                    self.peer_addresses.insert(hash, peer);

                    let history = self.address_cache.get_address_history(&hash);

                    if history.is_empty() {
                        return json_rpc_res!(request, null);
                    }
                    let status_hash = get_status(history);
                    return json_rpc_res!(request, status_hash);
                }

                Err(super::error::Error::InvalidParams)
            }
            "server.banner" => json_rpc_res!(request, "Welcome to Electrum"),
            "server.donation_address" => {
                json_rpc_res!(request, "bcrt1q9d4zjf92nvd3zhg6cvyckzaqumk4zre2c0k8hv")
            }
            "server.ping" => json_rpc_res!(request, null),
            // TODO: Return peers?
            "server.peers.subscribe" => json_rpc_res!(request, []),
            // TODO: Ask Backend for fees
            "blockchain.relayfee" => json_rpc_res!(request, 0.00001),
            "blockchain.block.header" => {
                if let Some(height) = request.params.get(0) {
                    let hash = self
                        .rpc
                        .getblockhash(height.as_u64().unwrap_or(0) as usize)?;
                    let header = self.rpc.getblockheader(hash, false)?.get_simple();
                    json_rpc_res!(request, header)
                } else {
                    Err(super::error::Error::InvalidParams)
                }
            }
            "blockchain.block.headers" => {
                let start_height = get_arg!(request, u64, 0);
                let count = get_arg!(request, u64, 1);
                let mut headers = String::new();
                let count = if count < 2016 { count } else { 2016 };
                for height in start_height..(start_height + count) {
                    let hash = self.rpc.getblockhash(height as usize)?;
                    let header = self.rpc.getblockheader(hash, false)?.get_simple();
                    headers.extend(header.chars().into_iter());
                }
                json_rpc_res!(request, {
                    "count": count,
                    "hex": headers,
                    "max": 2016
                })
            }
            "blockchain.scripthash.get_history" => {
                if let Some(script_hash) = request.params.get(0) {
                    let script_hash =
                        serde_json::from_value::<sha256::Hash>(script_hash.to_owned())?;
                    let transactions = self.address_cache.get_address_history(&script_hash);
                    let mut res = vec![];
                    for transaction in transactions {
                        let entry = TransactionHistoryEntry {
                            tx_hash: transaction.hash,
                            height: transaction.height,
                        };
                        res.push(entry);
                    }

                    return json_rpc_res!(request, res);
                }

                Err(super::error::Error::InvalidParams)
            }
            "blockchain.transaction.broadcast" => {
                let tx = get_arg!(request, String, 0);
                let hex = self.rpc.sendrawtransaction(tx)?;
                json_rpc_res!(request, hex)
            }
            "blockchain.transaction.get" => {
                if let Some(script_hash) = request.params.get(0) {
                    let tx_id = serde_json::from_value::<Txid>(script_hash.to_owned())?;
                    let tx = self.address_cache.get_cached_transaction(&tx_id);
                    if let Some(tx) = tx {
                        return json_rpc_res!(request, tx);
                    }
                }
                Err(super::error::Error::InvalidParams)
            }
            "blockchain.transaction.get_merkle" => {
                if let Some(script_hash) = request.params.get(0) {
                    let tx_id = serde_json::from_value::<Txid>(script_hash.to_owned());
                    let tx_id = tx_id?;
                    let proof = self.address_cache.get_merkle_proof(&tx_id);
                    let height = self.address_cache.get_height(&tx_id);

                    if let Some((proof, position)) = proof {
                        let result = json!({
                            "merkle": proof,
                            "block_height": height.unwrap_or(0),
                            "pos": position
                        });
                        return json_rpc_res!(request, result);
                    }
                }
                Err(super::error::Error::InvalidParams)
            }
            "blockchain.scripthash.get_balance" => {
                if let Some(script_hash) = request.params.get(0) {
                    let script_hash =
                        serde_json::from_value::<sha256::Hash>(script_hash.to_owned())?;
                    let balance = self.address_cache.get_address_balance(&script_hash);
                    let result = json!({
                        "confirmed": balance,
                        "unconfirmed": 0
                    });
                    return json_rpc_res!(request, result);
                }
                Err(super::error::Error::InvalidParams)
            }
            method => {
                // TODO: Remove this when all methods are implemented
                unimplemented!("Unsupported method: {method}");
            }
        }
    }

    pub async fn main_loop(mut self) -> Result<(), crate::error::Error> {
        loop {
            if let Ok(message) = self.peer_accept.recv() {
                match message {
                    Message::NewPeer((id, stream)) => {
                        self.peers.insert(id, stream);
                    }
                    Message::Message((peer, msg)) => {
                        trace!("Message: {msg}");
                        if let Ok(req) = serde_json::from_str::<Request>(msg.as_str()) {
                            let peer = self.peers.get(&peer);
                            if let None = peer {
                                log!(
                                    Level::Error,
                                    "Peer sent a message but is not listed as peer"
                                );
                                continue;
                            }
                            let peer = peer.unwrap().to_owned();
                            let id = req.id;
                            let res = self.handle_blockchain_request(peer.clone(), req);

                            if let Ok(res) = res {
                                peer.write(serde_json::to_string(&res).unwrap().as_bytes())
                                    .await?;
                            } else {
                                let res = json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "error":"Unknown",
                                    "data": null
                                });
                                peer.write(serde_json::to_string(&res).unwrap().as_bytes())
                                    .await?;
                            }
                        }
                    }
                    Message::NewBlock => {
                        log!(Level::Debug, "New Block!");
                        let best = self.rpc.getbestblock().unwrap();
                        let limits = self.address_cache.get_sync_limits(best.height as u32)?;

                        BlockchainSync::sync_range(&*self.rpc, &mut self.address_cache, limits)?;
                        let header = self
                            .rpc
                            .getblockheader(best.hash, false)
                            .unwrap()
                            .get_simple();
                        let result = json!({
                            "jsonrpc": "2.0",
                            "method": "blockchain.headers.subscribe",
                            "params": [{
                                "height": best.height,
                                "hex": header
                            }]
                        });
                        for (_, peer) in &mut self.peers {
                            let _ = peer
                                .write(serde_json::to_string(&result).unwrap().as_bytes())
                                .await?;
                        }
                        self.wallet_notify(best.height as u32).await;
                    }
                    Message::Disconnect(id) => {
                        self.peers.remove(&id);
                    }
                }
            }
        }
    }
    async fn wallet_notify(&self, height: u32) {
        let block = BlockchainSync::get_block(&*self.rpc, height);
        if let Err(err) = block {
            log!(Level::Error, "Got an error while loading block {}", err);
            return;
        }
        for transaction in block.unwrap().txdata {
            for out in transaction.output.iter() {
                let hash = get_spk_hash(&out.script_pubkey);

                if let Some(peer) = self.peer_addresses.get(&hash) {
                    let hash = get_spk_hash(&out.script_pubkey);
                    let history = self.address_cache.get_address_history(&hash);

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
            .expect("Main loop is broken");
    }
    log!(Level::Info, "Lost a peer");
    let _ = notify_channel.send(Message::Disconnect(id));
    Ok(())
}

pub async fn accept_loop(listener: Arc<TcpListener>, notify_channel: Sender<Message>) {
    let mut id_count = 0;
    loop {
        if let Ok((stream, _addr)) = listener.accept().await {
            log!(Level::Info, "New peer");
            let stream = Arc::new(stream);
            async_std::task::spawn(peer_loop(stream.clone(), id_count, notify_channel.clone()));
            let peer = Arc::new(Peer::new(stream));
            notify_channel
                .send(Message::NewPeer((id_count, peer)))
                .expect("Main loop is broken");
            id_count += 1;
        }
    }
}

fn get_hash_from_u8(data: &[u8]) -> sha256::Hash {
    let hash = sha2::Sha256::new().chain_update(data).finalize();
    sha256::Hash::from_slice(hash.as_slice()).expect("Engines shouldn't be Err")
}
pub fn get_spk_hash(spk: &Script) -> sha256::Hash {
    let script_hash = spk.as_bytes();
    let mut hash = sha2::Sha256::new().chain_update(script_hash).finalize();
    hash.reverse();
    sha256::Hash::from_slice(hash.as_slice()).expect("Engines shouldn't be Err")
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
        status_preimage.extend(
            format!("{}:{}:", transaction.hash, transaction.height)
                .chars()
                .into_iter(),
        );
    }
    get_hash_from_u8(status_preimage.as_bytes())
}
#[macro_export]
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
macro_rules! get_arg {
    ($request: ident, $arg_type: ty, $idx: literal) => {
        if let Some(arg) = $request.params.get($idx) {
            serde_json::from_value::<$arg_type>(arg.clone())?
        } else {
            return Err(super::error::Error::InvalidParams);
        }
    };
}
