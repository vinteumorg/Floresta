use crate::{address_cache::sqlite_storage::KvDatabase, blockchain::sync::BlockchainSync};
use crate::address_cache::AddressCache;
use crate::electrum::request::Request;
use crate::json_rpc_res;
use async_std::{
    io::BufReader,
    net::{TcpListener, TcpStream},
    prelude::*,
};

use bdk::bitcoin::hashes::hex::{FromHex, ToHex};
use bdk::bitcoin::hashes::{sha256, Hash};
use bdk::bitcoin::Script;

use btcd_rpc::client::{BTCDClient, BtcdRpc};
use log::{log, Level};
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
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
    pub address_cache: AddressCache<KvDatabase>,
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
    pub async fn new(
        address: &'static str,
        rpc: Arc<BTCDClient>,
        address_cache: AddressCache<KvDatabase>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
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
            "mempool.get_fee_histogram" => json_rpc_res!(
                request,
                [[12, 128812], [4, 92524], [2, 6478638], [1, 22890421]]
            ),
            "blockchain.scripthash.subscribe" => {
                if let Some(hash) = request.params.get(0) {
                    let hash = serde_json::from_value::<sha256::Hash>(hash.clone())
                        .map_err(|_| super::error::Error::InvalidParams)?;

                    self.peer_addresses.insert(hash, peer);
                }

                json_rpc_res!(request, null)
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
            method => {
                // TODO: Remove this when all methods are implemented
                unimplemented!("Unsupported method: {method}");
            }
        }
    }

    pub async fn main_loop(mut self) -> Result<(), std::io::Error> {
        loop {
            if let Ok(message) = self.peer_accept.recv() {
                match message {
                    Message::NewPeer((id, stream)) => {
                        self.peers.insert(id, stream);
                    }
                    Message::Message((peer, msg)) => {
                        println!("{msg}");
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
                            let res = self.handle_blockchain_request(peer.clone(), req);

                            if let Ok(res) = res {
                                peer.write(serde_json::to_string(&res).unwrap().as_bytes())
                                    .await?;
                            }
                        }
                    }
                    Message::NewBlock => {
                        println!("New Block!");
                        let best = self.rpc.getbestblock().unwrap();

                        self.address_cache.block_process(
                            &BlockchainSync::get_block(&*self.rpc, best.height as u32).unwrap(),
                            best.height as u32,
                        );
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
                    let status =
                        get_hash_from_u8(format!("{}:{height}:", transaction.txid()).as_bytes());
                    let notify = json!({
                        "jsonrpc": "2.0",
                        "method": "blockchain.scripthash.subscribe",
                        "params": [hash, status]
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
fn get_spk_hash_normal_order(spk: &Script) -> sha256::Hash {
    let script_hash = spk.as_bytes();
    let hash = sha2::Sha256::new().chain_update(script_hash).finalize();
    sha256::Hash::from_slice(hash.as_slice()).expect("Engines shouldn't be Err")
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

#[test]
fn test() {
    let hash = super::electrum_protocol::get_spk_hash(
        &Script::from_str("00142b6a2924aa9b1b115d1ac3098b0ba0e6ed510f2a").unwrap(),
    );
    println!("{}", hash.to_hex());
}
