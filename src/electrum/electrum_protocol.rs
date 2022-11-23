use crate::json_rpc_res;
use crate::{blockchain::UtreexodBackend, electrum::request::Request};
use async_std::{
    io::BufReader,
    net::{TcpListener, TcpStream},
    prelude::*,
};
use bdk::{database::Database, Wallet};
use btcd_rpc::client::{BTCDClient, BtcdRpc};
use log::debug;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{
    mpsc::{channel, Receiver, Sender},
    Arc,
};
pub struct ElectrumServer<D: Database> {
    pub chain: UtreexodBackend,
    pub wallet: Wallet<D>,
    pub rpc: Arc<BTCDClient>,
    pub listener: Option<Arc<TcpListener>>,
    pub peers: HashMap<u32, TcpStream>,
    pub peer_accept: Receiver<Message>,
    pub notify_tx: Sender<Message>,
}
pub enum Message {
    NewPeer((u32, TcpStream)),
    Message((Arc<TcpStream>, String)),
    Disconnect(u32),
    NewBlock,
}

impl<'a, D: Database + 'a> ElectrumServer<D> {
    pub async fn new(
        address: &'static str,
        wallet: Wallet<D>,
        chain: UtreexodBackend,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = Arc::new(TcpListener::bind(address).await?);
        let (tx, rx) = channel();
        Ok(ElectrumServer {
            rpc: chain.rpc.clone(),
            chain,
            wallet,
            listener: Some(listener),
            peers: HashMap::new(),
            peer_accept: rx,
            notify_tx: tx,
        })
    }
    pub fn handle_blockchain_request(
        &self,
        request: Request,
        rpc: &BTCDClient,
    ) -> Result<Value, super::error::Error> {
        match request.method.as_str() {
            "blockchain.estimatefee" => json_rpc_res!(request, 0.0001),
            "blockchain.headers.subscribe" => {
                let best = rpc.getbestblock().unwrap();
                let header = rpc.getblockheader(best.hash, false).unwrap().get_simple();
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
            "blockchain.scripthash.subscribe" => json_rpc_res!(request, null),
            "server.banner" => json_rpc_res!(request, "Welcome to Electrum"),
            "server.donation_address" => {
                json_rpc_res!(request, "38kb6SG6QL3NqajvAmAY3gT5MKkLYydUpq")
            }
            "server.ping" => json_rpc_res!(request, null),
            // TODO: Return peers?
            "server.peers.subscribe" => json_rpc_res!(request, []),
            // TODO: Ask Backend for fees
            "blockchain.relayfee" => json_rpc_res!(request, 0.00001),
            "blockchain.block.header" => {
                if let Some(height) = request.params.get(0) {
                    let hash = rpc.getblockhash(height.as_u64().unwrap_or(0) as usize)?;
                    let header = rpc.getblockheader(hash, false)?.get_simple();
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
                        if let Ok(req) = serde_json::from_str::<Request>(msg.as_str()) {
                            let mut peer = &*peer;
                            let res = self.handle_blockchain_request(req, &self.rpc);
                            if let Ok(res) = res {
                                let _ = peer
                                    .write(serde_json::to_string(&res).unwrap().as_bytes())
                                    .await?;
                                peer.write('\n'.to_string().as_bytes()).await?;
                            }
                        }
                    }
                    Message::NewBlock => {
                        println!("New Block!");
                        let best = self.rpc.getbestblock().unwrap();
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
                            peer.write('\n'.to_string().as_bytes()).await?;
                        }
                    }
                    Message::Disconnect(id) => {
                        self.peers.remove(&id);
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
            .send(Message::Message((stream.clone(), line)))
            .expect("Main loop is broken");
    }
    debug!("Lost a peer");
    let _ = notify_channel.send(Message::Disconnect(id));
    Ok(())
}
pub async fn accept_loop(listener: Arc<TcpListener>, notify_channel: Sender<Message>) {
    let mut id_count = 0;
    loop {
        if let Ok((stream, _addr)) = listener.accept().await {
            debug!("New peer");
            async_std::task::spawn(peer_loop(
                Arc::new(stream.clone()),
                id_count,
                notify_channel.clone(),
            ));
            notify_channel
                .send(Message::NewPeer((id_count, stream)))
                .expect("Main loop is broken");
            id_count += 1;
        }
    }
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
