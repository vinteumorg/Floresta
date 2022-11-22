use super::ElectrumMethods;
use crate::{blockchain::UtreexodBackend, electrum::request::Request};
use async_std::{
    io::BufReader,
    net::{TcpListener, TcpStream},
    prelude::*,
};
use bdk::{database::Database, Wallet};
use btcd_rpc::client::BTCDClient;
use log::debug;
use serde_json::{json, Value};
use std::sync::{
    mpsc::{channel, Receiver, Sender},
    Arc,
};
pub struct ElectrumServer<D: Database> {
    pub chain: UtreexodBackend,
    pub wallet: Wallet<D>,
    pub rpc: Arc<BTCDClient>,
    pub listener: Option<Arc<TcpListener>>,
    pub peers: Vec<TcpStream>,
    pub peer_accept: Receiver<Message>,
    pub notify_tx: Sender<Message>,
}
pub enum Message {
    NewPeer(TcpStream),
    Message((Arc<TcpStream>, String)),
    Disconnect(Arc<TcpStream>),
}
impl<D: Database> ElectrumMethods for ElectrumServer<D> {
    fn block_headers(&self) {
        todo!()
    }

    fn estimate_fee(&self) {
        todo!()
    }

    fn relay_fee(&self) {}

    fn get_balance(&self) {
        todo!()
    }

    fn get_history(&self) {
        todo!()
    }

    fn get_mempool(&self) {
        todo!()
    }

    fn list_unspent(&self) {
        todo!()
    }
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
            peers: vec![],
            peer_accept: rx,
            notify_tx: tx,
        })
    }
    pub fn handle_blockchain_request(&self, request: Request, _rpc: &BTCDClient) -> Value {
        match request.method.as_str() {
            "blockchain.estimatefee" => json!({
                "jsonrpc": "2.0",
                "result": 0.00001,
                "id": request.id
            }),
            "blockchain.headers.subscribe" => {
                // let best = rpc.getbestblock().unwrap();
                // let header = rpc.getblock(best.hash, true).unwrap();
                // if let VerbosityOutput::Verbose(block) = header {
                json!({
                    "jsonrpc": "2.0",
                    "result": {
                        "height": 117945,
                        "hex": "000000206fb558443b56cc83b00644616ac781a01dff45ded0040afa8f28e25e0c01000000dd35d4516fdce3ff8c5ae4a41a82769e9e7015c32065742f1a0839ff6d44cd611c7c633c4b011ef1a57d00"
                    },
                    "id": request.id
                })
                // } else {
                //     json!({
                //         "jsonrpc": "2.0",
                //         "result": {
                //             "height": 0,
                //             "hex": ""
                //         },
                //         "id": request.id
                //     })
                // }
            }
            "server.version" => json!({
                "jsonrpc": "2.0",
                "result": ["ElectrumX 1.16.0", "1.4"],
                "id": request.id
            }
            ),
            "mempool.get_fee_histogram" => json!({
                "jsonrpc": "2.0",
                "result": [[12, 128812], [4, 92524], [2, 6478638], [1, 22890421]],
                "id": request.id
            }),
            "blockchain.scripthash.subscribe" => json!({
                "jsonrpc": "2.0",
                "result": null,
                "id": request.id
            }),
            "server.banner" => json!({
                "jsonrpc": "2.0",
                "result": "Welcome tho Electrum!",
                "id": request.id
            }),
            "server.donation_address" => json!({
                "jsonrpc": "2.0",
                "result": "38kb6SG6QL3NqajvAmAY3gT5MKkLYydUpq",
                "id": request.id
            }),
            "server.peers.subscribe" => json!({
                "jsonrpc": "2.0",
                "result": [],
                "id": request.id
            }),
            "blockchain.relayfee" => json!({
                "jsonrpc": "2.0",
                "result": 0.00001,
                "id": request.id
            }),
            _ => {
                unimplemented!("Unsupported method");
            }
        }
    }

    pub async fn main_loop(mut self) -> Result<(), std::io::Error> {
        loop {
            if let Ok(message) = self.peer_accept.recv() {
                match message {
                    Message::NewPeer(stream) => self.peers.push(stream),
                    Message::Message((peer, msg)) => {
                        debug!("Got message: {msg}");

                        if let Ok(req) = serde_json::from_str::<Request>(msg.as_str()) {
                            let mut peer = &*peer;
                            let res = self.handle_blockchain_request(req, &self.rpc);
                            let _ = peer
                                .write(serde_json::to_string(&res).unwrap().as_bytes())
                                .await?;
                            peer.write('\n'.to_string().as_bytes()).await?;
                        }
                    }
                    _ => debug!("Unknown message"),
                }
            }
        }
    }
}
/// Each peer get one reading loop
async fn peer_loop(
    stream: Arc<TcpStream>,
    notify_channel: Sender<Message>,
) -> Result<(), std::io::Error> {
    let mut _stream = &*stream;

    while let Some(Ok(line)) = BufReader::new(_stream).lines().next().await {
        notify_channel
            .send(Message::Message((stream.clone(), line)))
            .expect("Main loop is broken");
    }
    debug!("Lost a peer");
    let _ = notify_channel.send(Message::Disconnect(stream));
    Ok(())
}
pub async fn accept_loop(listener: Arc<TcpListener>, notify_channel: Sender<Message>) {
    loop {
        if let Ok((stream, _addr)) = listener.accept().await {
            debug!("New peer");
            async_std::task::spawn(peer_loop(Arc::new(stream.clone()), notify_channel.clone()));
            notify_channel
                .send(Message::NewPeer(stream))
                .expect("Main loop is broken");
        }
    }
}
