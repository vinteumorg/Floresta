use std::{sync::Mutex, time::Instant};

use bitcoin::{network::utreexo::UtreexoBlock, Block, BlockHash, Transaction, Txid};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserRequest {
    Block(BlockHash),
    UtreexoBlock(BlockHash),
    MempoolTransaction(Txid),
    GetPeerInfo,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub address: String,
    pub services: String,
    pub user_agent: String,
    pub initial_height: u32,
}

#[derive(Debug, Clone)]
pub enum NodeResponse {
    Block(Block),
    UtreexoBlock(UtreexoBlock),
    MempoolTransaction(Transaction),
    GetPeerInfo(Vec<PeerInfo>),
}

pub trait NodeMethods {
    fn get_block(&self, block: BlockHash) -> Result<Option<Block>, oneshot::RecvError>;
    fn get_utreexo_block(
        &self,
        block: BlockHash,
    ) -> Result<Option<UtreexoBlock>, oneshot::RecvError>;
    fn get_mempool_transaction(
        &self,
        txid: Txid,
    ) -> Result<Option<Transaction>, oneshot::RecvError>;
    fn get_peer_info(&self) -> Result<Vec<PeerInfo>, oneshot::RecvError>;
}
#[derive(Debug)]
pub struct NodeInterface {
    pub(super) requests: Mutex<Vec<RequestData>>,
}
#[derive(Debug)]
pub struct RequestData {
    pub time: Instant,
    pub resolve: oneshot::Sender<Option<NodeResponse>>,
    pub req: UserRequest,
}
impl NodeInterface {
    pub fn send_answer(&self, request: UserRequest, answer: Option<NodeResponse>) {
        let mut requests = self.requests.lock().unwrap();
        let req = requests.iter().position(|x| x.req == request);
        if let Some(req) = req {
            let req = requests.remove(req);
            req.resolve.send(answer).unwrap();
        }
    }
}
impl NodeMethods for NodeInterface {
    fn get_block(&self, block: BlockHash) -> Result<Option<Block>, oneshot::RecvError> {
        let (tx, rx) = oneshot::channel();
        self.requests.lock().unwrap().push(RequestData {
            time: Instant::now(),
            resolve: tx,
            req: UserRequest::Block(block),
        });
        let blk = rx.recv()?;
        Ok(match blk {
            Some(NodeResponse::Block(blk)) => Some(blk),
            None => None,
            _ => unreachable!(),
        })
    }

    fn get_utreexo_block(
        &self,
        block: BlockHash,
    ) -> Result<Option<UtreexoBlock>, oneshot::RecvError> {
        let (tx, rx) = oneshot::channel();
        self.requests.lock().unwrap().push(RequestData {
            time: Instant::now(),
            resolve: tx,
            req: UserRequest::UtreexoBlock(block),
        });
        let blk = rx.recv()?;
        Ok(match blk {
            Some(NodeResponse::UtreexoBlock(blk)) => Some(blk),
            None => None,
            _ => unreachable!(),
        })
    }

    fn get_mempool_transaction(
        &self,
        txid: Txid,
    ) -> Result<Option<Transaction>, oneshot::RecvError> {
        let (tx, rx) = oneshot::channel();
        self.requests.lock().unwrap().push(RequestData {
            time: Instant::now(),
            resolve: tx,
            req: UserRequest::MempoolTransaction(txid),
        });
        let tx = rx.recv()?;
        Ok(match tx {
            Some(NodeResponse::MempoolTransaction(tx)) => Some(tx),
            None => None,
            _ => unreachable!(),
        })
    }

    fn get_peer_info(&self) -> Result<Vec<PeerInfo>, oneshot::RecvError> {
        let (tx, rx) = oneshot::channel();
        self.requests.lock().unwrap().push(RequestData {
            time: Instant::now(),
            resolve: tx,
            req: UserRequest::GetPeerInfo,
        });
        let peer_info = rx.recv()?;
        Ok(match peer_info {
            Some(NodeResponse::GetPeerInfo(peer_info)) => peer_info,
            None => vec![],
            _ => unreachable!(),
        })
    }
}
