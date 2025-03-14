use std::net::IpAddr;
use std::time::Instant;

use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::Transaction;
use bitcoin::Txid;
use floresta_chain::UtreexoBlock;
use serde::Serialize;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;

use super::node::ConnectionKind;
use super::node::NodeNotification;
use super::node::PeerStatus;
use super::transport::TransportProtocol;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// A request that can be made to the node.
///
/// While the node is running, consumers may want to request some useful data, like block data,
/// mempool transactions or tell the node to connect with some given peers. This struct represents
/// all the possible requests that can be made to the node as well as the data that needs to be
/// sent along with the request.
pub enum UserRequest {
    Block(BlockHash),
    UtreexoBlock(BlockHash),
    MempoolTransaction(Txid),
    GetPeerInfo,
    Connect((IpAddr, u16)),
}

#[derive(Debug, Clone, Serialize)]
/// A struct representing a peer connected to the node.
///
/// This struct contains information about a peer connected to the node, like its address, the
/// services it provides, the user agent it's using, the height of the blockchain it's currently
/// at, its state and the kind of connection it has with the node.
pub struct PeerInfo {
    pub address: String,
    pub services: String,
    pub user_agent: String,
    pub initial_height: u32,
    pub state: PeerStatus,
    pub kind: ConnectionKind,
    pub transport_protocol: TransportProtocol,
}

#[derive(Debug, Clone)]
/// A response that can be sent back to the user.
///
/// When the user makes a request to the node, the node will respond with some data. This enum
/// represents all the possible responses that the node can send back to the user.
pub enum NodeResponse {
    Block(Option<Block>),
    UtreexoBlock(Option<UtreexoBlock>),
    MempoolTransaction(Option<Transaction>),
    GetPeerInfo(Vec<PeerInfo>),
    Connect(bool),
}

#[derive(Debug, Clone)]
/// A struct representing the interface to the node.
///
/// This struct will be used by consumers to interact with the node. You may have as many of it as
/// you need, and you can use it to send requests to the node and get responses back.
pub struct NodeInterface {
    node_sender: UnboundedSender<NodeNotification>,
}

#[derive(Debug)]
pub struct RequestData {
    pub time: Instant,
    pub resolve: oneshot::Sender<Option<NodeResponse>>,
    pub req: UserRequest,
}

impl NodeInterface {
    pub fn new(node_sender: UnboundedSender<NodeNotification>) -> Self {
        NodeInterface { node_sender }
    }

    /// Sends a request to the node.
    ///
    /// This is an iternal utility function that will be used to send requests to the node. It will
    /// send the request to the node and return a oneshot receiver that will be used to get the
    /// response back.
    async fn send_request(
        &self,
        request: UserRequest,
    ) -> Result<NodeResponse, oneshot::error::RecvError> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .node_sender
            .send(NodeNotification::FromUser(request, tx)); // Send the request to the node

        rx.await
    }
}

impl NodeInterface {
    /// Connects to a specified address and port.
    ///
    /// This function will return a boolean indicating whether the connection was successful. It
    /// may be called multiple times, and may use hostnames or IP addresses.
    pub async fn connect(
        &self,
        addr: IpAddr,
        port: u16,
    ) -> Result<bool, oneshot::error::RecvError> {
        let val = self
            .send_request(UserRequest::Connect((addr, port)))
            .await?;

        extract_variant!(Connect, val);
    }

    /// Gets a block by its hash.
    ///
    /// This function will try to get a block from the network and return it. Note that we don't
    /// keep a local copy of the blockchain, so this function will always make a network request.
    pub async fn get_block(
        &self,
        block: BlockHash,
    ) -> Result<Option<Block>, oneshot::error::RecvError> {
        let val = self.send_request(UserRequest::Block(block)).await?;

        extract_variant!(Block, val);
    }

    /// Gets a Utreexo block by its hash.
    ///
    /// This is similar to `get_block`, but it returns proof data for the Utreexo accumulator in
    /// addition to the block itself.
    pub async fn get_utreexo_block(
        &self,
        block: BlockHash,
    ) -> Result<Option<UtreexoBlock>, oneshot::error::RecvError> {
        let val = self.send_request(UserRequest::UtreexoBlock(block)).await?;

        extract_variant!(UtreexoBlock, val)
    }

    /// Gets a transaction from the mempool by its ID.
    ///
    /// This function will return a transaction from the mempool if it exists. If the transaction
    /// is not in the mempool (because it doesn't exist or because it's already been mined), this
    /// function will return `None`.
    pub async fn get_mempool_transaction(
        &self,
        txid: Txid,
    ) -> Result<Option<Transaction>, oneshot::error::RecvError> {
        let val = self
            .send_request(UserRequest::MempoolTransaction(txid))
            .await?;

        extract_variant!(MempoolTransaction, val);
    }

    /// Gets information about all connected peers.
    ///
    /// This function will return a list of `PeerInfo` structs, each of which contains information
    /// about a single peer.
    pub async fn get_peer_info(&self) -> Result<Vec<PeerInfo>, oneshot::error::RecvError> {
        let val = self.send_request(UserRequest::GetPeerInfo).await?;

        extract_variant!(GetPeerInfo, val);
    }
}

macro_rules! extract_variant {
    ($variant:ident, $var:ident) => {
        if let NodeResponse::$variant(val) = $var {
            return Ok(val);
        } else {
            panic!("Unexpected variant");
        }
    };
}

use extract_variant;
