use floresta_chain::BlockchainError;
use thiserror::Error;

use crate::node::NodeRequest;

use super::peer::PeerError;

#[derive(Error, Debug)]
pub enum WireError {
    #[error("Blockchain error")]
    BlockchainError(#[from] BlockchainError),
    #[error("Error while writing into a channel")]
    ChannelSendError(async_std::channel::SendError<NodeRequest>),
    #[error("Peer error")]
    PeerError(PeerError),
    #[error("Coinbase didn't mature")]
    CoinbaseNotMatured,
    #[error("Peer not found in our current connections")]
    PeerNotFound,
    #[error("We don't have any peers")]
    NoPeersAvailable,
    #[error("Our peer is misbehaving")]
    PeerMisbehaving,
    #[error("Error while reading from a channel")]
    ChannelRecvError(#[from] async_std::channel::RecvError),
    #[error("Generic io error")]
    IoError(std::io::Error),
}
