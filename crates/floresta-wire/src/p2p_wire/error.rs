use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::{self};
use std::io;

use floresta_chain::BlockchainError;
use floresta_common::impl_error_from;
use floresta_compact_filters::IterableFilterStoreError;
use thiserror::Error;

use super::peer::PeerError;
use super::transport::TransportError;
use crate::node::NodeRequest;

#[derive(Error, Debug)]
pub enum WireError {
    #[error("Blockchain error")]
    Blockchain(BlockchainError),
    #[error("Error while writing into a channel")]
    ChannelSend(tokio::sync::mpsc::error::SendError<NodeRequest>),
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
    #[error("Failed to init peers, anchors.json does not exist yet.")]
    AnchorFileNotFound,
    #[error("Generic io error: {0}")]
    Io(std::io::Error),
    #[error("{0}")]
    Serde(serde_json::Error),
    #[error("We don't have any utreexo peers")]
    NoUtreexoPeersAvailable,
    #[error("We couldn't find a peer to send the request")]
    NoPeerToSendRequest,
    #[error("Peer timed out")]
    PeerTimeout,
    #[error("Compact block filters error")]
    CompactBlockFiltersError(IterableFilterStoreError),
    #[error("Poisoned lock")]
    PoisonedLock,
    #[error("We couldn't parse the provided address due to: {0}")]
    InvalidAddress(AddrParseError),
    #[error("Transport error: {0}")]
    Transport(TransportError),
}

impl_error_from!(WireError, PeerError, PeerError);
impl_error_from!(WireError, BlockchainError, Blockchain);
impl_error_from!(
    WireError,
    IterableFilterStoreError,
    CompactBlockFiltersError
);
impl_error_from!(WireError, AddrParseError, InvalidAddress);

impl From<tokio::sync::mpsc::error::SendError<NodeRequest>> for WireError {
    fn from(error: tokio::sync::mpsc::error::SendError<NodeRequest>) -> Self {
        WireError::ChannelSend(error)
    }
}

impl From<serde_json::Error> for WireError {
    fn from(err: serde_json::Error) -> WireError {
        WireError::Serde(err)
    }
}

impl From<io::Error> for WireError {
    fn from(err: io::Error) -> WireError {
        WireError::Io(err)
    }
}

impl From<TransportError> for WireError {
    fn from(e: TransportError) -> Self {
        match e {
            TransportError::Io(io) => WireError::Io(io),
            other => WireError::Transport(other),
        }
    }
}

#[derive(Debug, Clone)]
pub enum AddrParseError {
    InvalidIpv6,
    InvalidIpv4,
    InvalidHostname,
    InvalidPort,
    Inconclusive,
}

impl Display for AddrParseError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            AddrParseError::InvalidIpv6 => write!(f, "Invalid ipv6"),
            AddrParseError::InvalidIpv4 => write!(f, "Invalid ipv4"),
            AddrParseError::InvalidHostname => write!(f, "Invalid hostname"),
            AddrParseError::InvalidPort => write!(f, "Invalid port"),
            AddrParseError::Inconclusive => write!(f, "Inconclusive"),
        }
    }
}
