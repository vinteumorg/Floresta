use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::{self};
use std::io;

use floresta_chain::BlockchainError;
use floresta_common::impl_error_from;
use floresta_compact_filters::IteratableFilterStoreError;
use thiserror::Error;

use super::peer::PeerError;
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
    #[error("Generic io error")]
    Io(std::io::Error),
    #[error("We don't have any utreexo peers")]
    NoUtreexoPeersAvailable,
    #[error("We couldn't find a peer to send the request")]
    NoPeerToSendRequest,
    #[error("Peer timed out")]
    PeerTimeout,
    #[error("Compact block filters error")]
    CompactBlockFiltersError(IteratableFilterStoreError),
    #[error("Poisoned lock")]
    PoisonedLock,
    #[error("We couldn't parse the provided address due to: {0}")]
    InvalidAddress(AddrParseError),
}

impl_error_from!(WireError, PeerError, PeerError);
impl_error_from!(WireError, BlockchainError, Blockchain);
impl_error_from!(
    WireError,
    IteratableFilterStoreError,
    CompactBlockFiltersError
);
impl_error_from!(WireError, AddrParseError, InvalidAddress);

impl From<tokio::sync::mpsc::error::SendError<NodeRequest>> for WireError {
    fn from(error: tokio::sync::mpsc::error::SendError<NodeRequest>) -> Self {
        WireError::ChannelSend(error)
    }
}

impl From<io::Error> for WireError {
    fn from(err: io::Error) -> WireError {
        WireError::Io(err)
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
