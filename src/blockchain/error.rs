#[cfg(feature = "experimental-p2p")]
use super::p2p_blockchain::node::NodeRequest;

use bitcoin::blockdata::script;

#[cfg(feature = "cli-blockchain")]
use btcd_rpc::error::UtreexodError;

#[derive(Debug)]
pub enum BlockchainError {
    BlockNotPresent,
    #[cfg(feature = "cli-blockchain")]
    JsonRpcError(UtreexodError),
    ParsingError(bitcoin::hashes::hex::Error),
    BlockValidationError(BlockValidationErrors),
    InvalidProof,
    UtreexoError(String),
    DatabaseError(kv::Error),
    ConsensusDecodeError(bitcoin::consensus::encode::Error),
    ChainNotInitialized,
    InvalidTip(String),
    IoError(std::io::Error),
    #[cfg(feature = "experimental-p2p")]
    MessageTooBig,
    #[cfg(feature = "experimental-p2p")]
    PeerMessageInvalidMagic,
    #[cfg(feature = "experimental-p2p")]
    NoPeersAvailable,
    #[cfg(feature = "experimental-p2p")]
    ChannelError(async_std::channel::SendError<NodeRequest>),
    #[cfg(feature = "experimental-p2p")]
    RecvError(async_std::channel::RecvError),
    #[cfg(feature = "experimental-p2p")]
    CoinbaseNotMatured,
    #[cfg(feature = "experimental-p2p")]
    PeerNotFound,
}

#[derive(Debug)]
pub enum BlockValidationErrors {
    InvalidTx,
    NotEnoughPow,
    BadMerkleRoot,
    BadWitnessCommitment,
    NotEnoughMoney,
    FirstTxIsnNotCoinbase,
    BadCoinbaseOutValue,
    EmptyBlock,
    BlockExtendsAnOrphanChain,
    BadBip34,
}
impl From<bitcoin::consensus::encode::Error> for BlockchainError {
    fn from(err: bitcoin::consensus::encode::Error) -> Self {
        Self::ConsensusDecodeError(err)
    }
}

impl From<kv::Error> for BlockchainError {
    fn from(err: kv::Error) -> Self {
        BlockchainError::DatabaseError(err)
    }
}
#[cfg(feature = "experimental-p2p")]
impl From<async_std::channel::SendError<NodeRequest>> for BlockchainError {
    fn from(err: async_std::channel::SendError<NodeRequest>) -> Self {
        BlockchainError::ChannelError(err)
    }
}
#[cfg(feature = "cli-blockchain")]
impl From<UtreexodError> for BlockchainError {
    fn from(err: UtreexodError) -> Self {
        BlockchainError::JsonRpcError(err)
    }
}
impl From<bitcoin::hashes::hex::Error> for BlockchainError {
    fn from(err: bitcoin::hashes::hex::Error) -> Self {
        BlockchainError::ParsingError(err)
    }
}
impl From<script::Error> for BlockchainError {
    fn from(_: script::Error) -> Self {
        BlockchainError::BlockValidationError(BlockValidationErrors::InvalidTx)
    }
}
impl From<String> for BlockchainError {
    fn from(err: String) -> Self {
        BlockchainError::UtreexoError(err)
    }
}
impl From<std::io::Error> for BlockchainError {
    fn from(e: std::io::Error) -> Self {
        BlockchainError::IoError(e)
    }
}
#[cfg(feature = "experimental-p2p")]
impl From<async_std::channel::RecvError> for BlockchainError {
    fn from(e: async_std::channel::RecvError) -> Self {
        BlockchainError::RecvError(e)
    }
}
impl From<BlockValidationErrors> for BlockchainError {
    fn from(e: BlockValidationErrors) -> Self {
        BlockchainError::BlockValidationError(e)
    }
}
