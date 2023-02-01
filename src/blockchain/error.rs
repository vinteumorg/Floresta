use bitcoin::{blockdata::script, BlockHash};
use btcd_rpc::error::UtreexodError;
#[derive(Debug)]
pub enum BlockchainError {
    BlockNotPresent,
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
}
#[derive(Debug)]
pub enum BlockValidationErrors {
    PrevBlockNotFound(BlockHash),
    InvalidTx,
    NotEnoughPow,
    BadMerkleRoot,
    BadWitnessCommitment,
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
