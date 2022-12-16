use bitcoin::blockdata::script;
use btcd_rpc::error::UtreexodError;
#[allow(unused)]
#[derive(Debug)]
pub enum BlockchainError {
    BlockNotPresent,
    TxNotFound,
    JsonRpcError(UtreexodError),
    ParsingError(bitcoin::hashes::hex::Error),
    BlockValidationError,
    InvalidProof,
    UtreexoError(String),
    DatabaseError(kv::Error),
    ConsensusDecodeError(bitcoin::consensus::encode::Error),
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
        BlockchainError::BlockValidationError
    }
}
impl From<String> for BlockchainError {
    fn from(err: String) -> Self {
        BlockchainError::UtreexoError(err)
    }
}
