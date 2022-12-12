use bitcoin::blockdata::script;
use btcd_rpc::error::UtreexodError;

#[derive(Debug)]
pub enum BlockchainError {
    BlockNotPresent,
    _TxNotFound,
    JsonRpcError(UtreexodError),
    ParsingError(bitcoin::hashes::hex::Error),
    BlockValidationError,
    InvalidProof,
    UtreexoError(String),
    _UnknownError(Box<dyn std::error::Error>),
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