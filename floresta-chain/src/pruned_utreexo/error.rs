use bitcoin::blockdata::script;
#[cfg(feature = "cli-blockchain")]
use btcd_rpc::error::UtreexodError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BlockchainError {
    #[error("Block not present")]
    BlockNotPresent,
    #[cfg(feature = "cli-blockchain")]
    #[error("Json-Rpc error")]
    JsonRpcError(#[from] UtreexodError),
    #[error("Parsing error")]
    ParsingError(bitcoin::hashes::hex::Error),
    #[error("Invalid block")]
    BlockValidationError(BlockValidationErrors),
    #[error("Invalid Proof")]
    InvalidProof,
    #[error("Utreexo Error {0}")]
    UtreexoError(String),
    #[error("Database error")]
    DatabaseError(kv::Error),
    #[error("Decoding error")]
    ConsensusDecodeError(bitcoin::consensus::encode::Error),
    #[error("This chain is not initialized")]
    ChainNotInitialized,
    #[error("We are in an invalid tip")]
    InvalidTip(String),
    #[error(transparent)]
    IoError(std::io::Error),
}

#[derive(Error, Debug)]
pub enum BlockValidationErrors {
    #[error("This block contains an invalid transaction")]
    InvalidTx,
    #[error("This block doesn't have enough proof-of-work")]
    NotEnoughPow,
    #[error("Wrong merkle root")]
    BadMerkleRoot,
    #[error("Wrong witness commitment")]
    BadWitnessCommitment,
    #[error("A transaction spends more than it should")]
    NotEnoughMoney,
    #[error("The first transaction in a block isn't a coinbase")]
    FirstTxIsnNotCoinbase,
    #[error("Coinbase claims more bitcoins than it should")]
    BadCoinbaseOutValue,
    #[error("This block is empty (doesn't have a coinbase tx)")]
    EmptyBlock,
    #[error("This block extends a chain we don't have the ancestors")]
    BlockExtendsAnOrphanChain,
    #[error("BIP34 commitment mismatch")]
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

impl From<BlockValidationErrors> for BlockchainError {
    fn from(e: BlockValidationErrors) -> Self {
        BlockchainError::BlockValidationError(e)
    }
}
