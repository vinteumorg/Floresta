use crate::prelude::*;

use bitcoin::blockdata::script;
#[cfg(feature = "cli-blockchain")]
use btcd_rpc::error::UtreexodError;
use core::fmt::Debug;
use floresta_common::impl_error_from;
pub trait DatabaseError: Debug + Send + Sync + 'static {}
#[derive(Debug)]
pub enum BlockchainError {
    BlockNotPresent,
    #[cfg(feature = "cli-blockchain")]
    #[error("Json-Rpc error")]
    JsonRpcError(#[from] UtreexodError),
    ParsingError(bitcoin::hashes::hex::Error),
    BlockValidationError(BlockValidationErrors),
    InvalidProof,
    UtreexoError(String),
    DatabaseError(Box<dyn DatabaseError>),
    ConsensusDecodeError(bitcoin::consensus::encode::Error),
    ChainNotInitialized,
    InvalidTip(String),
    ScriptValidationFailed(script::Error),
    IoError(ioError),
}

#[derive(Clone, Debug, PartialEq)]
pub enum BlockValidationErrors {
    InvalidTx(String),
    NotEnoughPow,
    BadMerkleRoot,
    BadWitnessCommitment,
    NotEnoughMoney,
    FirstTxIsnNotCoinbase,
    BadCoinbaseOutValue,
    EmptyBlock,
    BlockExtendsAnOrphanChain,
    BadBip34,
    InvalidProof,
}
impl Display for BlockValidationErrors {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BlockValidationErrors::InvalidTx(e) => {
                write!(f, "This block contains an invalid transaction {}", e)
            }
            BlockValidationErrors::NotEnoughPow => {
                write!(f, "This block doesn't have enough proof-of-work")
            }
            BlockValidationErrors::BadMerkleRoot => write!(f, "Wrong merkle root"),
            BlockValidationErrors::BadWitnessCommitment => write!(f, "Wrong witness commitment"),
            BlockValidationErrors::NotEnoughMoney => {
                write!(f, "A transaction spends more than it should")
            }
            BlockValidationErrors::FirstTxIsnNotCoinbase => {
                write!(f, "The first transaction in a block isn't a coinbase")
            }
            BlockValidationErrors::BadCoinbaseOutValue => {
                write!(f, "Coinbase claims more bitcoins than it should")
            }
            BlockValidationErrors::EmptyBlock => {
                write!(f, "This block is empty (doesn't have a coinbase tx)")
            }
            BlockValidationErrors::BlockExtendsAnOrphanChain => {
                write!(f, "This block extends a chain we don't have the ancestors")
            }
            BlockValidationErrors::BadBip34 => write!(f, "BIP34 commitment mismatch"),
            BlockValidationErrors::InvalidProof => write!(f, "Invalid proof"),
        }
    }
}

impl<T: DatabaseError> From<T> for BlockchainError {
    fn from(value: T) -> Self {
        BlockchainError::DatabaseError(Box::new(value))
    }
}

impl_error_from!(BlockchainError, ioError, IoError);
impl_error_from!(
    BlockchainError,
    bitcoin::consensus::encode::Error,
    ConsensusDecodeError
);
impl_error_from!(BlockchainError, BlockValidationErrors, BlockValidationError);
impl_error_from!(BlockchainError, bitcoin::hashes::hex::Error, ParsingError);
impl_error_from!(BlockchainError, String, UtreexoError);
impl_error_from!(BlockchainError, script::Error, ScriptValidationFailed);

impl DatabaseError for kv::Error {}
