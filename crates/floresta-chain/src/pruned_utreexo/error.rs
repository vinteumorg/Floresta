//! This module defines error types specific to the blockchain validation and database operations, along with conversion between types.
//!
//! The main error types are:
//! - [BlockchainError]: High-level error type that encapsulates all the error kinds from our node chain backend operation.
//! - [TransactionError]: Represents errors in transaction validation
//! - [BlockValidationErrors]: Errors encountered during block validation that are not tied to any specific transaction
//!
//! Each error type implements `Display` and `Debug` for error reporting.

use core::fmt::Debug;

use bitcoin::blockdata::script;
use bitcoin::OutPoint;
use bitcoin::Txid;
use floresta_common::impl_error_from;

use crate::prelude::*;
pub trait DatabaseError: Debug + Send + Sync + 'static {}
#[derive(Debug)]
pub enum BlockchainError {
    BlockNotPresent,
    Parsing(String),
    BlockValidation(BlockValidationErrors),
    TransactionError(TransactionError),
    InvalidProof,
    UtreexoError(String),
    Database(Box<dyn DatabaseError>),
    ConsensusDecode(bitcoin::consensus::encode::Error),
    ChainNotInitialized,
    InvalidTip(String),
    ScriptValidationFailed(script::Error),
    Io(ioError),
}
#[derive(Clone, Debug, PartialEq)]
pub struct TransactionError {
    pub txid: Txid,
    pub error: BlockValidationErrors,
}

#[derive(Clone, Debug, PartialEq)]
pub enum BlockValidationErrors {
    BlockTooNew,
    BlockTooOld,
    InvalidBlockTimestamp,
    InvalidCoinbase(String),
    UtxoNotFound(OutPoint),
    ScriptValidationError(String),
    InvalidOutput,
    ScriptError,
    BlockTooBig,
    TooManyCoins,
    NotEnoughPow,
    BadMerkleRoot,
    BadWitnessCommitment,
    NotEnoughMoney,
    FirstTxIsNotCoinbase,
    BadCoinbaseOutValue,
    EmptyBlock,
    BlockExtendsAnOrphanChain,
    BadBip34,
    InvalidProof,
    CoinbaseNotMatured,
    BadRelativeBlockLock,
    BadRelativeTimeLock,
    BadAbsoluteLockTime,
}

// Helpful macro for generating a TransactionError
macro_rules! tx_err {
    ($txid_fn:expr, $variant:ident, $msg:expr) => {
        TransactionError {
            txid: ($txid_fn)(),
            error: BlockValidationErrors::$variant($msg.into()),
        }
    };
    ($txid_fn:expr, $variant:ident) => {
        TransactionError {
            txid: ($txid_fn)(),
            error: BlockValidationErrors::$variant,
        }
    };
}

impl Display for TransactionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Transaction {} is invalid: {}", self.txid, self.error)
    }
}

impl Display for BlockValidationErrors {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BlockValidationErrors::BlockTooNew => {
                write!(f, "A block is too new for the MTP at its height")
            }
            BlockValidationErrors::BlockTooOld => {
                write!(f, "A block is too old for the MTP at its height")
            }
            BlockValidationErrors::InvalidBlockTimestamp => {
                write!(f, "A block contains a invalid timestamp")
            }
            BlockValidationErrors::BadAbsoluteLockTime => {
                write!(f, "A transaction contains a invalid absolute lock time.",)
            }
            BlockValidationErrors::BadRelativeBlockLock => {
                write!(f, "this transaction contains a Block Height locked Sequence that isnt satisfied. ",)
            }
            BlockValidationErrors::BadRelativeTimeLock => {
                write!(
                    f,
                    "this transaction contains a Block Time locked Sequence that isnt satisfied. ",
                )
            }
            BlockValidationErrors::ScriptValidationError(e) => {
                write!(f, "{}", e)
            }
            BlockValidationErrors::UtxoNotFound(outpoint) => {
                write!(f, "Utxo referenced by {:?} not found", outpoint)
            }
            BlockValidationErrors::InvalidOutput => {
                write!(f, "Invalid output, verify spending values")
            }
            BlockValidationErrors::BlockTooBig => write!(f, "Block too big"),
            BlockValidationErrors::InvalidCoinbase(e) => {
                write!(f, "Invalid coinbase: {:?}", e)
            }
            BlockValidationErrors::TooManyCoins => write!(f, "Moving more coins that exists"),
            BlockValidationErrors::ScriptError => {
                write!(
                    f,
                    "Script does not follow size requirements of 2>= and <=520"
                )
            }
            BlockValidationErrors::NotEnoughPow => {
                write!(f, "This block doesn't have enough proof-of-work")
            }
            BlockValidationErrors::BadMerkleRoot => write!(f, "Wrong merkle root"),
            BlockValidationErrors::BadWitnessCommitment => write!(f, "Wrong witness commitment"),
            BlockValidationErrors::NotEnoughMoney => {
                write!(f, "A transaction spends more than it should")
            }
            BlockValidationErrors::FirstTxIsNotCoinbase => {
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
            BlockValidationErrors::CoinbaseNotMatured => {
                write!(f, "Coinbase not matured yet")
            }
        }
    }
}

impl<T: DatabaseError> From<T> for BlockchainError {
    fn from(value: T) -> Self {
        BlockchainError::Database(Box::new(value))
    }
}

impl_error_from!(BlockchainError, ioError, Io);
impl_error_from!(BlockchainError, TransactionError, TransactionError);
impl_error_from!(
    BlockchainError,
    bitcoin::consensus::encode::Error,
    ConsensusDecode
);
impl_error_from!(BlockchainError, BlockValidationErrors, BlockValidation);
impl_error_from!(BlockchainError, String, UtreexoError);
impl_error_from!(BlockchainError, script::Error, ScriptValidationFailed);

impl Display for BlockchainError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl DatabaseError for kv::Error {}
impl core2::error::Error for BlockchainError {}
