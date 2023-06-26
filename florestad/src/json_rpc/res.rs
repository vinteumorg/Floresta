use std::fmt::Display;

use jsonrpc_core::ErrorCode;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct GetBlockchainInfoRes {
    pub best_block: String,
    pub height: u32,
    pub ibd: bool,
    pub validated: u32,
}

#[derive(Debug)]
pub enum Error {
    TxNotFound,
    InvalidDescriptor,
    BlockNotFound,
    ChainError,
}
impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Error::TxNotFound => "Transaction not found",
            Error::InvalidDescriptor => "Invalid descriptor",
            Error::BlockNotFound => "Block not found",
            Error::ChainError => "Chain error",
        };
        write!(f, "{}", msg)
    }
}
impl From<Error> for i64 {
    fn from(val: Error) -> Self {
        match val {
            Error::BlockNotFound => 1,
            Error::ChainError => 2,
            Error::TxNotFound => 3,
            Error::InvalidDescriptor => 4,
        }
    }
}
impl From<Error> for ErrorCode {
    fn from(val: Error) -> Self {
        let code = val.into();
        ErrorCode::ServerError(code)
    }
}

impl From<Error> for jsonrpc_core::Error {
    fn from(value: Error) -> Self {
        jsonrpc_core::Error {
            message: value.to_string(),
            code: value.into(),
            data: None,
        }
    }
}
