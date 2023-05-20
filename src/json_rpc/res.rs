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

impl Into<i64> for Error {
    fn into(self) -> i64 {
        match self {
            Error::BlockNotFound => 1,
            Error::ChainError => 2,
            Error::TxNotFound => 3,
            Error::InvalidDescriptor => 4,
        }
    }
}
impl Into<ErrorCode> for Error {
    fn into(self) -> ErrorCode {
        let code = self.into();
        ErrorCode::ServerError(code)
    }
}

impl Into<jsonrpc_core::Error> for Error {
    fn into(self) -> jsonrpc_core::Error {
        jsonrpc_core::Error {
            message: format!("{:?}", self),
            code: self.into(),
            data: None,
        }
    }
}
