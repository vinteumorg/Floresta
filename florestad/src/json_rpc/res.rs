use std::fmt::Display;

use jsonrpc_core::ErrorCode;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct GetBlockchainInfoRes {
    pub best_block: String,
    pub height: u32,
    pub ibd: bool,
    pub validated: u32,
    pub latest_work: String,
    pub latest_block_time: u32,
    pub leaf_count: u32,
    pub root_count: u32,
    pub root_hashes: Vec<String>,
    pub chain: String,
    pub progress: f32,
    pub difficulty: u64,
}
#[derive(Deserialize, Serialize)]
pub struct RawTxJson {
    pub in_active_chain: bool,
    pub hex: String,
    pub txid: String,
    pub hash: String,
    pub size: u32,
    pub vsize: u32,
    pub weight: u32,
    pub version: u32,
    pub locktime: u32,
    pub vin: Vec<TxInJson>,
    pub vout: Vec<TxOutJson>,
    pub blockhash: String,
    pub confirmations: u32,
    pub blocktime: u32,
    pub time: u32,
}
#[derive(Deserialize, Serialize)]
pub struct TxOutJson {
    pub value: u64,
    pub n: u32,
    pub script_pub_key: ScriptPubKeyJson,
}
#[derive(Deserialize, Serialize)]
pub struct ScriptPubKeyJson {
    pub asm: String,
    pub hex: String,
    pub req_sigs: u32,
    #[serde(rename = "type")]
    pub type_: String,
    pub address: String,
}
#[derive(Deserialize, Serialize)]
pub struct TxInJson {
    pub txid: String,
    pub vout: u32,
    pub script_sig: ScriptSigJson,
    pub sequence: u32,
    pub witness: Vec<String>,
}
#[derive(Deserialize, Serialize)]
pub struct ScriptSigJson {
    pub asm: String,
    pub hex: String,
}
#[derive(Deserialize, Serialize)]
pub struct BlockJson {
    pub hash: String,
    pub confirmations: u32,
    pub strippedsize: usize,
    pub size: usize,
    pub weight: usize,
    pub height: u32,
    pub version: i32,
    #[serde(rename = "versionHex")]
    pub version_hex: String,
    pub merkleroot: String,
    pub tx: Vec<String>,
    pub time: u32,
    pub mediantime: u32,
    pub nonce: u32,
    pub bits: String,
    pub difficulty: u64,
    pub chainwork: String,
    pub n_tx: usize,
    pub previousblockhash: String,
    pub nextblockhash: Option<String>,
}

#[derive(Debug)]
pub enum Error {
    TxNotFound,
    InvalidDescriptor,
    BlockNotFound,
    ChainError,
    InvalidPort,
    InvalidAddress,
    WalletError,
    IoError,
}
impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Error::TxNotFound => "Transaction not found",
            Error::InvalidDescriptor => "Invalid descriptor",
            Error::BlockNotFound => "Block not found",
            Error::ChainError => "Chain error",
            Error::InvalidPort => "Invalid port",
            Error::InvalidAddress => "Invalid address",
            Error::WalletError => "Wallet errror",
            Error::IoError => "I/O Error",
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
            Error::InvalidPort => 5,
            Error::InvalidAddress => 6,
            Error::WalletError => 7,
            Error::IoError => 8,
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

impl From<std::io::Error> for Error {
    fn from(_value: std::io::Error) -> Self {
        Error::IoError
    }
}
