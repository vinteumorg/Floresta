use std::fmt::Display;

use axum::response::IntoResponse;
use serde::Deserialize;
use serde::Serialize;

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
    pub difficulty: u128,
    pub chainwork: String,
    pub n_tx: usize,
    pub previousblockhash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nextblockhash: Option<String>,
}

#[derive(Debug)]
pub enum Error {
    MissingParams,
    MissingReq,
    TxNotFound,
    InvalidScript,
    InvalidDescriptor,
    BlockNotFound,
    Chain,
    InvalidVout,
    InvalidHeight,
    InvalidHash,
    InvalidRequest,
    MethodNotFound,
    Decode(String),
    InvalidPort,
    InvalidAddress,
    Node(String),
    NoBlockFilters,
    InvalidNetwork,
    InvalidHex,
    InInitialBlockDownload,
    Encode,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidRequest => write!(f, "Invalid request"),
            Error::InvalidHeight => write!(f, "Invalid height"),
            Error::InvalidHash =>  write!(f, "Invalid hash"),
            Error::InvalidHex =>  write!(f, "Invalid hex"),
            Error::InvalidVout =>  write!(f, "Invalid vout"),
            Error::MethodNotFound =>  write!(f, "Method not found"),
            Error::Decode(e) =>  write!(f, "error decoding request: {}", e),
            Error::TxNotFound =>  write!(f, "Transaction not found"),
            Error::InvalidDescriptor =>  write!(f, "Invalid descriptor"),
            Error::BlockNotFound =>  write!(f, "Block not found"),
            Error::Chain => write!(f, "Chain error"),
            Error::InvalidPort => write!(f, "Invalid port"),
            Error::InvalidAddress => write!(f, "Invalid address"),
            Error::Node(e) => write!(f, "Node error: {}", e),
            Error::NoBlockFilters => write!(f, "You don't have block filters enabled, please start florestad with --cfilters to run this RPC"),
            Error::InvalidNetwork => write!(f, "Invalid network"),
            Error::InInitialBlockDownload => write!(f, "Node is in initial block download, wait until it's finished"),
            Error::Encode => write!(f, "Error encoding response"),
            Error::InvalidScript => write!(f, "Invalid script"),
            Error::MissingParams => write!(f, "Missing params field"),
            Error::MissingReq => write!(f, "Missing request field"),
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::http::Response<axum::body::Body> {
        let body = serde_json::json!({
            "error": self.to_string(),
            "result": serde_json::Value::Null,
            "id": serde_json::Value::Null,
        });
        axum::http::Response::builder()
            .status(axum::http::StatusCode::BAD_REQUEST)
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }
}
