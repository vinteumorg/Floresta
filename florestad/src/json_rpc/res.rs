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

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum GetBlockRes {
    Verbose(Box<GetBlockResVerbose>),
    Serialized(String),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    pub data: Option<String>,
}

/// A full bitcoin block, returned by get_block
#[derive(Debug, Deserialize, Serialize)]
pub struct GetBlockResVerbose {
    /// This block's hash.
    pub hash: String,
    /// How many blocks have been added to the chain, after this one have been found. This is
    /// inclusive, so it starts with one when this block is the latest. If another one is found,
    /// then it increments to 2 and so on...
    pub confirmations: u32,
    /// The size of this block, without the witness
    pub strippedsize: usize,
    /// This block's size, with the witness
    pub size: usize,
    /// This block's weight.
    ///
    /// Data inside a segwit block is counted differently, 'base data' has a weight of 4, while
    /// witness only counts 1. This is (3 * base_size) + size
    pub weight: usize,
    /// How many blocks there are before this block
    pub height: u32,
    /// This block's version field
    ///
    /// Currently, blocks have version 2 (see BIP34), but it may also flip some of the LSB for
    /// either consensus reason (see BIPs 8 and 9) or for version rolling mining, usually bits
    /// after the 24th are not touched. Therefore, the actual version is likely the result of
    /// version & ~(1 << 24).
    /// This is encoded as a number, see `version_hex` for a hex-encoded version
    pub version: i32,
    #[serde(rename = "versionHex")]
    /// Same as `version` by hex-encoded
    pub version_hex: String,
    /// This block's merkle root
    ///
    /// A Merkle Tree is a binary tree where every leaf is some data, and the branches are pairwise
    /// hashes util reaching the root. This allows for compact proof of inclusion in the original
    /// set. This merkle tree commits to the txid of all transactions in a block, and is used by
    /// some light clients to determine whether a transaction is in a given block
    pub merkleroot: String,
    /// A list of hex-encoded transaction id for the tx's in this block
    pub tx: Vec<String>,
    /// The timestamp committed to in this block's header
    ///
    /// Since there's no central clock that can tell time precisely in Bitcoin, this value is
    /// reported by miners and only constrained by a couple of consensus rules. More sensibly, it
    /// is **not** guaranteed to be monotonical. So a block n might have a lower timestamp than
    /// block `n - 1`.
    /// If you need it to be monotonical, see `mediantime` instead
    pub time: u32,
    /// The meadian of the last 11 blocktimes.
    ///
    /// This is a monotonically increasing number that bounds how old a block can be. Blocks may
    /// not have a timestamp less than the current `mediantime`. This is also used in relative
    /// timelocks.
    pub mediantime: u32,
    /// The nonce used to mine this block.
    ///
    /// Blocks are mined by increasing this value until you find a hash that is less than a network
    /// defined target. This number has no meaning in itself and is just a random u32.
    pub nonce: u32,
    /// Bits is a compact representation for the target.
    ///
    /// This is a exponential format (with well-define rounding) used by openssl that Satoshi
    /// decided to make consensus critical :/
    pub bits: String,
    /// The difficulty is derived from the current target and is defined as how many hashes, on
    /// average, one has to make before finding a valid block
    ///
    /// This is computed as 1 / (target / 2 ^ 256). In most software (this one included) the
    /// difficulty is a multiple of the smallest possible difficulty. So to find the actual
    /// difficulty you have to multiply this by the min_diff.
    /// For mainnet, mindiff is 2 ^ 32
    pub difficulty: u128,
    /// Commullative work in this network
    ///
    /// This is a estimate of how many hashes the network has ever made to produce this chain
    pub chainwork: String,
    /// How many transactions in this block
    pub n_tx: usize,
    /// The hash of the block coming before this one
    pub previousblockhash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The hash of the block coming after this one, if any
    pub nextblockhash: Option<String>,
}

#[derive(Debug)]
pub enum Error {
    MissingParams,
    MissingReq,
    InvalidVerbosityLevel,
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
    InvalidMemInfoMode,
    Wallet(String),
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
            Error::InvalidVerbosityLevel => write!(f, "Invalid verbosity level"),
            Error::InvalidMemInfoMode => write!(f, "Invalid meminfo mode, should be stats or mallocinfo"),
            Error::Wallet(e) => write!(f, "Wallet error: {}", e),
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
