use std::fmt::Display;

use axum::response::IntoResponse;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Deserialize, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    pub data: Option<String>,
}

#[derive(Debug)]
pub enum JsonRpcError {
    /// There was a rescan request but we do not have any addresses in the watch-only wallet.
    NoAddressesToRescan,

    /// There was a rescan request with invalid values
    InvalidRescanVal,

    /// Missing parameter, e.g., if a required parameter is not provided in the request
    MissingParameter(String),

    /// The provided parameter is of the wrong type, e.g., if a string is expected but a number is
    /// provided
    InvalidParameterType(String),

    /// Verbosity level is not 0 or 1
    InvalidVerbosityLevel,

    /// The requested transaction is not found in the blockchain
    TxNotFound,

    /// The provided script is invalid, e.g., if it is not a valid P2PKH or P2SH script
    InvalidScript,

    /// The provided descriptor is invalid, e.g., if it does not match the expected format
    InvalidDescriptor,

    /// The requested block is not found in the blockchain
    BlockNotFound,

    /// There is an error with the chain, e.g., if the chain is not synced or when the chain is not valid
    Chain,

    /// The request is invalid, e.g., some parameters use an incorrect type
    InvalidRequest,

    /// The requested method is not found, e.g., if the method is not implemented or when the method is not available
    MethodNotFound,

    /// This error is returned when there is an error decoding the request, e.g., if the request is not valid JSON
    Decode(String),

    /// The provided port is invalid, e.g., when it is not a valid port number (0-65535)
    InvalidPort,

    /// The provided address is invalid, e.g., when it is not a valid IP address or hostname
    InvalidAddress,

    /// This error is returned when there is an error with the node, e.g., if the node is not connected or when the node is not responding
    Node(String),

    /// This error is returned when the node does not have block filters enabled, which is required for some RPC calls
    NoBlockFilters,

    /// This error is returned when a hex value is invalid
    InvalidHex,

    /// This error is returned when the node is in initial block download, which means it is still syncing the blockchain
    InInitialBlockDownload,

    InvalidMemInfoMode,

    /// This error is returned when there is an error with the wallet, e.g., if the wallet is not loaded or when the wallet is not available
    Wallet(String),

    /// This error is returned when there is an error with block filters, e.g., if the filters are not available or when there is an issue with the filter data
    Filters(String),

    /// This error is returned when the addnode command is invalid, e.g., if the command is not recognized or when the parameters are incorrect
    InvalidAddnodeCommand,

    /// Raised if when the rescanblockchain command, with the timestamp flag activated, contains some timestamp thats less than the genesis one and not zero which is the default value for this arg.
    InvalidTimestamp,
}

impl Display for JsonRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JsonRpcError::InvalidTimestamp => write!(f, "Invalid timestamp, ensure that it is between the genesis and the tip."),
            JsonRpcError::InvalidRescanVal => write!(f, "Your rescan request contains invalid values"),
            JsonRpcError::NoAddressesToRescan => write!(f, "You do not have any address to proceed with the rescan"),
            JsonRpcError::MissingParameter(opt) => write!(f, "Missing parameter: {opt}"),
            JsonRpcError::InvalidParameterType(opt) => write!(f, "Invalid parameter type for: {opt}"),
            JsonRpcError::InvalidRequest => write!(f, "Invalid request"),
            JsonRpcError::InvalidHex =>  write!(f, "Invalid hex"),
            JsonRpcError::MethodNotFound =>  write!(f, "Method not found"),
            JsonRpcError::Decode(e) =>  write!(f, "error decoding request: {e}"),
            JsonRpcError::TxNotFound =>  write!(f, "Transaction not found"),
            JsonRpcError::InvalidDescriptor =>  write!(f, "Invalid descriptor"),
            JsonRpcError::BlockNotFound =>  write!(f, "Block not found"),
            JsonRpcError::Chain => write!(f, "Chain error"),
            JsonRpcError::InvalidPort => write!(f, "Invalid port"),
            JsonRpcError::InvalidAddress => write!(f, "Invalid address"),
            JsonRpcError::Node(e) => write!(f, "Node error: {e}"),
            JsonRpcError::NoBlockFilters => write!(f, "You don't have block filters enabled, please start florestad without --no-cfilters to run this RPC"),
            JsonRpcError::InInitialBlockDownload => write!(f, "Node is in initial block download, wait until it's finished"),
            JsonRpcError::InvalidScript => write!(f, "Invalid script"),
            JsonRpcError::InvalidVerbosityLevel => write!(f, "Invalid verbosity level"),
            JsonRpcError::InvalidMemInfoMode => write!(f, "Invalid meminfo mode, should be stats or mallocinfo"),
            JsonRpcError::Wallet(e) => write!(f, "Wallet error: {e}"),
            JsonRpcError::Filters(e) => write!(f, "Error with filters: {e}"),
            JsonRpcError::InvalidAddnodeCommand => write!(f, "Invalid addnode command"),
        }
    }
}

impl IntoResponse for JsonRpcError {
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
