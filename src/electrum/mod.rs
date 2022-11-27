use serde::{Deserialize, Serialize};

pub mod electrum_protocol;
pub mod error;
pub mod request;
#[derive(Debug, Deserialize, Serialize)]
struct TransactionHistoryEntry {
    height: u32,
    tx_hash: String,
}
