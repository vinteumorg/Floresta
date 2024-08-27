// SPDX-License-Identifier: MIT

use serde::Deserialize;
use serde::Serialize;

pub mod electrum_protocol;
pub mod error;
pub mod request;
#[derive(Debug, Deserialize, Serialize)]
struct TransactionHistoryEntry {
    height: u32,
    tx_hash: String,
}
#[derive(Debug, Deserialize, Serialize)]
struct MempoolTransaction {
    height: u32,
    tx_hash: String,
    fee: u32,
}
