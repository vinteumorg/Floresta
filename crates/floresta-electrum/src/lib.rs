// SPDX-License-Identifier: MIT

#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(clippy::manual_is_multiple_of)]

use serde::Deserialize;
use serde::Serialize;

pub mod electrum_protocol;
pub mod error;
pub mod request;

#[derive(Debug, Deserialize, Serialize)]
pub struct TransactionHistoryEntry {
    height: u32,
    tx_hash: String,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct MempoolTransaction {
    height: u32,
    tx_hash: String,
    fee: u32,
}
