#![allow(unused)]

use bitcoin::psbt::serialize::Serialize;
use serde::Deserialize;
use serde_json::Value;
pub enum BlockchainRequest {
    BlockHeaders,
    EstimateFee,
    RelayFee,
    GetBalance,
    GetHistory,
    GetMempool,
    ListUnspent,
}

#[derive(Debug, Deserialize)]
pub struct Request {
    pub id: i32,
    pub method: String,
    pub jsonrpc: String,

    #[serde(default)]
    pub params: Vec<Value>,
}

pub struct Response<T: Serialize> {
    pub id: i32,
    pub result: T,
    pub jsonrpc: String,
}
impl<T: Serialize> Response<T> {
    pub fn new(result: T) -> Response<T> {
        Response {
            id: 0,
            jsonrpc: "2.0".into(),
            result,
        }
    }
}

pub enum Server {
    Ping,
    AddPeer,
    Features,
}
