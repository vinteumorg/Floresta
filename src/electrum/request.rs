use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct Request {
    pub id: i32,
    pub method: String,
    pub jsonrpc: String,

    #[serde(default)]
    pub params: Vec<Value>,
}
