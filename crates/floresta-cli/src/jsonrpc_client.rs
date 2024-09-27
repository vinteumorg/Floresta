use std::fmt::Debug;

use serde::Deserialize;

use crate::rpc::JsonRPCClient;

#[derive(Debug)]
pub struct Client(jsonrpc::Client);

pub struct JsonRPCConfig {
    pub url: String,
    pub user: Option<String>,
    pub pass: Option<String>,
}

impl Client {
    pub fn new(url: String) -> Self {
        let client =
            jsonrpc::Client::simple_http(&url, None, None).expect("Failed to create client");
        Self(client)
    }

    pub fn new_with_config(config: JsonRPCConfig) -> Self {
        let client =
            jsonrpc::Client::simple_http(&config.url, config.user.clone(), config.pass.clone())
                .expect("Failed to create client");

        Self(client)
    }

    pub fn rpc_call<Response>(
        &self,
        method: &str,
        params: &[serde_json::Value],
    ) -> Result<Response, crate::rpc_types::Error>
    where
        Response: for<'a> serde::de::Deserialize<'a> + Debug,
    {
        let raw = serde_json::value::to_raw_value(params)?;
        let req = self.0.build_request(method, Some(&*raw));
        let resp = self
            .0
            .send_request(req)
            .map_err(crate::rpc_types::Error::from);

        Ok(resp?.result()?)
    }
}

impl JsonRPCClient for Client {
    fn call<T: for<'a> serde::de::Deserialize<'a> + Debug>(
        &self,
        method: &str,
        params: &[serde_json::Value],
    ) -> Result<T, crate::rpc_types::Error> {
        self.rpc_call(method, params)
    }
}

#[derive(Debug, Deserialize)]
pub struct JsonRpcResponse<Res> {
    pub jsonrpc: String,
    pub id: u64,
    pub result: Option<Res>,
    pub error: Option<serde_json::Value>,
}
