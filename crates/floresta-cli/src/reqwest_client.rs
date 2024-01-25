use std::fmt::Debug;

use serde::Deserialize;
use serde_json::json;

use crate::rpc::JsonRPCClient;

#[derive(Debug, Default, Clone)]
pub struct ReqwestClient {
    client: reqwest::blocking::Client,
    url: String,
    auth: Option<(String, String)>,
}

pub struct ReqwestConfig {
    pub url: String,
    pub proxy: Option<reqwest::Proxy>,
    pub auth: Option<(String, String)>,
    pub timeout: Option<std::time::Duration>,
    pub headers: Option<reqwest::header::HeaderMap>,
}

impl ReqwestClient {
    pub fn new(url: String) -> Self {
        Self {
            url,
            ..Default::default()
        }
    }

    pub fn new_with_config(config: ReqwestConfig) -> Self {
        let mut client_builder = reqwest::blocking::Client::builder();

        if let Some(proxy) = config.proxy {
            client_builder = client_builder.proxy(proxy);
        }

        if let Some(timeout) = config.timeout {
            client_builder = client_builder.timeout(timeout);
        }

        if let Some(headers) = config.headers {
            client_builder = client_builder.default_headers(headers);
        }

        let client = client_builder.build().unwrap();
        Self {
            url: config.url,
            auth: config.auth,
            client,
        }
    }

    pub fn rpc_call<Response>(
        &self,
        method: &str,
        params: &[serde_json::Value],
    ) -> Result<Response, crate::rpc_types::Error>
    where
        Response: for<'a> serde::de::Deserialize<'a> + Debug,
    {
        let mut req = self
            .client
            .post(&self.url)
            .body(
                json!({
                    "jsonrpc": "2.0",
                    "id": 0,
                    "method": method,
                    "params": params,
                })
                .to_string(),
            )
            .header("Content-Type", "application/json");

        if let Some((user, pass)) = &self.auth {
            req = req.basic_auth(user, Some(pass));
        }

        let resp = req.send()?;
        let resp = serde_json::from_str::<JsonRpcResponse<Response>>(&resp.text()?)?;
        match resp.result {
            Some(resp) => Ok(resp),
            None if resp.error.is_some() => Err(crate::rpc_types::Error::Api(resp.error.unwrap())),
            None => Err(crate::rpc_types::Error::EmtpyResponse),
        }
    }
}

impl JsonRPCClient for ReqwestClient {
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
