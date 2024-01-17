use serde_json::json;

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
        params: Vec<serde_json::Value>,
    ) -> anyhow::Result<Response>
    where
        Response: for<'a> serde::de::Deserialize<'a>,
    {
        let mut req = self.client.post(&self.url).body(
            json!({
                "jsonrpc": "2.0",
                "id": 0,
                "method": method,
                "params": params,
            })
            .to_string(),
        );
        if let Some((user, pass)) = &self.auth {
            req = req.basic_auth(user, Some(pass));
        }

        let resp = req.send()?;
        let resp = resp.text()?;

        let resp: Response = serde_json::from_str(&resp)?;

        Ok(resp)
    }
}
