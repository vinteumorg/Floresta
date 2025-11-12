use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct RpcClient {
    pub rpc_url: String,
    pub rpc_user: String,
    pub rpc_password: String,
}

impl RpcClient {
    pub fn new_bitcoind() -> Self {
        let rpc_port = std::env::var("BITCOIN_RPC_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(18443);

        Self {
            rpc_url: format!("http://127.0.0.1:{}", rpc_port),
            rpc_user: "fuzzer".to_string(),
            rpc_password: "fuzzing123".to_string(),
        }
    }

    pub fn new_floresta() -> Self {
        let rpc_port = std::env::var("FLORESTA_RPC_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(18598);

        Self {
            rpc_url: format!("http://127.0.0.1:{}", rpc_port),
            rpc_user: String::new(),      // Floresta doesn't need auth
            rpc_password: String::new(),
        }
    }

    pub fn call(&self, method: &str, params: &[Value]) -> Result<Value, String> {
        const MAX_RETRIES: u32 = 3;
        const RETRY_DELAY_MS: u64 = 100;

        for attempt in 1..=MAX_RETRIES {
            match self.call_once(method, params) {
                Ok(result) => return Ok(result),
                Err(e) if attempt < MAX_RETRIES => {
                    eprintln!("RPC attempt {}/{} failed: {}", attempt, MAX_RETRIES, e);
                    std::thread::sleep(Duration::from_millis(RETRY_DELAY_MS));
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!()
    }

    fn call_once(&self, method: &str, params: &[Value]) -> Result<Value, String> {
        use reqwest::blocking::Client;

        let request_body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let mut client_builder = Client::builder().timeout(Duration::from_secs(5));

        // Add basic auth if credentials provided
        let client = if !self.rpc_user.is_empty() {
            client_builder = client_builder.danger_accept_invalid_certs(true);
            client_builder
                .build()
                .map_err(|e| format!("Failed to create HTTP client: {}", e))?
        } else {
            client_builder
                .build()
                .map_err(|e| format!("Failed to create HTTP client: {}", e))?
        };

        let mut request = client.post(&self.rpc_url).json(&request_body);

        // Add authentication for Bitcoin Core
        if !self.rpc_user.is_empty() {
            request = request.basic_auth(&self.rpc_user, Some(&self.rpc_password));
        }

        let response = request
            .send()
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        let response_json: Value = response
            .json()
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        // Check for RPC error
        if let Some(error) = response_json.get("error") {
            if !error.is_null() {
                return Err(format!("RPC Error: {}", error));
            }
        }

        // Extract result
        response_json
            .get("result")
            .cloned()
            .ok_or("No result field in RPC response".to_string())
    }
}
