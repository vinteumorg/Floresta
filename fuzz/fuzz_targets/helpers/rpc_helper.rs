//! JSON-RPC Client Helper for Differential Fuzzing
//!
//! This module provides an HTTP client for making JSON-RPC calls to Bitcoin Core
//! and Floresta nodes during differential fuzzing campaigns.

use std::time::Duration;

use serde_json::json;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct RpcClient {
    rpc_url: String,
    rpc_user: String,
    rpc_password: String,
}

impl RpcClient {
    /// Creates a new RPC client configured for Bitcoin Core.
    ///
    /// # Configuration
    /// - Port: Read from `BITCOIN_RPC_PORT` env var (default: 18443)
    /// - Credentials: fuzzer/fuzzing123
    ///
    /// # Returns
    /// Configured Bitcoin Core RPC client
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

    /// Creates a new RPC client configured for Floresta.
    ///
    /// # Configuration
    /// - Port: Read from `FLORESTA_RPC_PORT` env var (default: 18598)
    /// - No authentication required
    ///
    /// # Returns
    /// Configured Floresta RPC client

    pub fn new_floresta() -> Self {
        let rpc_port = std::env::var("FLORESTA_RPC_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(18598);

        Self {
            rpc_url: format!("http://127.0.0.1:{}", rpc_port),
            rpc_user: String::new(), // Floresta doesn't need auth
            rpc_password: String::new(),
        }
    }
    /// Executes a JSON-RPC method call with retries.
    ///
    /// # Arguments
    /// * `method` - RPC method name (e.g., "getblock", "getblockhash")
    /// * `params` - Array of parameters for the RPC call
    ///
    /// # Returns
    /// - `Ok(Value)` - Successful RPC result
    /// - `Err(String)` - Error message from network, parsing, or RPC layer
    ///
    /// # Retries
    /// Retries up to 3 times with 100ms delays on transient failures.

    pub fn call(&self, method: &str, params: &[Value]) -> Result<Value, String> {
        /// Maximum number of retry attempts for transient RPC failures
        const MAX_RETRIES: u32 = 3;

        /// Delay between retry attempts in milliseconds
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

    /// Internal helper for single RPC call attempt without retries.
    ///
    /// # Arguments
    /// * `method` - RPC method name
    /// * `params` - RPC parameters
    ///
    /// # Returns
    /// Result of the RPC call
    fn call_once(&self, method: &str, params: &[Value]) -> Result<Value, String> {
        use reqwest::blocking::Client;

        let request_body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let mut client_builder = Client::builder().timeout(Duration::from_secs(5));

        // Configure HTTP client with TLS settings for Bitcoin Core
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
