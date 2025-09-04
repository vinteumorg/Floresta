//! This module holds all RPC server side methods for interacting with our node's network stack.

use super::res::JsonRpcError;
use super::server::RpcChain;
use super::server::RpcImpl;

impl<Blockchain: RpcChain> RpcImpl<Blockchain> {
    pub(crate) async fn ping(&self) -> Result<bool, JsonRpcError> {
        self.node
            .ping()
            .await
            .map_err(|e| JsonRpcError::Node(e.to_string()))
    }
}
