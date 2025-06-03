//! This module holds all RPC server side methods for interacting with our node's network stack.

use super::res::Error as RpcError;
use super::server::RpcChain;
use super::server::RpcImpl;

impl<Blockchain: RpcChain> RpcImpl<Blockchain> {
    pub(crate) async fn ping(&self) -> Result<bool, RpcError> {
        self.node
            .ping()
            .await
            .map_err(|e| RpcError::Node(e.to_string()))
    }
}
