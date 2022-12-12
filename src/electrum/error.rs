use btcd_rpc::error::UtreexodError;

use crate::{impl_from_error, blockchain::error::BlockchainError};
#[derive(Debug)]
pub enum Error {
    BackendError(UtreexodError),
    InvalidParams,
    ParsingError(serde_json::Error),
    BlockchainError(BlockchainError),
}

impl_from_error!(BackendError, UtreexodError);
impl_from_error!(ParsingError, serde_json::Error);
impl_from_error!(BlockchainError, BlockchainError);