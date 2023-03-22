#[cfg(feature = "cli-blockchain")]
use btcd_rpc::error::UtreexodError;

use crate::{blockchain::error::BlockchainError, impl_from_error};
#[derive(Debug)]
pub enum Error {
    #[cfg(feature = "cli-blockchain")]
    BackendError(UtreexodError),
    InvalidParams,
    ParsingError(serde_json::Error),
    BlockchainError(BlockchainError),
}
#[cfg(feature = "cli-blockchain")]
impl_from_error!(BackendError, UtreexodError);
impl_from_error!(ParsingError, serde_json::Error);
impl_from_error!(BlockchainError, BlockchainError);
