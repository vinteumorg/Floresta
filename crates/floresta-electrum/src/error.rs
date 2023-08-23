#[cfg(feature = "cli-blockchain")]
use btcd_rpc::error::UtreexodError;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Utreexod error")]
    #[cfg(feature = "cli-blockchain")]
    BackendError(#[from] UtreexodError),
    #[error("Invalid params passed in")]
    InvalidParams,
    #[error("Invalid json string {0}")]
    ParsingError(#[from] serde_json::Error),
    #[error("Blockchain error")]
    ChainError(Box<dyn core2::error::Error + Send + 'static>),
    #[error("IO error")]
    IoError(#[from] std::io::Error),
}
