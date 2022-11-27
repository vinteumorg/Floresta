use btcd_rpc::error::UtreexodError;

use crate::impl_from_error;
#[derive(Debug)]
pub enum Error {
    BackendError(UtreexodError),
    InvalidParams,
    ParsingError(serde_json::Error),
}
impl From<UtreexodError> for Error {
    fn from(err: UtreexodError) -> Self {
        Error::BackendError(err)
    }
}
impl_from_error!(ParsingError, serde_json::Error);
