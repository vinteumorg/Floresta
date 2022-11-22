use btcd_rpc::error::UtreexodError;

pub enum Error {
    BackendError(UtreexodError),
    InvalidParams,
}
impl From<UtreexodError> for Error {
    fn from(err: UtreexodError) -> Self {
        Error::BackendError(err)
    }
}
