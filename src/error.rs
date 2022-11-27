use crate::impl_from_error;
use bitcoin::consensus::encode;
use btcd_rpc::error::UtreexodError;
#[derive(Debug)]
pub enum Error {
    UtreexodError(UtreexodError),
    ParsingError(bitcoin::hashes::hex::Error),
    TxNotFound,
    EncodeError(encode::Error),
    BlockNotFound,
    WalletNotInitialized,
    DbError(kv::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BlockNotFound => write!(f, "block not found"),
            Error::EncodeError(err) => write!(f, "Encode error: {err}"),
            Error::ParsingError(err) => write!(f, "Parsing Error {err}"),
            Error::TxNotFound => write!(f, "TxNotFound"),
            Error::UtreexodError(_) => write!(f, "UtreexodError"),
            Error::WalletNotInitialized => write!(f, "WalletNotInitialized"),
            Error::DbError(err) => write!(f, "Database error {err}"),
        }
    }
}

impl_from_error!(ParsingError, bitcoin::hashes::hex::Error);
impl_from_error!(UtreexodError, UtreexodError);
impl_from_error!(EncodeError, encode::Error);
impl_from_error!(DbError, kv::Error);

impl std::error::Error for Error {}
#[macro_export]
macro_rules! impl_from_error {
    ($field: ident, $error: ty) => {
        impl From<$error> for Error {
            fn from(err: $error) -> Self {
                Error::$field(err)
            }
        }
    };
}
