use crate::{blockchain::error::BlockchainError, impl_from_error};
use bitcoin::consensus::encode;
#[cfg(feature = "cli-blockchain")]
use btcd_rpc::error::UtreexodError;
#[derive(Debug)]
pub enum Error {
    #[cfg(feature = "cli-blockchain")]
    UtreexodError(UtreexodError),
    ParsingError(bitcoin::hashes::hex::Error),
    EncodeError(encode::Error),
    WalletNotInitialized,
    DbError(kv::Error),
    ParseNumError(std::num::ParseIntError),
    RustreexoError(String),
    IoError(std::io::Error),
    ValidationError(bitcoin::blockdata::script::Error),
    ChainError(BlockchainError),
    SerdeJsonError(serde_json::Error),
    TomlParsingError(toml::de::Error),
    WalletInputError(crate::wallet_input::ParsingError),
    AddressParsingError(bitcoin::util::address::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::EncodeError(err) => write!(f, "Encode error: {err}"),
            Error::ParsingError(err) => write!(f, "Parsing Error {err}"),
            #[cfg(feature = "cli-blockchain")]
            Error::UtreexodError(_) => write!(f, "UtreexodError"),
            Error::WalletNotInitialized => write!(f, "WalletNotInitialized"),
            Error::DbError(err) => write!(f, "Database error {err}"),
            Error::ParseNumError(err) => write!(f, "int parse error: {err}"),
            Error::RustreexoError(err) => write!(f, "Rustreexo error: {err}"),
            Error::IoError(err) => write!(f, "Io error {err}"),
            Error::ValidationError(err) => write!(f, "Error during script evaluation: {err}"),
            Error::ChainError(err) => write!(f, "Error with our blockchain backend: {:?}", err),
            Error::SerdeJsonError(err) => write!(f, "Error serializing object {err}"),
            Error::WalletInputError(err) => write!(f, "Error while parsing user input {:?}", err),
            Error::TomlParsingError(err) => write!(f, "Error deserializing toml file {err}"),
            Error::AddressParsingError(err) => write!(f, "Invalid address {err}"),
        }
    }
}

impl_from_error!(ParsingError, bitcoin::hashes::hex::Error);
#[cfg(feature = "cli-blockchain")]
impl_from_error!(UtreexodError, UtreexodError);
impl_from_error!(EncodeError, encode::Error);
impl_from_error!(DbError, kv::Error);
impl_from_error!(ParseNumError, std::num::ParseIntError);
impl_from_error!(RustreexoError, String);
impl_from_error!(IoError, std::io::Error);
impl_from_error!(ValidationError, bitcoin::blockdata::script::Error);
impl_from_error!(ChainError, BlockchainError);
impl_from_error!(SerdeJsonError, serde_json::Error);
impl_from_error!(WalletInputError, crate::wallet_input::ParsingError);
impl_from_error!(TomlParsingError, toml::de::Error);
impl_from_error!(AddressParsingError, bitcoin::util::address::Error);

impl std::error::Error for Error {}
#[macro_export]
/// Implements [From<T>] where [T] is a possible error outcome in this crate, this macro only
/// takes [T] and builds [Error] with the right variant.
macro_rules! impl_from_error {
    ($field: ident, $error: ty) => {
        impl From<$error> for Error {
            fn from(err: $error) -> Self {
                Error::$field(err)
            }
        }
    };
}
