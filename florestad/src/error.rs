use bitcoin::consensus::encode;
#[cfg(feature = "cli-blockchain")]
use btcd_rpc::error::UtreexodError;
use floresta_chain::BlockValidationErrors;
use floresta_chain::BlockchainError;
#[derive(Debug)]
pub enum Error {
    #[cfg(feature = "cli-blockchain")]
    UtreexodError(UtreexodError),
    Parsing(bitcoin::hashes::hex::Error),
    Encode(encode::Error),
    Db(kv::Error),
    ParseNum(std::num::ParseIntError),
    Rustreexo(String),
    Io(std::io::Error),
    BlockValidation(BlockValidationErrors),
    ScriptValidation(bitcoin::blockdata::script::Error),
    Blockchain(BlockchainError),
    SerdeJson(serde_json::Error),
    TomlParsing(toml::de::Error),
    WalletInput(slip132::Error),
    AddressParsing(bitcoin::util::address::Error),
    Miniscript(miniscript::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Encode(err) => write!(f, "Encode error: {err}"),
            Error::Parsing(err) => write!(f, "Parsing Error {err}"),
            #[cfg(feature = "cli-blockchain")]
            Error::UtreexodError(_) => write!(f, "UtreexodError"),
            Error::Db(err) => write!(f, "Database error {err}"),
            Error::ParseNum(err) => write!(f, "int parse error: {err}"),
            Error::Rustreexo(err) => write!(f, "Rustreexo error: {err}"),
            Error::Io(err) => write!(f, "Io error {err}"),
            Error::ScriptValidation(err) => write!(f, "Error during script evaluation: {err}"),
            Error::Blockchain(err) => write!(f, "Error with our blockchain backend: {:?}", err),
            Error::SerdeJson(err) => write!(f, "Error serializing object {err}"),
            Error::WalletInput(err) => write!(f, "Error while parsing user input {:?}", err),
            Error::TomlParsing(err) => write!(f, "Error deserializing toml file {err}"),
            Error::AddressParsing(err) => write!(f, "Invalid address {err}"),
            Error::Miniscript(err) => write!(f, "Miniscript error: {err}"),
            Error::BlockValidation(err) => write!(f, "Error while validating block: {err:?}"),
        }
    }
}
/// Implements `From<T>` where `T` is a possible error outcome in this crate, this macro only
/// takes [T] and builds [Error] with the right variant.
macro_rules! impl_from_error {
    ($field:ident, $error:ty) => {
        impl From<$error> for Error {
            fn from(err: $error) -> Self {
                Error::$field(err)
            }
        }
    };
}
impl_from_error!(Parsing, bitcoin::hashes::hex::Error);
#[cfg(feature = "cli-blockchain")]
impl_from_error!(UtreexodError, UtreexodError);
impl_from_error!(Encode, encode::Error);
impl_from_error!(Db, kv::Error);
impl_from_error!(ParseNum, std::num::ParseIntError);
impl_from_error!(Rustreexo, String);
impl_from_error!(Io, std::io::Error);
impl_from_error!(ScriptValidation, bitcoin::blockdata::script::Error);
impl_from_error!(Blockchain, BlockchainError);
impl_from_error!(SerdeJson, serde_json::Error);
impl_from_error!(WalletInput, slip132::Error);
impl_from_error!(TomlParsing, toml::de::Error);
impl_from_error!(BlockValidation, BlockValidationErrors);
impl_from_error!(AddressParsing, bitcoin::util::address::Error);
impl_from_error!(Miniscript, miniscript::Error);

impl std::error::Error for Error {}
