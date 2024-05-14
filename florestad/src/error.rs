use crate::slip132;
use bitcoin::consensus::encode;
#[cfg(feature = "cli-blockchain")]
use btcd_rpc::error::UtreexodError;
use floresta_chain::BlockValidationErrors;
use floresta_chain::BlockchainError;
use thiserror::Error;
#[derive(Error, Debug)]
pub enum Error {
    #[cfg(feature = "cli-blockchain")]
    #[error(transparent)]
    UtreexodError(#[from] UtreexodError),
    #[error(transparent)]
    Encode(#[from] encode::Error),
    #[error(transparent)]
    Db(#[from] kv::Error),
    #[error(transparent)]
    ParseNum(#[from] std::num::ParseIntError),
    #[error(transparent)]
    Rustreexo(#[from] String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    BlockValidation(#[from] BlockValidationErrors),
    #[error(transparent)]
    ScriptValidation(#[from] bitcoin::blockdata::script::Error),
    #[error(transparent)]
    Blockchain(#[from] BlockchainError),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
    #[error(transparent)]
    TomlParsing(#[from] toml::de::Error),
    #[error(transparent)]
    WalletInput(#[from] slip132::Error),
    #[error(transparent)]
    AddressParsing(#[from] bitcoin::address::ParseError),
    #[error(transparent)]
    Address(#[from] bitcoin::address::Error),
    #[error(transparent)]
    Miniscript(#[from] miniscript::Error),
}
