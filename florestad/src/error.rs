use bitcoin::consensus::encode;
use floresta_chain::BlockValidationErrors;
use floresta_chain::BlockchainError;
#[cfg(feature = "compact-filters")]
use floresta_compact_filters::IterableFilterStoreError;
use floresta_watch_only::kv_database::KvDatabaseError;
use floresta_watch_only::WatchOnlyError;
use tokio_rustls::rustls::pki_types;

use crate::slip132;
#[derive(Debug)]
pub enum FlorestadError {
    /// Represents an error encountered during encoding/decoding operations.
    Encode(encode::Error),

    /// Represents an error encountered while interacting with the kv database.
    Db(kv::Error),

    /// Represents an error encountered during parsing a number from a string
    ParseNum(std::num::ParseIntError),

    /// Represents an utreexo error, such as a proof validation failure.
    Rustreexo(String),

    /// Represents an error encountered while interacting with the database.
    Io(std::io::Error),

    // Represents an error while validating a block, such as a missing transaction or an invalid proof.
    BlockValidation(BlockValidationErrors),

    /// Represents an error encountered during script validation, such as an invalid script or a failed evaluation.
    ScriptValidation(bitcoin::blockdata::script::Error),

    /// Represents an error while interacting with the blockchain backend, such as a missing block or an invalid proof.
    Blockchain(BlockchainError),

    /// Represents an error encountered while serializing or deserializing JSON objects.
    SerdeJson(serde_json::Error),

    /// Represents an error encountered while parsing a TOML file.
    TomlParsing(toml::de::Error),

    /// Represents an error parsing registered HD version bytes from slip132
    WalletInput(slip132::Error),

    /// Represents an error while parsing a bitcoin address.
    AddressParsing(bitcoin::address::ParseError),

    /// Represents an error while parsing a miniscript.
    Miniscript(miniscript::Error),

    /// Represents an error while parsing a private key or a certificate from PEM format.
    InvalidPrivKey(pki_types::pem::Error),

    /// Represents an error while parsing a certificate from PEM format.
    InvalidCert(pki_types::pem::Error),

    /// Represents an error while configuring TLS settings.
    CouldNotConfigureTLS(tokio_rustls::rustls::Error),

    /// Represents an error while generating a PKCS#8 keypair.
    CouldNotGenerateKeypair(rcgen::Error),

    /// Represents an error while generating a certificate parameter.
    CouldNotGenerateCertParam(rcgen::Error),

    /// Represents an error while generating a self-signed certificate.
    CouldNotGenerateSelfSignedCert(rcgen::Error),

    /// Represents an error while writing a file to the filesystem.
    CouldNotWriteFile(String, std::io::Error),

    /// Represents an error while creating the data directory.
    CouldNotCreateDataDir(String, std::io::Error),

    /// Represents an error while initializing the logger.
    CouldNotInitializeLogger(fern::InitError),

    /// Represents an error while obtaining a lock on the data directory.
    CannotObtainALockOnDataDir(KvDatabaseError),

    /// Represents an error while initializing the watch-only wallet.
    CouldNotInitializeWallet(WatchOnlyError<KvDatabaseError>),

    /// Represents an error while setting up the watch-only wallet.
    CouldNotSetupWallet(String),

    /// Represents an error when the assumed valid value is invalid.
    InvalidAssumedValidValue(bitcoin::hex::HexToArrayError),

    #[cfg(feature = "compact-filters")]
    /// Represents an error while loading the compact filters store.
    CouldNotLoadCompactFiltersStore(IterableFilterStoreError),

    /// Represents an error when the network has already been validated as supported.
    NetworkAlreadyValidatedAsSupported(BlockchainError),

    /// Represents an error while creating a chain provider.
    CouldNotCreateChainProvider(String),

    /// Represents an error while creating an Electrum server.
    CouldNotCreateElectrumServer(Box<dyn std::error::Error>),

    /// Represents an error while binding the Electrum server to a socket.
    FailedToBindElectrumServer(std::io::Error),

    /// Represents an error while creating the TLS data directory.
    CouldNotCreateTLSDataDir(String, std::io::Error),

    /// Represents an error while creating the TLS configuration.
    FailedToCreateTLSConfiguration(tokio_rustls::rustls::Error),

    /// Represents an error when the provided xpub is invalid.
    InvalidProvidedXpub(String, crate::slip132::Error),

    /// Represents an error when the wallet cache could not be obtained.
    CouldNotObtainWalletCache(String),

    /// Represents an error when a descriptor could not be pushed to the wallet.
    CouldNotPushDescriptorToWallet(String),
}

impl std::fmt::Display for FlorestadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlorestadError::Encode(err) => write!(f, "Encode error: {err}"),
            FlorestadError::Db(err) => write!(f, "Database error {err}"),
            FlorestadError::ParseNum(err) => write!(f, "int parse error: {err}"),
            FlorestadError::Rustreexo(err) => write!(f, "Rustreexo error: {err}"),
            FlorestadError::Io(err) => write!(f, "Io error {err}"),
            FlorestadError::ScriptValidation(err) => {
                write!(f, "Error during script evaluation: {err}")
            }
            FlorestadError::Blockchain(err) => {
                write!(f, "Error with our blockchain backend: {err:?}")
            }
            FlorestadError::SerdeJson(err) => write!(f, "Error serializing object {err}"),
            FlorestadError::WalletInput(err) => write!(f, "Error while parsing user input {err:?}"),
            FlorestadError::TomlParsing(err) => write!(f, "Error deserializing toml file {err}"),
            FlorestadError::AddressParsing(err) => write!(f, "Invalid address {err}"),
            FlorestadError::Miniscript(err) => write!(f, "Miniscript error: {err}"),
            FlorestadError::BlockValidation(err) => {
                write!(f, "Error while validating block: {err:?}")
            }
            FlorestadError::CouldNotConfigureTLS(err) => {
                write!(f, "Error while configuring TLS: {err:?}")
            }
            FlorestadError::InvalidPrivKey(err) => {
                write!(f, "Error while reading PKCS#8 private key {err:?}")
            }
            FlorestadError::InvalidCert(err) => {
                write!(f, "Error while reading PKCS#8 certificate {err:?}")
            }
            FlorestadError::CouldNotGenerateKeypair(err) => {
                write!(f, "Error while generating PKCS#8 keypair: {err}")
            }
            FlorestadError::CouldNotGenerateCertParam(err) => {
                write!(f, "Error while generating certificate param: {err}")
            }
            FlorestadError::CouldNotGenerateSelfSignedCert(err) => {
                write!(f, "Error while generating self-signed certificate: {err}")
            }
            FlorestadError::CouldNotWriteFile(path, err) => {
                write!(f, "Error while creating file {path}: {err}")
            }
            FlorestadError::CouldNotCreateDataDir(path, err) => {
                write!(f, "Error while creating data directory {path}: {err}")
            }
            FlorestadError::CouldNotInitializeLogger(err) => {
                write!(f, "Error while initializing logger: {err}")
            }
            FlorestadError::CannotObtainALockOnDataDir(err) => {
                write!(f, "Cannot obtain a lock on data directory: {err}")
            }
            FlorestadError::CouldNotInitializeWallet(err) => {
                write!(f, "Could not initialize wallet: {err}")
            }
            FlorestadError::CouldNotSetupWallet(err) => {
                write!(f, "Could not setup wallet: {err}")
            }
            FlorestadError::InvalidAssumedValidValue(value) => {
                write!(f, "Invalid assumed valid value: {value}")
            }

            #[cfg(feature = "compact-filters")]
            FlorestadError::CouldNotLoadCompactFiltersStore(err) => {
                write!(f, "Could not load compact filters store: {err}")
            }

            FlorestadError::NetworkAlreadyValidatedAsSupported(err) => {
                write!(f, "Network already validated as supported: {err}")
            }
            FlorestadError::CouldNotCreateChainProvider(err) => {
                write!(f, "Could not create chain provider: {err}")
            }
            FlorestadError::CouldNotCreateElectrumServer(err) => {
                write!(f, "Could not create Electrum server: {err}")
            }
            FlorestadError::FailedToBindElectrumServer(err) => {
                write!(f, "Failed to bind Electrum server: {err}")
            }
            FlorestadError::CouldNotCreateTLSDataDir(path, err) => {
                write!(f, "Could not create TLS data directory {path}: {err}")
            }
            FlorestadError::FailedToCreateTLSConfiguration(err) => {
                write!(f, "Failed to create TLS configuration: {err}")
            }
            FlorestadError::InvalidProvidedXpub(xpub, err) => {
                write!(f, "Invalid provided xpub {xpub}: {err:?}")
            }
            FlorestadError::CouldNotObtainWalletCache(err) => {
                write!(f, "Could not obtain wallet cache: {err}")
            }
            FlorestadError::CouldNotPushDescriptorToWallet(err) => {
                write!(f, "Could not push descriptor to wallet: {err}")
            }
        }
    }
}

/// Implements `From<T>` where `T` is a possible error outcome in this crate, this macro only
/// takes `T` and builds [`FlorestadError`] with the right variant.
macro_rules! impl_from_error {
    ($field:ident, $error:ty) => {
        impl From<$error> for FlorestadError {
            fn from(err: $error) -> Self {
                FlorestadError::$field(err)
            }
        }
    };
}

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
impl_from_error!(AddressParsing, bitcoin::address::ParseError);
impl_from_error!(Miniscript, miniscript::Error);

impl std::error::Error for FlorestadError {}
