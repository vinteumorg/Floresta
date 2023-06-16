//! This module contains some common strings for versioning

/// The default name of our data dir
pub const DIR_NAME: &str = ".floresta";
/// Version of rust-bitcoin we are using. If we bump it on Cargo.toml, should change here too
pub const RUST_BITCOIN_VERSION: &str = "0.29.3";
/// Version of rustreexo we use
pub const RUSTREEXO_VERSION: &str = "0.1.0";
/// Our own version
pub const FLORESTA_VERSION: &str = env!("CARGO_PKG_VERSION");
