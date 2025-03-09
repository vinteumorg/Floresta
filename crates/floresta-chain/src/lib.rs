// SPDX-License-Identifier: MIT

//! # Floresta Chain
//! This crate provides the core validation logic for a full node using libfloresta.
//! It is maintained as a separate crate to allow other projects to build on it,
//! independent of the libfloresta P2P network or libfloresta wallet.
//! The main entry point is the [ChainState] struct, that keeps track of the current
//! blockchain state, like headers and utreexo accumulator.
//!
//! All data is stored in a `ChainStore` implementation, which is generic over the
//! underlying database. See the ChainStore trait for more information. For a
//! ready-to-use implementation, see the [KvChainStore] struct.
#![cfg_attr(not(test), no_std)]

macro_rules! bhash {
    ($s:expr) => {{
        // Catch invalid literals at compile time
        const _: () = match crate::validate_hash_compile_time($s) {
            Ok(()) => (),
            Err(e) => panic!("{}", e),
        };
        BlockHash::from_str($s).expect("Literal should be valid")
    }};
}

pub mod pruned_utreexo;
pub(crate) use floresta_common::prelude;
pub use pruned_utreexo::chain_state::*;
pub use pruned_utreexo::chainparams::*;
pub use pruned_utreexo::chainstore::*;
pub use pruned_utreexo::error::*;
pub use pruned_utreexo::udata::*;
pub use pruned_utreexo::Notification;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Bitcoin,
    Testnet,
    Regtest,
    Signet,
}
impl From<bitcoin::network::Network> for Network {
    fn from(network: bitcoin::network::Network) -> Self {
        match network {
            bitcoin::network::Network::Bitcoin => Network::Bitcoin,
            bitcoin::network::Network::Testnet => Network::Testnet,
            bitcoin::network::Network::Regtest => Network::Regtest,
            bitcoin::network::Network::Signet => Network::Signet,
            _ => panic!("Unknown network"),
        }
    }
}
impl From<Network> for bitcoin::network::Network {
    fn from(network: Network) -> Self {
        match network {
            Network::Bitcoin => bitcoin::network::Network::Bitcoin,
            Network::Testnet => bitcoin::network::Network::Testnet,
            Network::Regtest => bitcoin::network::Network::Regtest,
            Network::Signet => bitcoin::network::Network::Signet,
        }
    }
}

#[allow(dead_code)]
/// This const function is used to validate hash literals at compile time
const fn validate_hash_compile_time(s: &str) -> Result<(), &str> {
    let bytes = s.as_bytes();

    // Note: An ASCII character is 1 byte, so the expected byte count is 64
    if bytes.len() != 64 {
        return Err("Hash literal is not exactly 64 hex digits");
    }

    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if !((b >= b'0' && b <= b'9') || (b >= b'a' && b <= b'f') || (b >= b'A' && b <= b'F')) {
            return Err("Hash literal contains an invalid ASCII hex digit");
        }
        i += 1;
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use bitcoin::network::Network as BNetwork;

    use super::validate_hash_compile_time as validate_hash;
    use super::Network;

    #[test]
    fn test_network() {
        assert_eq!(Network::Bitcoin, BNetwork::Bitcoin.into());
        assert_eq!(Network::Testnet, BNetwork::Testnet.into());
        assert_eq!(Network::Regtest, BNetwork::Regtest.into());
        assert_eq!(Network::Signet, BNetwork::Signet.into());
    }

    #[test]
    fn test_validate_hash_compile_time() {
        // Valid: exactly 64 ASCII hex digits.
        let valid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(validate_hash(valid).is_ok());

        for len in 0..=128 {
            let test_str = "a".repeat(len);
            if len == 64 {
                assert!(validate_hash(&test_str).is_ok());
            } else {
                assert!(validate_hash(&test_str).is_err());
            }
        }

        // Invalid hex character at the end: 'g'.
        let invalid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg";
        assert_eq!(invalid.len(), 64);
        assert!(validate_hash(invalid).is_err());

        // Invalid ascii character in the middle: 'é'
        let invalid_ascii = "0123456789abcdef0123456789abcdéf0123456789abcdef0123456789abcde";
        assert_eq!(invalid_ascii.len(), 64);
        assert!(validate_hash(invalid_ascii).is_err());
    }
}
