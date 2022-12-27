//!
//! Handles different inputs, try to make sense out of it and store a sane descriptor at the end
//!

use std::array::TryFromSliceError;

use bitcoin::util::base58;
#[derive(Debug)]
pub enum ParsingError {
    UnknownVersion([u8; 4]),
    InvalidBase68CheckString(base58::Error),
    InvalidSlice(TryFromSliceError),
    InvalidSize(usize),
}
impl From<base58::Error> for ParsingError {
    fn from(err: base58::Error) -> Self {
        Self::InvalidBase68CheckString(err)
    }
}
impl From<TryFromSliceError> for ParsingError {
    fn from(err: TryFromSliceError) -> Self {
        Self::InvalidSlice(err)
    }
}
pub mod extended_pub_key {
    use bitcoin::{
        util::{
            base58,
            bip32::{ChainCode, ExtendedPubKey, Fingerprint},
        },
        Network,
    };

    use super::ParsingError;
    type Error = ParsingError;
    fn get_network(version: [u8; 4]) -> Result<Network, Error> {
        match version {
            // Mainnet
            // P2PKH or P2SH
            [0x04, 0x88, 0xb2, 0x1e] => Ok(Network::Bitcoin),
            // P2WPKH in P2SH
            [0x04, 0x9d, 0x7c, 0xb2] => Ok(Network::Bitcoin),
            // P2WPKH
            [0x04, 0xb2, 0x47, 0x46] => Ok(Network::Bitcoin),
            // Multi-signature P2WSH in P2SH
            [0x02, 0x95, 0xb4, 0x3f] => Ok(Network::Bitcoin),
            // Multi-signature P2WSH
            [0x02, 0xaa, 0x7e, 0xd3] => Ok(Network::Bitcoin),

            // Testnet
            // P2PKH or P2SH
            [0x04, 0x35, 0x87, 0xcf] => Ok(Network::Bitcoin),
            // P2WPKH in P2SH
            [0x04, 0x4a, 0x52, 0x62] => Ok(Network::Bitcoin),
            // P2WPKH
            [0x04, 0x5f, 0x1c, 0xf6] => Ok(Network::Bitcoin),
            // Multi-signature P2WSH in P2SH
            [0x02, 0x42, 0x89, 0xef] => Ok(Network::Bitcoin),
            // Multi-signature P2WSH
            [0x02, 0x57, 0x54, 0x83] => Ok(Network::Bitcoin),
            _ => Err(Error::UnknownVersion(version)),
        }
    }
    /// Decoding extended public key from binary data according to BIP 32
    /// code partially copied from Rust-Bitcoin
    fn decode_xpub(data: &[u8]) -> Result<ExtendedPubKey, Error> {
        if data.len() != 78 {
            return Err(Error::InvalidSize(data.len()));
        }
        let network = get_network(data[0..4].try_into()?)?;

        Ok(ExtendedPubKey {
            network,
            depth: data[4],
            parent_fingerprint: Fingerprint::from(&data[5..9]),
            child_number: bitcoin::util::bip32::ChildNumber::Normal { index: 0 }, //TODO
            chain_code: ChainCode::from(&data[13..45]),
            public_key: bitcoin::secp256k1::PublicKey::from_slice(&data[45..78]).expect("msg"),
        })
    }
    pub fn from_wif(wif: &str) -> Result<ExtendedPubKey, Error> {
        let data = base58::from_check(wif)?;
        decode_xpub(&data)
    }
}
