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

#[cfg(test)]
pub mod test {
    use bitcoin::{secp256k1::Secp256k1, util::bip32::ChildNumber};
    use bitcoin::{Address, Network};

    #[test]
    fn test_parsing() {
        // Test cases from https://github.com/satoshilabs/slips/blob/master/slip-0132.md
        const XPUB: &str = "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj";
        const YPUB: &str = "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP";
        const ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

        let secp = Secp256k1::new();

        let xpub: bitcoin::util::bip32::ExtendedPubKey = super::extended_pub_key::from_wif(XPUB)
            .expect("Parsing failed")
            .ckd_pub(&secp, ChildNumber::Normal { index: 0 })
            .and_then(|key| key.ckd_pub(&secp, ChildNumber::Normal { index: 0 }))
            .unwrap();
        let first_pk = bitcoin::PublicKey {
            compressed: true,
            inner: xpub.public_key,
        };
        let ypub = super::extended_pub_key::from_wif(YPUB)
            .expect("Parsing failed")
            .ckd_pub(&secp, ChildNumber::Normal { index: 0 })
            .and_then(|key| key.ckd_pub(&secp, ChildNumber::Normal { index: 0 }))
            .unwrap();
        let second_pk = bitcoin::PublicKey {
            compressed: true,
            inner: ypub.public_key,
        };

        let zpub = super::extended_pub_key::from_wif(ZPUB)
            .expect("Parsing failed")
            .ckd_pub(&secp, ChildNumber::Normal { index: 0 })
            .and_then(|key| key.ckd_pub(&secp, ChildNumber::Normal { index: 0 }))
            .unwrap();
        let third_pk = bitcoin::PublicKey {
            compressed: true,
            inner: zpub.public_key,
        };
        // Old p2pkh
        assert_eq!(
            Address::p2pkh(&first_pk, bitcoin::Network::Bitcoin)
                .to_string()
                .as_str(),
            "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
        );
        // p2wpkh-p2pkh
        let script = Address::p2wpkh(&second_pk, bitcoin::Network::Bitcoin)
            .unwrap()
            .script_pubkey();

        assert_eq!(
            Address::p2sh(&script, Network::Bitcoin)
                .unwrap()
                .to_string()
                .as_str(),
            "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
        );

        // p2wpkh
        assert_eq!(
            Address::p2wpkh(&third_pk, bitcoin::Network::Bitcoin)
                .unwrap()
                .to_string()
                .as_str(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        )
    }
}
