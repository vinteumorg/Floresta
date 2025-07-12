// Based on slip132 from LNP/BP Descriptor Wallet library by:
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Adapted for Floresta by:
//     Davidson Sousa <me@dlsouza.lol>

//! Bitcoin SLIP-132 standard implementation for parsing custom xpub/xpriv key
//! formats

use core::str::FromStr;

use bitcoin::base58;
use bitcoin::bip32;
use bitcoin::bip32::Xpriv;
use bitcoin::bip32::Xpub;
use serde::Deserialize;
use serde::Serialize;

/// Magical version bytes for xpub: bitcoin mainnet public key for P2PKH or P2SH
pub const VERSION_MAGIC_XPUB: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
/// Magical version bytes for xprv: bitcoin mainnet private key for P2PKH or
/// P2SH
pub const VERSION_MAGIC_XPRV: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];
/// Magical version bytes for ypub: bitcoin mainnet public key for P2WPKH in
/// P2SH
pub const VERSION_MAGIC_YPUB: [u8; 4] = [0x04, 0x9D, 0x7C, 0xB2];
/// Magical version bytes for yprv: bitcoin mainnet private key for P2WPKH in
/// P2SH
pub const VERSION_MAGIC_YPRV: [u8; 4] = [0x04, 0x9D, 0x78, 0x78];
/// Magical version bytes for zpub: bitcoin mainnet public key for P2WPKH
pub const VERSION_MAGIC_ZPUB: [u8; 4] = [0x04, 0xB2, 0x47, 0x46];
/// Magical version bytes for zprv: bitcoin mainnet private key for P2WPKH
pub const VERSION_MAGIC_ZPRV: [u8; 4] = [0x04, 0xB2, 0x43, 0x0C];
/// Magical version bytes for Ypub: bitcoin mainnet public key for
/// multi-signature P2WSH in P2SH
pub const VERSION_MAGIC_YPUB_MULTISIG: [u8; 4] = [0x02, 0x95, 0xb4, 0x3f];
/// Magical version bytes for Yprv: bitcoin mainnet private key for
/// multi-signature P2WSH in P2SH
pub const VERSION_MAGIC_YPRV_MULTISIG: [u8; 4] = [0x02, 0x95, 0xb0, 0x05];
/// Magical version bytes for Zpub: bitcoin mainnet public key for
/// multi-signature P2WSH
pub const VERSION_MAGIC_ZPUB_MULTISIG: [u8; 4] = [0x02, 0xaa, 0x7e, 0xd3];
/// Magical version bytes for Zprv: bitcoin mainnet private key for
/// multi-signature P2WSH
pub const VERSION_MAGIC_ZPRV_MULTISIG: [u8; 4] = [0x02, 0xaa, 0x7a, 0x99];

/// Magical version bytes for tpub: bitcoin testnet/regtest public key for
/// P2PKH or P2SH
pub const VERSION_MAGIC_TPUB: [u8; 4] = [0x04, 0x35, 0x87, 0xCF];
/// Magical version bytes for tprv: bitcoin testnet/regtest private key for
/// P2PKH or P2SH
pub const VERSION_MAGIC_TPRV: [u8; 4] = [0x04, 0x35, 0x83, 0x94];
/// Magical version bytes for upub: bitcoin testnet/regtest public key for
/// P2WPKH in P2SH
pub const VERSION_MAGIC_UPUB: [u8; 4] = [0x04, 0x4A, 0x52, 0x62];
/// Magical version bytes for uprv: bitcoin testnet/regtest private key for
/// P2WPKH in P2SH
pub const VERSION_MAGIC_UPRV: [u8; 4] = [0x04, 0x4A, 0x4E, 0x28];
/// Magical version bytes for vpub: bitcoin testnet/regtest public key for
/// P2WPKH
pub const VERSION_MAGIC_VPUB: [u8; 4] = [0x04, 0x5F, 0x1C, 0xF6];
/// Magical version bytes for vprv: bitcoin testnet/regtest private key for
/// P2WPKH
pub const VERSION_MAGIC_VPRV: [u8; 4] = [0x04, 0x5F, 0x18, 0xBC];
/// Magical version bytes for Upub: bitcoin testnet/regtest public key for
/// multi-signature P2WSH in P2SH
pub const VERSION_MAGIC_UPUB_MULTISIG: [u8; 4] = [0x02, 0x42, 0x89, 0xef];
/// Magical version bytes for Uprv: bitcoin testnet/regtest private key for
/// multi-signature P2WSH in P2SH
pub const VERSION_MAGIC_UPRV_MULTISIG: [u8; 4] = [0x02, 0x42, 0x85, 0xb5];
/// Magical version bytes for Zpub: bitcoin testnet/regtest public key for
/// multi-signature P2WSH
pub const VERSION_MAGIC_VPUB_MULTISIG: [u8; 4] = [0x02, 0x57, 0x54, 0x83];
/// Magical version bytes for Zprv: bitcoin testnet/regtest private key for
/// multi-signature P2WSH
pub const VERSION_MAGIC_VPRV_MULTISIG: [u8; 4] = [0x02, 0x57, 0x50, 0x48];

/// Extended public and private key processing errors
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// error in BASE58 key encoding. Details: {0}
    Base58(base58::Error),

    /// error in hex key encoding. Details: {0}
    Hex(bitcoin::hashes::hex::HexToArrayError),

    /// pk->pk derivation was attempted on a hardened key.
    CannotDeriveFromHardenedKey,

    /// child number {0} is out of range.
    InvalidChildNumber(u32),

    /// invalid child number format.
    InvalidChildNumberFormat,

    /// invalid derivation path format.
    InvalidDerivationPathFormat,

    /// unknown version magic bytes {0:#06X?}
    UnknownVersion([u8; 4]),

    /// encoded extended key data has wrong length {0}
    WrongExtendedKeyLength(usize),

    /// unrecognized or unsupported extended key prefix (please check SLIP 32
    /// for possible values)
    UnknownSlip32Prefix,

    /// failure in rust bitcoin library
    InternalFailure,
}

impl From<bip32::Error> for Error {
    fn from(err: bip32::Error) -> Self {
        match err {
            bip32::Error::CannotDeriveFromHardenedKey => Error::CannotDeriveFromHardenedKey,
            bip32::Error::InvalidChildNumber(no) => Error::InvalidChildNumber(no),
            bip32::Error::InvalidChildNumberFormat => Error::InvalidChildNumberFormat,
            bip32::Error::InvalidDerivationPathFormat => Error::InvalidDerivationPathFormat,
            bip32::Error::Secp256k1(_) => Error::InternalFailure,
            bip32::Error::UnknownVersion(ver) => Error::UnknownVersion(ver),
            bip32::Error::WrongExtendedKeyLength(len) => Error::WrongExtendedKeyLength(len),
            bip32::Error::Base58(err) => Error::Base58(err),
            bip32::Error::Hex(err) => Error::Hex(err),
            _ => Error::InternalFailure,
        }
    }
}

impl From<base58::Error> for Error {
    fn from(err: base58::Error) -> Self {
        Error::Base58(err)
    }
}

/// SLIP 132-defined key applications defining types of scriptPubKey descriptors
/// in which they can be used
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum KeyApplication {
    /// xprv/xpub: keys that can be used for P2PKH and multisig P2SH
    /// scriptPubKey descriptors.
    #[serde(rename = "bip44")]
    Hashed,

    /// zprv/zpub: keys that can be used for P2WPKH scriptPubKey descriptors
    #[serde(rename = "bip84")]
    SegWit,

    /// Zprv/Zpub: keys that can be used for multisig P2WSH scriptPubKey
    /// descriptors
    #[serde(rename = "bip48-native")]
    SegWitMultisig,

    /// yprv/ypub: keys that can be used for P2WPKH-in-P2SH scriptPubKey
    /// descriptors
    #[serde(rename = "bip49")]
    Nested,

    /// Yprv/Ypub: keys that can be used for multisig P2WSH-in-P2SH
    /// scriptPubKey descriptors
    #[serde(rename = "bip48-nested")]
    NestedMultisig,
}

/// Unknown string representation of [`KeyApplication`] enum
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct UnknownKeyApplicationError;

impl FromStr for KeyApplication {
    type Err = UnknownKeyApplicationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "bip44" => KeyApplication::Hashed,
            "bip84" => KeyApplication::SegWit,
            "bip48-native" => KeyApplication::SegWitMultisig,
            "bip49" => KeyApplication::Nested,
            "bip48-nested" => KeyApplication::NestedMultisig,
            _ => return Err(UnknownKeyApplicationError),
        })
    }
}

/// Trait for building standard BIP32 extended keys from SLIP132 variant.
pub trait FromSlip132 {
    /// Constructs standard BIP32 extended key from SLIP132 string.
    fn from_slip132_str(s: &str) -> Result<Self, Error>
    where
        Self: Sized;
}

impl FromSlip132 for Xpub {
    fn from_slip132_str(s: &str) -> Result<Self, Error> {
        let mut data = base58::decode_check(s)?;

        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&data[0..4]);
        let slice = match prefix {
            VERSION_MAGIC_XPUB
            | VERSION_MAGIC_YPUB
            | VERSION_MAGIC_ZPUB
            | VERSION_MAGIC_YPUB_MULTISIG
            | VERSION_MAGIC_ZPUB_MULTISIG => VERSION_MAGIC_XPUB,

            VERSION_MAGIC_TPUB
            | VERSION_MAGIC_UPUB
            | VERSION_MAGIC_VPUB
            | VERSION_MAGIC_UPUB_MULTISIG
            | VERSION_MAGIC_VPUB_MULTISIG => VERSION_MAGIC_TPUB,

            _ => return Err(Error::UnknownSlip32Prefix),
        };
        data[0..4].copy_from_slice(&slice);

        let xpub = Xpub::decode(&data)?;

        Ok(xpub)
    }
}

impl FromSlip132 for Xpriv {
    fn from_slip132_str(s: &str) -> Result<Self, Error> {
        let mut data = base58::decode_check(s)?;

        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&data[0..4]);
        let slice = match prefix {
            VERSION_MAGIC_XPRV
            | VERSION_MAGIC_YPRV
            | VERSION_MAGIC_ZPRV
            | VERSION_MAGIC_YPRV_MULTISIG
            | VERSION_MAGIC_ZPRV_MULTISIG => VERSION_MAGIC_XPRV,

            VERSION_MAGIC_TPRV
            | VERSION_MAGIC_UPRV
            | VERSION_MAGIC_VPRV
            | VERSION_MAGIC_UPRV_MULTISIG
            | VERSION_MAGIC_VPRV_MULTISIG => VERSION_MAGIC_TPRV,

            _ => return Err(Error::UnknownSlip32Prefix),
        };
        data[0..4].copy_from_slice(&slice);

        let xprv = Xpriv::decode(&data)?;

        Ok(xprv)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::bip32::ChildNumber;
    use bitcoin::bip32::Xpub;
    use bitcoin::key::Secp256k1;
    use bitcoin::Address;
    use bitcoin::Network;

    use crate::prelude::*;
    use crate::slip132::FromSlip132;

    #[test]
    fn test_xpub_parsing() {
        // Test cases from https://github.com/satoshilabs/slips/blob/master/slip-0132.md
        const XPUB: &str = "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj";
        const YPUB: &str = "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP";
        const ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

        let secp = Secp256k1::new();

        let xpub: bitcoin::bip32::Xpub = Xpub::from_slip132_str(XPUB)
            .expect("Parsing failed")
            .ckd_pub(&secp, ChildNumber::Normal { index: 0 })
            .and_then(|key| key.ckd_pub(&secp, ChildNumber::Normal { index: 0 }))
            .unwrap();
        let ypub = Xpub::from_slip132_str(YPUB)
            .expect("Parsing failed")
            .ckd_pub(&secp, ChildNumber::Normal { index: 0 })
            .and_then(|key| key.ckd_pub(&secp, ChildNumber::Normal { index: 0 }))
            .unwrap();
        let zpub = Xpub::from_slip132_str(ZPUB)
            .expect("Parsing failed")
            .ckd_pub(&secp, ChildNumber::Normal { index: 0 })
            .and_then(|key| key.ckd_pub(&secp, ChildNumber::Normal { index: 0 }))
            .unwrap();
        // Old p2pkh
        assert_eq!(
            Address::p2pkh(xpub.to_pub(), Network::Bitcoin)
                .to_string()
                .as_str(),
            "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
        );

        // p2wpkh-p2pkh
        let script = Address::p2wpkh(&ypub.to_pub(), Network::Bitcoin).script_pubkey();

        assert_eq!(
            Address::p2sh(&script, Network::Bitcoin)
                .unwrap()
                .to_string()
                .as_str(),
            "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
        );

        // p2wpkh
        assert_eq!(
            Address::p2wpkh(&zpub.to_pub(), Network::Bitcoin)
                .to_string()
                .as_str(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        )
    }
}
