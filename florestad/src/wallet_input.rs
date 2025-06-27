//! Handles different inputs, try to make sense out of it and store a sane descriptor at the end

use std::str::FromStr;

use bitcoin::bip32::Xpub;
use bitcoin::Address;
use bitcoin::Network;
use bitcoin::ScriptBuf;
use floresta_common::descriptor_internals::ConcreteDescriptor;
use floresta_common::descriptor_internals::DerivationRange;
use floresta_common::descriptor_internals::DescriptorRequest;
use floresta_common::descriptor_internals::RescanRequest;
use log::warn;

use crate::slip132;

/// Helper function to cast a ['Xpub'] from
/// a String.
pub fn to_xpub(s: &str) -> Result<Xpub, slip132::Error> {
    slip132::FromSlip132::from_slip132_str(s)
}

/// Converts the inserted addresses, descriptors and xpubs
/// into compatible types so we can cache them using
/// the wallet API.
pub(crate) fn convert_to_internal(
    xpubs: &[String],
    initial_descriptors: &[String],
    addresses: &[String],
    network: Network,
    addresses_per_descriptor: u32,
) -> Result<(Vec<ConcreteDescriptor>, Vec<ScriptBuf>), crate::error::Error> {
    let mut xpub_descriptor_request: Vec<_> = xpubs
        .iter()
        .filter_map(|x| {
            let casted = match to_xpub(x) {
                Ok(x) => x,
                Err(e) => {
                    warn!("The user inserted an invalid xpub; {e:?}");
                    return None;
                }
            };
            let main_desc = DescriptorRequest {
                desc: format!("wpkh({casted}/0/*)"),
                timestamp: RescanRequest::Full,
                label: format!("A Xpub Descriptor; {casted}"),
                range: DerivationRange::End(addresses_per_descriptor),
                ..Default::default()
            };
            let change_desc = DescriptorRequest {
                desc: format!("wpkh({casted}/1/*)"),
                timestamp: RescanRequest::Full,
                label: format!("A Xpub Change Descriptor; {casted}"),
                range: DerivationRange::End(addresses_per_descriptor),
                ..Default::default()
            };

            Some([main_desc, change_desc])
        })
        .flatten()
        .collect();

    let mut descriptors: Vec<DescriptorRequest> = initial_descriptors
        .iter()
        .map(|d| DescriptorRequest {
            desc: d.clone(),
            timestamp: RescanRequest::Full,
            label: format!("A Xpub Descriptor; {d}"),
            range: DerivationRange::End(addresses_per_descriptor),
            ..Default::default()
        })
        .collect();

    xpub_descriptor_request.append(&mut descriptors);

    let desc_ret: Vec<_> = xpub_descriptor_request
        .into_iter()
        .map(DescriptorRequest::into_concrete_descriptors)
        .collect::<Result<Vec<Vec<ConcreteDescriptor>>, _>>()?
        .into_iter()
        .flatten()
        .collect();

    let addr_ret = addresses
        .iter()
        .filter_map(|address| match Address::from_str(address) {
            Ok(address) => address.require_network(network).ok(),
            Err(e) => {
                log::error!("Invalid address provided: {address} \nReason: {e:?}");
                None
            }
        })
        .map(|address| address.script_pubkey())
        .collect::<Vec<ScriptBuf>>();

    Ok((desc_ret, addr_ret))
}
#[cfg(test)]
pub mod test {
    use bitcoin::bip32::ChildNumber;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::Network;

    use super::*;

    #[test]
    fn test_xpub_parsing() {
        // Test cases from https://github.com/satoshilabs/slips/blob/master/slip-0132.md
        const XPUB: &str = "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj";
        const YPUB: &str = "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP";
        const ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

        let secp = Secp256k1::new();

        let xpub: bitcoin::bip32::Xpub = super::to_xpub(XPUB)
            .expect("Parsing failed")
            .ckd_pub(&secp, ChildNumber::Normal { index: 0 })
            .and_then(|key| key.ckd_pub(&secp, ChildNumber::Normal { index: 0 }))
            .unwrap();
        let ypub = super::to_xpub(YPUB)
            .expect("Parsing failed")
            .ckd_pub(&secp, ChildNumber::Normal { index: 0 })
            .and_then(|key| key.ckd_pub(&secp, ChildNumber::Normal { index: 0 }))
            .unwrap();
        let zpub = super::to_xpub(ZPUB)
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

    // #[test]
    // fn test_initial_wallet_build() {
    //     use pretty_assertions::assert_eq;
    //     let addresses_per_descriptor = 1;
    //     let network = Network::Bitcoin;
    //     // Build wallet from xpub (in this case a zpub from slip132 standard)
    //     let w1_xpub = InitialWalletSetup::build(&[
    //         "zpub6qvVf5mN7DH14wr7oZS7xL6cpcFPDmxFEHBk18YpUF1qnroE1yGfW83eafbbi23dzRk7jrVXeJFMyCo3urmQpwkXtVnRmGmaJ3qVvdwx4mB".to_owned()
    //     ], &[], &[], network, addresses_per_descriptor).unwrap();
    //     // Build same wallet from output descriptor
    //     let w1_descriptor = InitialWalletSetup::build(&[], &[
    //         "wpkh(xpub6CFy3kRXorC3NMTt8qrsY9ucUfxVLXyFQ49JSLm3iEG5gfAmWewYFzjNYFgRiCjoB9WWEuJQiyYGCdZvUTwPEUPL9pPabT8bkbiD9Po47XG/<0;1>/*)".to_owned()
    //     ], &[], network, addresses_per_descriptor).unwrap();
    //     // Using both methods the result should be the same
    //     assert_eq!(w1_xpub, w1_descriptor);
    //     // Both normal receiving descriptor and change descriptor should be present
    //     assert_eq!(
    //         w1_descriptor.descriptors
    //             .iter()
    //             .map(ToString::to_string)
    //             .collect::<Vec<_>>(),
    //         vec![
    //             "wpkh(xpub6CFy3kRXorC3NMTt8qrsY9ucUfxVLXyFQ49JSLm3iEG5gfAmWewYFzjNYFgRiCjoB9WWEuJQiyYGCdZvUTwPEUPL9pPabT8bkbiD9Po47XG/0/*)#qua4l7ct",
    //             "wpkh(xpub6CFy3kRXorC3NMTt8qrsY9ucUfxVLXyFQ49JSLm3iEG5gfAmWewYFzjNYFgRiCjoB9WWEuJQiyYGCdZvUTwPEUPL9pPabT8bkbiD9Po47XG/1/*)#3gc5ztgn"
    //         ]
    //     );
    //     // Receiving and change addresses
    //     let addresses = vec![
    //         "bc1q88guum89mxwszau37m3y4p24renwlwgtkscl6x".to_owned(),
    //         "bc1q24629yendf7q0dxnw362dqccn52vuz9s0z59hr".to_owned(),
    //     ];
    //     assert_eq!(
    //         w1_descriptor
    //             .addresses
    //             .iter()
    //             .map(ToString::to_string)
    //             .collect::<Vec<_>>(),
    //         addresses
    //     );
    //     // We can build from these addresses
    //     let w1_addresses =
    //         InitialWalletSetup::build(&[], &[], &addresses, network, addresses_per_descriptor)
    //             .unwrap();
    //     // And the result will be the same as from xpub/descriptor
    //     assert_eq!(w1_descriptor.addresses, w1_addresses.addresses);
    //     // We can also build from xpub, descriptor and addresses, at same time
    //     let w1_all =
    //         InitialWalletSetup::build(&[
    //             "zpub6qvVf5mN7DH14wr7oZS7xL6cpcFPDmxFEHBk18YpUF1qnroE1yGfW83eafbbi23dzRk7jrVXeJFMyCo3urmQpwkXtVnRmGmaJ3qVvdwx4mB".to_owned()
    //         ], &[
    //             "wpkh(xpub6CFy3kRXorC3NMTt8qrsY9ucUfxVLXyFQ49JSLm3iEG5gfAmWewYFzjNYFgRiCjoB9WWEuJQiyYGCdZvUTwPEUPL9pPabT8bkbiD9Po47XG/<0;1>/*)".to_owned()
    //         ], &addresses, network, addresses_per_descriptor).unwrap();
    //     // And the result should be the same, no duplication will happen
    //     assert_eq!(w1_descriptor, w1_all);
    // }
    //
    // #[test]
    // fn test_initial_wallet_build_multisig_testnet() {
    //     use pretty_assertions::assert_eq;
    //     let addresses_per_descriptor = 1;
    //     let network = Network::Testnet;
    //     let w1_descriptor = InitialWalletSetup::build(&[], &[
    //         "wsh(sortedmulti(1,[54ff5a12/48h/1h/0h/2h]tpubDDw6pwZA3hYxcSN32q7a5ynsKmWr4BbkBNHydHPKkM4BZwUfiK7tQ26h7USm8kA1E2FvCy7f7Er7QXKF8RNptATywydARtzgrxuPDwyYv4x/<0;1>/*,[bcf969c0/48h/1h/0h/2h]tpubDEFdgZdCPgQBTNtGj4h6AehK79Jm4LH54JrYBJjAtHMLEAth7LuY87awx9ZMiCURFzFWhxToRJK6xp39aqeJWrG5nuW3eBnXeMJcvDeDxfp/<0;1>/*))#fuw35j0q".to_owned()
    //     ], &[], network, addresses_per_descriptor).unwrap();
    //     let addresses = vec![
    //         "tb1q2eeqw57e7pmrh5w3wkrshctx2qk80vf4mu7l7ek3ne4hg3lmcrnqcwejgj".to_owned(),
    //         "tb1q6dpyc3jyqelgfwksedef0k2244rcg4gf6wvqm463lk907es2m08qnrfky7".to_owned(),
    //     ];
    //     assert_eq!(
    //         w1_descriptor
    //             .addresses
    //             .iter()
    //             .map(ToString::to_string)
    //             .collect::<Vec<_>>(),
    //         addresses
    //     );
    // }
}
