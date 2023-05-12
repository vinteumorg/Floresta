use std::{collections::HashMap, ffi::c_uint};

use bitcoin::{
    bitcoinconsensus::{VERIFY_NONE, VERIFY_P2SH, VERIFY_WITNESS},
    blockdata::constants::{genesis_block, max_target},
    hashes::hex::FromHex,
    util::uint::Uint256,
    Block, BlockHash, Network,
};
#[derive(Clone)]
pub struct ChainParams {
    /// The network's first block, also called genesis block.
    pub genesis: Block,
    /// Whether or not we are allowed to mine blocks with the network's smallest diff, this
    /// is used in testnet, if a block takes more than 20 minutes to be mined
    pub pow_allow_min_diff: bool,
    /// Whether or not we are allowed to mine without retargets, this is used in regtests
    pub pow_allow_no_retarget: bool,
    /// This is the maximum possible target (i.e, minimum possible difficulty), and in mainnet
    /// it's defined as ~((uint256)0 >> 32).
    pub max_target: Uint256,
    /// Interval of blocks until the block reward halves
    pub subsidy_halving_interval: u64,
    /// We expect blocks to take this many seconds to be found, on average
    pub pow_target_spacing: u64,
    /// When we retarget we expect this many seconds to be elapsed since last time. If
    /// it's more, we decrease difficulty, if it's less we increase difficulty
    pub pow_target_timespan: u64,
    /// We wait this many blocks before a coinbase output can be spent
    pub coinbase_maturity: u32,
    /// The height at which bip32 is activated
    pub bip34_activation_height: u32,
    /// The height at which bip65 is activated
    pub bip65_activation_height: u32,
    /// The height at which bip66 is activated
    pub bip66_activation_height: u32,
    /// The height at which segwit is activated
    pub segwit_activation_height: u32,
    /// The height at which csv(CHECK_SEQUENCE_VERIFY) is activated
    pub csv_activation_height: u32,
    pub exceptions: HashMap<BlockHash, c_uint>,
}
impl ChainParams {
    fn max_target(net: Network) -> Uint256 {
        match net {
            Network::Bitcoin => max_target(net),
            Network::Testnet => Uint256([
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x00000000ffff0000,
            ]),
            Network::Signet => Uint256([
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x00000377ae000000,
            ]),
            Network::Regtest => Uint256([
                0xffffffffffffffff,
                0xffffffffffffffff,
                0xffffffffffffffff,
                0x7fffffffffffffff,
            ]),
        }
    }
}
impl From<Network> for ChainParams {
    fn from(net: Network) -> Self {
        let genesis = genesis_block(net);
        let max_target = ChainParams::max_target(net);
        // For some reason, some blocks in the mainnet and testnet have different rules than it should
        // be, so we need to keep a list of exceptions and treat them differently
        let mut exceptions = HashMap::new();
        exceptions.insert(
            BlockHash::from_hex("00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22")
                .unwrap(),
            VERIFY_NONE,
        ); // BIP16 exception on main net
        exceptions.insert(
            BlockHash::from_hex("0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad")
                .unwrap(),
            VERIFY_P2SH | VERIFY_WITNESS,
        ); // Taproot exception on main net
        exceptions.insert(
            BlockHash::from_hex("00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105")
                .unwrap(),
            VERIFY_NONE,
        ); // BIP16 exception on test net

        match net {
            Network::Bitcoin => ChainParams {
                genesis,
                max_target,
                pow_allow_min_diff: false,
                pow_allow_no_retarget: false,
                pow_target_spacing: 10 * 60, // One block every 600 seconds (10 minutes)
                pow_target_timespan: 14 * 24 * 60 * 60, // two weeks
                subsidy_halving_interval: 210_000,
                coinbase_maturity: 100,
                bip34_activation_height: 227931,
                bip65_activation_height: 388381,
                bip66_activation_height: 363725,
                segwit_activation_height: 481824,
                csv_activation_height: 419328,
                exceptions,
            },
            Network::Testnet => ChainParams {
                genesis,
                max_target,
                pow_allow_min_diff: true,
                pow_allow_no_retarget: false,
                pow_target_spacing: 10 * 60, // One block every 600 seconds (10 minutes)
                pow_target_timespan: 14 * 24 * 60 * 60, // two weeks
                subsidy_halving_interval: 210_000,
                coinbase_maturity: 100,
                bip34_activation_height: 211_111,
                bip65_activation_height: 581_885,
                bip66_activation_height: 330_776,
                segwit_activation_height: 834_624,
                csv_activation_height: 770_112,
                exceptions,
            },
            Network::Signet => ChainParams {
                genesis,
                max_target,
                pow_allow_min_diff: false,
                pow_allow_no_retarget: false,
                pow_target_spacing: 10 * 60, // One block every 600 seconds (10 minutes)
                pow_target_timespan: 14 * 24 * 60 * 60, // two weeks
                subsidy_halving_interval: 210_000,
                coinbase_maturity: 100,
                bip34_activation_height: 500,
                csv_activation_height: 1,
                bip65_activation_height: 1,
                bip66_activation_height: 1,
                segwit_activation_height: 1,
                exceptions,
            },
            Network::Regtest => ChainParams {
                genesis,
                max_target,
                pow_allow_min_diff: false,
                pow_allow_no_retarget: true,
                pow_target_spacing: 10 * 60, // One block every 600 seconds (10 minutes)
                pow_target_timespan: 14 * 24 * 60 * 60, // two weeks
                subsidy_halving_interval: 150,
                coinbase_maturity: 100,
                bip34_activation_height: 500,
                csv_activation_height: 0,
                bip65_activation_height: 0,
                bip66_activation_height: 0,
                segwit_activation_height: 0,
                exceptions,
            },
        }
    }
}

pub fn get_chain_dns_seeds(network: Network) -> Vec<&'static str> {
    let mut seeds = vec![];
    // DNS seeds taken from Bitcoin Core at commit 382b692a503355df7347efd9c128aff465b5583e
    match network {
        Network::Bitcoin => {
            seeds.push("seed.bitcoin.sipa.be."); // Pieter Wuille
            seeds.push("dnsseed.bluematt.me."); // Matt Corallo
            seeds.push("dnsseed.bitcoin.dashjr.org."); // Luke Dashjr
            seeds.push("seed.bitcoinstats.com."); // Christian Decker
            seeds.push("seed.bitcoin.jonasschnelli.ch."); // Jonas Schnelli
            seeds.push("seed.btc.petertodd.org."); // Peter Todd, only supports
            seeds.push("seed.bitcoin.sprovoost.nl."); // Sjors Provoost
            seeds.push("dnsseed.emzy.de."); // Stephan Oeste
            seeds.push("seed.bitcoin.wiz.biz."); // Jason Maurice
        }
        Network::Testnet => {
            seeds.push("testnet-seed.bitcoin.jonasschnelli.ch.");
            seeds.push("seed.tbtc.petertodd.org.");
            seeds.push("seed.testnet.bitcoin.sprovoost.nl.");
            seeds.push("testnet-seed.bluematt.me.");
        }
        Network::Signet => {
            seeds.push("seed.signet.bitcoin.sprovoost.nl.");
            seeds.push("x1000000.seed.dlsouza.lol."); // Davidson Souza, returns utreexo peers
        }
        Network::Regtest => {
            // no seeds for regtest
        }
    }
    seeds
}
