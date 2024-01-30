extern crate alloc;
use alloc::vec::Vec;
use core::ffi::c_uint;

#[cfg(feature = "bitcoinconsensus")]
use bitcoin::bitcoinconsensus::VERIFY_NONE;
#[cfg(feature = "bitcoinconsensus")]
use bitcoin::bitcoinconsensus::VERIFY_P2SH;
#[cfg(feature = "bitcoinconsensus")]
use bitcoin::bitcoinconsensus::VERIFY_WITNESS;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::Target;
use rustreexo::accumulator::node_hash::NodeHash;
use rustreexo::accumulator::stump::Stump;

use crate::prelude::*;
use crate::Network;
#[derive(Clone, Debug)]
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
    pub max_target: Target,
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
    /// A list of exceptions to the rules, where the key is the block hash and the value is the
    /// verification flags
    pub exceptions: HashMap<BlockHash, c_uint>,
    pub network_roots: Stump,
    pub assumeutreexo_index: (BlockHash, u32),
}

impl ChainParams {
    fn max_target(net: Network) -> Target {
        match net {
            Network::Bitcoin => Target::MAX_ATTAINABLE_MAINNET,
            Network::Testnet => Target::MAX_ATTAINABLE_TESTNET,
            Network::Signet => Target::MAX_ATTAINABLE_SIGNET,
            Network::Regtest => Target::MAX_ATTAINABLE_REGTEST,
        }
    }
}

fn get_signet_roots() -> Stump {
    let roots: Vec<NodeHash> = [
        "e40250d1e2d3d3abded6e2446d1d1850bd2afc28df7d05a95ab2338f91e0ce0d",
        "c1643b2a77926d8dd0a1b015c78582639d99a07dbd05be9b922e1ac4e46f2fa4",
        "13147475bb573e7776d27b3291c02b42da34456780575541c3ec934f5fbcb850",
        "5d99a864eb42840ad3377c2a988fa67fcc811953a76af38497d5a6c95fc3885e",
        "4b7002041f561e83a41e6bc1eefca8c5a696430d1fdc9f3bc8f1bf0cd3867dd8",
        "1e431cb227c1aaff04031f7699e4cb3f910bf1f50622b8e66f9d7a8a228c4cf9",
        "1886863097b35c47912104770d07778e7f55d1f6561dd0250bbea63664c55215",
        "99acbac755e23fad975beb23c032e2e3d602cabf579f3d9774e2b5489d928f56",
        "0e5ebc2344bc8870065ea94c95ae779722ccfff8b7e3b178b1d70b69443a9ae8",
        "c25021470a43774944c824c574d9e9d54c670782cc1df9276ac64f4608d4f959",
        "667c2196ae872696f13be73410cd8b03b009290c3edd8bd310acb42782bddd44",
    ]
    .iter()
    .map(|hash| NodeHash::from_str(hash).unwrap())
    .collect();

    Stump {
        roots,
        leaves: 3852458,
    }
}

#[cfg(feature = "bitcoinconsensus")]
fn get_exceptions() -> HashMap<BlockHash, c_uint> {
    // For some reason, some blocks in the mainnet and testnet have different rules than it should
    // be, so we need to keep a list of exceptions and treat them differently
    let mut exceptions = HashMap::new();
    exceptions.insert(
        BlockHash::from_str("00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22")
            .unwrap(),
        VERIFY_NONE,
    ); // BIP16 exception on main net
    exceptions.insert(
        BlockHash::from_str("0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad")
            .unwrap(),
        VERIFY_P2SH | VERIFY_WITNESS,
    ); // Taproot exception on main net
    exceptions.insert(
        BlockHash::from_str("00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105")
            .unwrap(),
        VERIFY_NONE,
    ); // BIP16 exception on test net
    exceptions
}

#[cfg(not(feature = "bitcoinconsensus"))]
fn get_exceptions() -> HashMap<BlockHash, c_uint> {
    HashMap::new()
}

impl From<Network> for ChainParams {
    fn from(net: Network) -> Self {
        let genesis = genesis_block(net.into());
        let max_target = ChainParams::max_target(net);
        let exceptions = get_exceptions();
        match net {
            Network::Bitcoin => ChainParams {
                assumeutreexo_index: (genesis.block_hash(), 0),
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
                network_roots: Stump::default(),
            },
            Network::Testnet => ChainParams {
                assumeutreexo_index: (genesis.block_hash(), 0),
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
                network_roots: Stump::default(),
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
                network_roots: get_signet_roots(),
                assumeutreexo_index: (
                    BlockHash::from_str(
                        "000000976b44aa6a0998b2577babfeb74ab85596accd7a5bf5aac74ee8b25081",
                    )
                    .unwrap(),
                    180473,
                ),
            },
            Network::Regtest => ChainParams {
                assumeutreexo_index: (genesis.block_hash(), 0),
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
                network_roots: Stump::default(),
            },
        }
    }
}

pub fn get_chain_dns_seeds(network: Network) -> Vec<&'static str> {
    let mut seeds = Vec::new();
    // DNS seeds taken from Bitcoin Core at commit 382b692a503355df7347efd9c128aff465b5583e
    match network {
        Network::Bitcoin => {
            seeds.push("seed.bitcoin.sipa.be."); // Pieter Wuille
            seeds.push("dnsseed.bluematt.me."); // Matt Corallo
            seeds.push("dnsseed.bitcoin.dashjr.org."); // Luke Dashjr
            seeds.push("seed.bitcoinstats.com."); // Christian Decker
            seeds.push("seed.bitcoin.jonasschnelli.ch."); // Jonas Schnelli
            seeds.push("seed.btc.petertodd.org."); // Peter Todd
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
