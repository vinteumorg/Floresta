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
        "8e6fcdcf05020fa1f7131a59a7050b33ca74852f5e82a5fbe236402bc4c8a928",
        "f4c92949c71be7613699977eebf6d3bd5c8fd3e538a01380583e5aba14273425",
        "d73ceb2748d342b14a269d7c0feb34aca1341a6367cc75cff6db8422eb01916d",
        "a012e516784ccb7af26d7b356bf645e6a167cce5b48b9368c58c523acd25f6bf",
        "e6e74ebc1d01ac47541c90afaac208c9b0f16226d2d046742032374e925a79ae",
        "235b255558e994e6c5b6011469e891436cbf18107a939847e6e5df4cb939a96b",
        "a9f45482564f0cb103067636c39fe30df1fa04b6b04d438c655530d991432761",
        "d46716b7ccaf8d9eff11557527056f6100e016126df369eef95b9c9874467d40",
        "7039b9053ef819d35c079eb4dcdd37029653a325bf416768e7de16bacf2c90af",
        "f7a626339303030fc1b71d228e74aebdc2126cb7a2c5e01eb036225ea9dd41c2",
        "b21123705cb4cef5a104705037ccd80ae7281789aa07cd468d5949c7e62df37b",
        "ca931559f3ad9c91b9510f5dbfa42467e40ad8a0069d8f273de6079e9b115232",
        "954ca698b58b6e6cdcc89948c841059d892578b7d67a249965fff83de5aaa7e3",
    ]
    .iter()
    .map(|hash| NodeHash::from_str(hash).unwrap())
    .collect();

    Stump {
        roots,
        leaves: 1477499,
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
                        "0000001321625245a27e0be82a640106d019e35e48a024a17df1ceeb9b1f2131",
                    )
                    .unwrap(),
                    74551,
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
