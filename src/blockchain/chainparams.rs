use bitcoin::{
    blockdata::constants::{genesis_block, max_target},
    util::uint::Uint256,
    Block, Network,
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
}
impl ChainParams {
    fn max_target(net: Network) -> Uint256 {
        match net {
            Network::Bitcoin => max_target(net),
            Network::Testnet => max_target(net),
            Network::Signet => Uint256([
                0x00000377ae000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ]),
            Network::Regtest => Uint256([
                0x7fffffffffffffff,
                0xffffffffffffffff,
                0xffffffffffffffff,
                0xffffffffffffffff,
            ]),
        }
    }
}
impl From<Network> for ChainParams {
    fn from(net: Network) -> Self {
        let genesis = genesis_block(net);
        let max_target = ChainParams::max_target(net);
        match net {
            Network::Bitcoin => ChainParams {
                genesis,
                max_target,
                pow_allow_min_diff: false,
                pow_allow_no_retarget: false,
                pow_target_spacing: 10 * 60, // One block every 600 seconds (10 minutes)
                pow_target_timespan: 14 * 24 * 60 * 60, // two weeks
                subsidy_halving_interval: 210_000,
            },
            Network::Testnet => ChainParams {
                genesis,
                max_target,
                pow_allow_min_diff: true,
                pow_allow_no_retarget: false,
                pow_target_spacing: 10 * 60, // One block every 600 seconds (10 minutes)
                pow_target_timespan: 14 * 24 * 60 * 60, // two weeks
                subsidy_halving_interval: 210_000,
            },
            Network::Signet => ChainParams {
                genesis,
                max_target,
                pow_allow_min_diff: false,
                pow_allow_no_retarget: false,
                pow_target_spacing: 10 * 60, // One block every 600 seconds (10 minutes)
                pow_target_timespan: 14 * 24 * 60 * 60, // two weeks
                subsidy_halving_interval: 210_000,
            },
            Network::Regtest => ChainParams {
                genesis,
                max_target,
                pow_allow_min_diff: false,
                pow_allow_no_retarget: true,
                pow_target_spacing: 10 * 60, // One block every 600 seconds (10 minutes)
                pow_target_timespan: 14 * 24 * 60 * 60, // two weeks
                subsidy_halving_interval: 150,
            },
        }
    }
}
