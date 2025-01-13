//! Main module for the p2p chain. This is a blockchain provider, just like cli-chain, but it's
//! backed by p2p Bitcoin's p2p network.

use std::net::SocketAddr;

use bitcoin::Network;
use floresta_chain::pruned_utreexo::consensus::AssumeUtreexoValue;

#[derive(Debug, Clone)]
/// Configuration for the Utreexo node.
pub struct UtreexoNodeConfig {
    /// The blockchain we are in, defaults to Bitcoin. Possible values are Bitcoin,
    /// Testnet, Regtest and Signet.
    pub network: Network,
    /// Whether to use PoW fraud proofs. Defaults to false.
    ///
    /// PoW fraud proof is a mechanism to skip the verification of the whole blockchain,
    /// but while also giving a better security than simple SPV. Check out the documentation
    /// in `pow_fraud_proofs.md` under the `docs` folder.
    pub pow_fraud_proofs: bool,
    /// Whether to use compact filters. Defaults to false.
    ///
    /// Compact filters are useful to rescan the blockchain for a specific address, without
    /// needing to download the whole chain. It will download ~1GB of filters, and then
    /// download the blocks that match the filters.
    pub compact_filters: bool,
    /// Fixed peers to connect to. Defaults to None.
    ///
    /// If you want to connect to a specific peer, you can set this to a string with the
    /// format `ip:port`. For example, `localhost:8333`.
    pub fixed_peer: Option<String>,
    /// Maximum ban score. Defaults to 100.
    ///
    /// If a peer misbehaves, we increase its ban score. If the ban score reaches this value,
    /// we disconnect from the peer.
    pub max_banscore: u32,
    /// Maximum number of outbound connections. Defaults to 8.
    pub max_outbound: u32,
    /// Maximum number of inflight requests. Defaults to 10.
    ///
    /// More inflight requests means more memory usage, but also more parallelism.
    pub max_inflight: u32,
    /// Data directory for the node. Defaults to `.floresta-node`.
    pub datadir: String,
    /// A SOCKS5 proxy to use. Defaults to None.
    pub proxy: Option<SocketAddr>,
    /// If enabled, the node will assume that the provided Utreexo state is valid, and will
    /// start running from there
    pub assume_utreexo: Option<AssumeUtreexoValue>,
    /// If we assumeutreexo or pow_fraud_proof, we can skip the IBD and make our node usable
    /// faster, with the tradeoff of security. If this is enabled, we will still download the
    /// blocks in the background, and verify the final Utreexo state. So, the worse case scenario
    /// is that we are vulnerable to a fraud proof attack for a few hours, but we can spot it
    /// and react in a couple of hours at most, so the attack window is very small.
    pub backfill: bool,
    /// If we are using network-provided block filters, we may not need to download the whole
    /// chain of filters, as our wallets may not have been created at the beginning of the chain.
    /// With this option, we can make a rough estimate of the block height we need to start
    /// and only download the filters from that height.
    ///
    /// If the value is negative, it's relative to the current tip. For example, if the current
    /// tip is at height 1000, and we set this value to -100, we will start downloading filters
    /// from height 900.
    pub filter_start_height: Option<i32>,
    /// The user agent that we will advertise to our peers. Defaults to `floresta:<version>`.
    pub user_agent: String,
}

impl Default for UtreexoNodeConfig {
    fn default() -> Self {
        UtreexoNodeConfig {
            network: Network::Bitcoin,
            pow_fraud_proofs: false,
            compact_filters: false,
            fixed_peer: None,
            max_banscore: 100,
            max_outbound: 8,
            max_inflight: 10,
            datadir: ".floresta-node".to_string(),
            proxy: None,
            backfill: false,
            assume_utreexo: None,
            filter_start_height: None,
            user_agent: format!("floresta:{}", env!("CARGO_PKG_VERSION")),
        }
    }
}

pub mod dns_seeds {
    use bitcoin::p2p::ServiceFlags;

    extern crate alloc;
    use alloc::vec::Vec;

    use floresta_chain::Network;

    /// A dns seed is a authoritative DNS server that returns the IP addresses of nodes that are
    /// likely to be accepting incoming connections. This is our preferred way of finding new peers
    /// on the first startup, as peers returned by seeds are likely to be online and accepting
    /// connections. We may use this as a fallback if we don't have any peers to connect in
    /// subsequent startups.
    ///
    /// Some seeds allow filtering by service flags, so we may use this to find peers that are
    /// likely to be running Utreexo, for example.
    pub struct DnsSeed {
        /// The network this peer supports (e.g, mainnet, testnet, etc)
        pub network: Network,
        /// The domain name of the seed
        pub seed: &'static str,
        /// Useful filters we can use to find relevant peers
        pub filters: ServiceFlags,
    }

    impl DnsSeed {
        pub fn new(network: Network, seed: &'static str, filters: ServiceFlags) -> Self {
            DnsSeed {
                network,
                seed,
                filters,
            }
        }
        pub fn get_chain_dns_seeds(network: Network) -> Vec<DnsSeed> {
            // DNS seeds taken from Bitcoin Core at commit 382b692a503355df7347efd9c128aff465b5583e
            let mut seeds = Vec::new();

            // Some dns seeds lets us filter the returned peers by advertised services. We are interested
            // in peers with: UTREEXO, COMPACT_FILTERS, WITNESS and NETWORK. Not all seeds supports all
            // bits, so from this list, we pick the ones they support, and ask for this

            // x9 or 0x09 means NETWORK + WITNESS
            let x9: ServiceFlags = ServiceFlags::from(0x9);
            // this mean NETWORK + WITNESS + COMPACT_FILTERS
            let x49 = ServiceFlags::from(0x49);
            // this mean NETWORK + WITNESS + COMPACT_FILTERS + UTREEXO
            let x1000049 = ServiceFlags::from(0x1000049);
            // this means NETWORK + WITNESS + UTREEXO
            let x1000009 = ServiceFlags::from(0x1000009);
            // filters aren't supported (usually returns a static list of peers)
            let none = ServiceFlags::NONE;

            match network {
                Network::Bitcoin => {
                    seeds.push(DnsSeed::new(
                        Network::Bitcoin,
                        "seed.calvinkim.info",
                        x1000009,
                    ));
                    seeds.push(DnsSeed::new(
                        Network::Bitcoin,
                        "seed.bitcoin.sipa.be",
                        x9, // no COMPACT_FILTERS
                    ));
                    seeds.push(DnsSeed::new(Network::Bitcoin, "dnsseed.bluematt.me", x49));
                    seeds.push(DnsSeed::new(Network::Bitcoin, "seed.bitcoinstats.com", x49));
                    seeds.push(DnsSeed::new(
                        Network::Bitcoin,
                        "seed.btc.petertodd.org",
                        x49,
                    ));
                    seeds.push(DnsSeed::new(
                        Network::Bitcoin,
                        "seed.bitcoin.luisschwab.com",
                        x1000049,
                    ));
                    seeds.push(DnsSeed::new(
                        Network::Bitcoin,
                        "seed.bitcoin.sprovoost.nl",
                        x49,
                    ));
                    seeds.push(DnsSeed::new(Network::Bitcoin, "dnsseed.emzy.de", x49));
                    seeds.push(DnsSeed::new(Network::Bitcoin, "seed.bitcoin.wiz.biz", x49));
                }
                Network::Testnet => {
                    seeds.push(DnsSeed::new(
                        Network::Testnet,
                        "testnet-seed.bitcoin.jonasschnelli.ch",
                        x49,
                    ));
                    seeds.push(DnsSeed::new(
                        Network::Testnet,
                        "seed.tbtc.petertodd.org",
                        x49,
                    ));
                    seeds.push(DnsSeed::new(
                        Network::Testnet,
                        "seed.testnet.bitcoin.sprovoost.nl",
                        x49,
                    ));
                    seeds.push(DnsSeed::new(
                        Network::Testnet,
                        "testnet-seed.bluematt.me",
                        none,
                    ));
                }
                Network::Signet => {
                    seeds.push(DnsSeed::new(
                        Network::Signet,
                        "seed.signet.bitcoin.sprovoost.nl",
                        x49,
                    ));
                    seeds.push(DnsSeed::new(Network::Signet, "seed.dlsouza.lol", x1000049));
                }
                Network::Regtest => {
                    // No seeds for regtest
                }
            };
            seeds
        }
    }
}

pub mod address_man;
pub mod chain_selector;
pub mod error;
pub mod mempool;
pub mod node;
pub mod node_context;
pub mod node_interface;
pub mod peer;
pub mod running_node;
pub mod socks;
pub mod sync_node;
#[cfg(test)]
#[doc(hidden)]
pub mod tests;
