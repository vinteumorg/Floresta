use clap::arg;
use clap::command;
use clap::Parser;
use clap::ValueEnum;
use florestad::Network as FlorestaNetwork;

#[derive(Clone, Debug, ValueEnum, Default)]
pub enum Network {
    #[default]
    Bitcoin,
    Signet,
    Testnet,
    Regtest,
}

impl From<Network> for FlorestaNetwork {
    fn from(network: Network) -> Self {
        match network {
            Network::Bitcoin => FlorestaNetwork::Bitcoin,
            Network::Signet => FlorestaNetwork::Signet,
            Network::Testnet => FlorestaNetwork::Testnet,
            Network::Regtest => FlorestaNetwork::Regtest,
        }
    }
}

impl From<Network> for floresta_chain::Network {
    fn from(network: Network) -> Self {
        match network {
            Network::Bitcoin => floresta_chain::Network::Bitcoin,
            Network::Signet => floresta_chain::Network::Signet,
            Network::Testnet => floresta_chain::Network::Testnet,
            Network::Regtest => floresta_chain::Network::Regtest,
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Bitcoin => write!(f, "bitcoin"),
            Network::Signet => write!(f, "signet"),
            Network::Testnet => write!(f, "testnet"),
            Network::Regtest => write!(f, "regtest"),
        }
    }
}

#[derive(Parser)]
#[command(
    author = "Davidson Souza", 
    version = env!("GIT_DESCRIBE"),
    about = "florestad - a lightweight Bitcoin client", 
    long_about = env!("LONG_VERSION"),
)]
pub struct Cli {
    #[arg(short, long, value_name = "FILE")]
    /// Sets a custom config file
    pub config_file: Option<String>,

    #[arg(short, long, default_value_t=Network::Bitcoin)]
    /// Which network should we use
    pub network: Network,

    #[arg(short, long, default_value_t = false)]
    /// Turn debugging information on
    pub debug: bool,

    #[arg(long)]
    /// Option for saving log into data_Dir
    ///
    /// if set, log will be saved into $DATA_DIR/output.log.
    pub log_to_file: bool,

    #[arg(long, value_name = "PATH")]
    /// Where should we store data. This is the directory where we'll store the chainstate,
    /// the wallet, the logs, the compact block filters, the Utreexo state, etc.
    /// Defaults to `~/.floresta`. The passed value should be an absolute path.
    pub data_dir: Option<String>,

    #[arg(long, default_value_t = true)]
    /// Whether to build Compact Block Filters
    ///
    /// Those filters let you query for chain data after IBD, like wallet rescan,
    /// finding an utxo, finding specific tx_ids.
    /// Will cause more disk usage
    pub cfilters: bool,

    #[arg(long, short, default_value = None, value_name = "address[:<port>]")]
    /// The url of a proxy we should open p2p connections through (e.g. 127.0.0.1:9050)
    pub proxy: Option<String>,

    #[arg(long, value_name = "XPUB")]
    /// Add a xpub to our wallet
    ///
    /// This option can be passed many times, and will accept any SLIP039-valid extended
    /// public key. You only need to pass this once, but there's no harm in passing it
    /// more than once. After you start florestad at least once passing some xpub, florestad
    /// will follow the first 100 addresses derived from this xpub on each keychain  and
    /// cache any transactions where those addresses appear. You can use either the integrated
    /// json-rpc or electrum server to fetch an addresses' history, balance and utxos.
    pub wallet_xpub: Option<Vec<String>>,

    #[arg(long, value_name = "DESCRIPTOR")]
    /// Add an output descriptor to our wallet
    ///
    /// This option can be passed many times, and will accept any valid output descriptor.
    /// You only need to pass this once, but there's no harm in passing it more than once.
    /// After you start florestad at least once passing some xpub, florestad
    /// will follow the first 100 addresses derived from this xpub on each keychain  and
    /// cache any transactions where those addresses appear. You can use either the integrated
    /// json-rpc or electrum server to fetch an addresses' history, balance and utxos.
    pub wallet_descriptor: Option<Vec<String>>,

    #[arg(long, value_name = "BLOCK_HASH")]
    /// Assume blocks before this one as having valid scripts
    ///
    /// Assume that blocks that are buried under a considerable work have valid scripts.
    /// We still do other checks, like amounts, UTXO existence, reward... the only check we
    /// skip is the script validation
    pub assume_valid: Option<String>,

    #[arg(long, short, value_name = "address[:<port>]")]
    /// An address for the ZeroMQ server to listen to
    ///
    /// ZeroMQ is a lightweight message queue for Inter Process Communication. If you connect
    /// with this server, it'll push new blocks after we fully validate it.
    pub zmq_address: Option<String>,

    #[arg(long, value_name = "address[:<port>]")]
    /// A node to connect to
    ///
    /// If this option is provided, we'll connect **only** to this node. It should be an ipv4
    /// address in the format <address>[:<port>]
    pub connect: Option<String>,

    #[arg(long, value_name = "address[:<port>]")]
    /// The address where our json-rpc server should listen to in the format <address>[:<port>]
    pub rpc_address: Option<String>,

    #[arg(long, value_name = "address[:<port>]")]
    /// The address where our electrum server should listen to in the format <address>[:<port>]
    pub electrum_address: Option<String>,

    #[arg(long, value_name = "address[:<port>]")]
    /// The address where our ssl electrum server should listen to in the format <address>[:<port>]
    pub ssl_electrum_address: Option<String>,

    #[arg(long, value_name = "HEIGHT")]
    /// Download block filters starting at this height. Negative numbers are relative to the current tip.
    pub filters_start_height: Option<i32>,

    #[arg(long)]
    /// Whether we should assume a utreexo state for a given height
    ///
    /// This option will significantly speed up the initial block download, by skipping the
    /// validation of the first hundreds of thousands of blocks. However, there's an inherent
    /// trust in the developer that the utreexo state is correct. Everything after the assumed
    /// height will be fully validated.
    pub assume_utreexo: bool,

    #[arg(long, value_name = "PATH")]
    /// Path to the SSL certificate file
    pub ssl_cert_path: Option<String>,

    #[arg(long, value_name = "PATH")]
    /// Path to the SSL private key file
    pub ssl_key_path: Option<String>,

    #[arg(long, default_value_t = false)]
    /// Whether to disable SSL
    pub no_ssl: bool,

    #[cfg(unix)]
    #[arg(long, default_value = "false")]
    /// Whether we should run as a daemon
    pub daemon: bool,

    #[cfg(unix)]
    #[arg(long, value_name = "FILE", requires = "daemon")]
    /// A file to write the process id to
    ///
    /// In case you're using the daemon option, and you want to know the process id, you can
    /// write it to a file. This option should be an absolute path to a file. Usually, you'd
    /// write it to $DATA_DIR/florestad.pid
    pub pid_file: Option<String>,
}
