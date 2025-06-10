use bitcoin::Network;
use clap::arg;
use clap::command;
use clap::Parser;

#[derive(Parser)]
#[command(
    author = "Davidson Souza",
    version = env!("GIT_DESCRIBE"),
    about = "florestad - a lightweight Bitcoin client",
    long_about = env!("LONG_VERSION"),
)]
pub struct Cli {
    #[arg(long, default_value_t = false)]
    /// Whether to disable DNS seeds
    pub disable_dns_seeds: bool,

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
    /// finding a utxo, finding specific tx_ids.
    /// Will cause more disk usage
    pub cfilters: bool,

    #[arg(long, short, default_value = None, value_name = "address[:<port>]")]
    /// The url of a proxy we should open p2p connections through (e.g. 127.0.0.1:9050)
    pub proxy: Option<String>,

    #[arg(long, value_name = "XPUB")]
    /// Add an xpub to our wallet
    ///
    /// This option can be passed many times, and will accept any SLIP039-valid extended
    /// public key. You only need to pass this once, but there's no harm in passing it
    /// more than once. After you start florestad at least once, passing some xpub, florestad
    /// will follow the first 100 addresses derived from this xpub on each keychain  and
    /// cache any transactions where those addresses appear. You can use either the integrated
    /// json-rpc or electrum server to fetch an address's history, balance and utxos.
    pub wallet_xpub: Option<Vec<String>>,

    #[arg(long, value_name = "DESCRIPTOR")]
    /// Add an output descriptor to our wallet
    ///
    /// This option can be passed many times, and will accept any valid output descriptor.
    /// You only need to pass this once, but there's no harm in passing it more than once.
    /// After you start florestad at least once, passing some xpub, florestad
    /// will follow the first 100 addresses derived from this xpub on each keychain  and
    /// cache any transactions where those addresses appear. You can use either the integrated
    /// json-rpc or electrum server to fetch an address's history, balance and utxos.
    pub wallet_descriptor: Option<Vec<String>>,

    #[arg(long, value_name = "BLOCK_HASH")]
    /// Assume blocks before this one, as having valid scripts
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

    #[arg(long, default_value_t = false)]
    /// Whether assume utreexo should be disabled.
    ///
    /// This option will disable assume utreexo. This feature allows the node to skip validation
    /// of historical blocks, making it ready-to-use in a shorter time than validating all blocks.
    /// Disabling it will cause the node to validate all blocks from genesis.
    ///
    /// By default, floresta will still validate those blocks and transactions on background until
    /// we reach the assumed tip. If you want to stop this behavior, use the --no-backfill flag.
    pub no_assume_utreexo: bool,

    #[arg(long, value_name = "PATH")]
    /// Path to the SSL certificate file (defaults to <data-dir>/ssl/cert.pem).
    ///
    /// The user should create a PKCS#8 based one with openssl. For example, you
    /// could create yourself a self-signed certificate with:
    ///
    /// openssl req -x509 -new -key key.pem -out cert.pem -days 365 -subj "/CN=localhost"
    ///
    /// alternatively, you can run florestad with --gen-selfsigned-cert
    pub ssl_cert_path: Option<String>,

    #[arg(long, value_name = "PATH")]
    /// Path to the SSL private key file (defaults to <data-dir>/ssl/key.pem).
    ///
    /// The user should create a PKCS#8 based one with openssl. For example, you
    /// could create yourself a key for a self-signed certificate:
    ///
    /// openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa_keygen_bits:2048
    pub ssl_key_path: Option<String>,

    #[arg(long, default_value_t = false)]
    /// Whether to disable SSL
    pub no_ssl: bool,

    #[arg(long, default_value_t = false)]
    /// Auto generates a ssl certificate in boot phase of florestad.
    ///
    /// It may conflict with other ssl related flags, please read the SSL Certificates section in README.md
    pub gen_selfsigned_cert: bool,

    #[arg(long, default_value_t = false)]
    /// Whether we should try to connect with peers using the old, unencrypted V1 P2P protocol,
    /// if we can't make a V2 connection.
    ///
    /// Note that for utreexod, we will still use V1, because it doesn't have V2 yet.
    /// (TODO: Update when they implement this)
    pub allow_v1_fallback: bool,

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

    #[arg(long, default_value_t = false)]
    /// Whether backfill should be disabled
    ///
    /// If we assumeutreexo or use pow fraud proofs, you have the option to download and validate
    /// the blocks that were skipped. This will take a long time, but will run on the background
    /// and won't affect the node's operation. You may notice that this will take a lot of CPU
    /// and bandwidth to run.
    ///
    /// The default behavior is verifying the blocks that were skipped during node startup.
    /// This will run in the background and wont't affect node's operation. However,
    /// to disable backfilling, run floresta using this flag.
    pub no_backfill: bool,
}
