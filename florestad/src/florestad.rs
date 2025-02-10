use std::fmt::Arguments;
use std::fs;
use std::fs::File;
use std::io::BufReader;
#[cfg(feature = "metrics")]
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;
use std::sync::Mutex;
#[cfg(feature = "json-rpc")]
use std::sync::OnceLock;

pub use bitcoin::Network;
use fern::colors::Color;
use fern::colors::ColoredLevelConfig;
use fern::FormatCallback;
#[cfg(feature = "experimental-db")]
use floresta_chain::pruned_utreexo::flat_chain_store::FlatChainStore as ChainStore;
#[cfg(feature = "experimental-db")]
use floresta_chain::pruned_utreexo::flat_chain_store::FlatChainStoreConfig;
#[cfg(feature = "zmq-server")]
use floresta_chain::pruned_utreexo::BlockchainInterface;
pub use floresta_chain::AssumeUtreexoValue;
use floresta_chain::AssumeValidArg;
use floresta_chain::BlockchainError;
use floresta_chain::ChainState;
#[cfg(not(feature = "experimental-db"))]
use floresta_chain::KvChainStore as ChainStore;
#[cfg(feature = "compact-filters")]
use floresta_compact_filters::flat_filters_store::FlatFiltersStore;
#[cfg(feature = "compact-filters")]
use floresta_compact_filters::network_filters::NetworkFilters;
use floresta_electrum::electrum_protocol::client_accept_loop;
use floresta_electrum::electrum_protocol::ElectrumServer;
use floresta_watch_only::kv_database::KvDatabase;
use floresta_watch_only::AddressCache;
use floresta_watch_only::AddressCacheDatabase;
use floresta_wire::address_man::AddressMan;
use floresta_wire::mempool::Mempool;
use floresta_wire::node::UtreexoNode;
use floresta_wire::running_node::RunningNode;
use floresta_wire::UtreexoNodeConfig;
use futures::channel::oneshot;
use futures::executor::block_on;
use log::debug;
use log::error;
use log::info;
use log::warn;
use log::Record;
use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::IsCa;
use rcgen::KeyPair;
use rustreexo::accumulator::pollard::Pollard;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::task;
#[cfg(feature = "metrics")]
use tokio::time::Duration;
#[cfg(feature = "metrics")]
use tokio::time::{self};
use tokio_rustls::rustls::internal::pemfile::certs;
use tokio_rustls::rustls::internal::pemfile::pkcs8_private_keys;
use tokio_rustls::rustls::NoClientAuth;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::config_file::ConfigFile;
use crate::error;
#[cfg(feature = "json-rpc")]
use crate::json_rpc;
use crate::wallet_input::InitialWalletSetup;
#[cfg(feature = "zmq-server")]
use crate::zmq::ZMQServer;

#[derive(Clone)]
/// General configuration for the floresta daemon.
///
/// Those configs should be passed in by anyone that wants to start a floresta instance. Some of
/// these are also exposed through the config file.
pub struct Config {
    /// Whether we should disable dns seeds
    pub disable_dns_seeds: bool,
    /// Where we should place our data
    ///
    /// This directory must be readable and writable by our process. We'll use this dir to store
    /// both chain and wallet data, so this should be kept in a non-volatile medium. We are not
    /// particularly aggressive in disk usage, so we don't need a fast disk to work.
    ///
    /// If not set, it defaults to $HOME/.floresta
    pub data_dir: Option<String>,
    /// We consider blocks prior to this one to have a valid signature
    ///
    /// This is an optimization mirrored from Core, where blocks before this one are considered to
    /// have valid signatures. The idea here is that if a block is buried under a lot of PoW, it's
    /// very unlikely that it is invalid. We still validate everything else and build the
    /// accumulator until this point (unless running on PoW-fraud proof or assumeutreexo mode) so
    /// there's still some work to do.
    pub assume_valid: Option<String>,
    /// A vector of xpubs to cache
    ///
    /// This is a list of SLIP-132-encoded extended public key that we should add to our Watch-only
    /// wallet. A descriptor may be only passed one time, if you call florestad with an already
    /// cached address, that will be a no-op. After a xpub is cached, we derive multiple addresses
    /// from it and try to find transactions involving it.
    pub wallet_xpub: Option<Vec<String>>,
    /// An output descriptor to cache
    ///
    /// This should be a list of output descriptors that we should add to our watch-only wallet.
    /// This works just like wallet_xpub, but with a descriptor.
    pub wallet_descriptor: Option<Vec<String>>,
    /// Where should we read from a config file
    ///
    /// This is a toml-encoded file with floresta's configs. For a sample of how this file looks
    /// like, see config.toml.sample inside floresta's codebase.
    ///
    /// If a setting is modified by the config file and this config struct, the following logic is
    /// used:
    ///     - For vectors, we use the combination of both vectors
    ///     - for mutually exclusive options, this struct has precedence over the config file
    pub config_file: Option<String>,
    /// A proxy that we should use to connect with others
    ///
    /// This should be a socks5 proxy, like Tor's socks. If provided, all our outgoing connections
    /// will be made through this one, except dns seed connections.
    pub proxy: Option<String>,
    /// The network we are running in, it may be one of: bitcoin, signet, regtest or testnet.
    pub network: Network,
    /// Whether we should build and store compact block filters
    ///
    /// Those filters are used for rescanning our wallet for historical transactions. If you don't
    /// have this on, the only way to find historical transactions is to download all blocks, which
    /// is very inefficient and resource/time consuming. But keep in mind that filters will take
    /// up disk space.
    pub cfilters: bool,
    /// If we are using block filters, we may not need to download the whole chain of filters, as
    /// our wallets may not have been created at the beginning of the chain. With this option, we
    /// can make a rough estimate of the block height we need to start downloading filters.
    ///
    /// If the value is negative, it's relative to the current tip. For example, if the current tip
    /// is at height 1000, and we set this value to -100, we will start downloading filters from
    /// height 900.
    pub filters_start_height: Option<i32>,
    #[cfg(feature = "zmq-server")]
    /// The address to listen to for our ZMQ server
    ///
    /// We have an (optional) ZMQ server, that pushes new blocks over a PUSH/PULL ZMQ queue, this
    /// is the address that we'll listen for incoming connections.
    pub zmq_address: Option<String>,
    pub connect: Option<String>,
    #[cfg(feature = "json-rpc")]
    /// The address our json-rpc should listen to
    pub json_rpc_address: Option<String>,
    /// The address our electrum server should listen to
    pub electrum_address: Option<String>,
    /// The address for ssl electrum server
    pub ssl_electrum_address: Option<String>,
    /// Whether we should write logs to the stdio
    pub log_to_stdout: bool,
    /// Whether we should log to a fs file
    pub log_to_file: bool,
    /// Whether we should use assume utreexo
    pub assume_utreexo: bool,
    /// Whether we should post debug information to the console
    pub debug: bool,
    /// The user agent that we will advertise to our peers
    pub user_agent: String,
    /// The value to use for assumeutreexo
    pub assumeutreexo_value: Option<AssumeUtreexoValue>,
    /// Path to the SSL certificate file (defaults to `{data_dir}/ssl/cert.pem`).
    ///
    /// The user should create a PKCS#8 based one with openssl. For example:
    ///
    /// openssl req -x509 -new -key key.pem -out cert.pem -days 365 -subj "/CN=localhost"
    pub ssl_cert_path: Option<String>,
    /// Path to the SSL private key file (defaults to `{data_dir}/ssl/key.pem`).
    ///
    /// The user should create a PKCS#8 based one with openssl. For example:
    ///
    /// openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa_keygen_bits:2048
    pub ssl_key_path: Option<String>,
    /// Whether to disable SSL for the Electrum server
    pub no_ssl: bool,
    /// Whether to create self signed certificate for ssl_key_path and ssl_cert_path
    pub gen_selfsigned_cert: bool,
    /// Whether to allow fallback to v1 transport if v2 connection fails.
    pub allow_v1_fallback: bool,
    /// Whehter we should backfill
    ///
    /// If we assumeutreexo or use pow fraud proofs, you have the option to download and validate
    /// the blocks that were skipped. This will take a long time, but will run on the background
    /// and won't affect the node's operation. You may notice that this will take a lot of CPU
    /// and bandwidth to run.
    pub backfill: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            disable_dns_seeds: false,
            data_dir: None,
            assume_valid: None,
            wallet_xpub: None,
            wallet_descriptor: None,
            config_file: None,
            proxy: None,
            network: Network::Bitcoin,
            cfilters: false,
            filters_start_height: None,
            #[cfg(feature = "zmq-server")]
            zmq_address: None,
            connect: None,
            #[cfg(feature = "json-rpc")]
            json_rpc_address: None,
            electrum_address: None,
            ssl_electrum_address: None,
            log_to_stdout: false,
            log_to_file: false,
            assume_utreexo: false,
            debug: false,
            user_agent: String::default(),
            assumeutreexo_value: None,
            ssl_cert_path: None,
            ssl_key_path: None,
            no_ssl: false,
            gen_selfsigned_cert: false,
            allow_v1_fallback: false,
            backfill: false,
        }
    }
}

pub struct Florestad {
    /// The config used by this node, see [Config] for more details
    config: Config,
    /// A channel that tells others to stop what they are doing because we
    /// are about to die
    stop_signal: Arc<RwLock<bool>>,
    /// A channel that notifies we are done, and it's safe to die now
    stop_notify: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
    #[cfg(feature = "json-rpc")]
    /// A handle to our json-rpc server
    json_rpc: OnceLock<tokio::task::JoinHandle<()>>,
}

impl Florestad {
    /// Kills a running florestad, this will return as soon as the main node stops.
    ///
    /// It's not safe to stop your program before this thread returns because some
    /// information may not be fully flushed to disk yet, and killing the process
    /// before flushing everything is equivalent to an unclean shutdown.
    #[allow(unused)]
    pub fn stop(&self) {
        block_on(async move {
            *self.stop_signal.write().await = true;
            let chan = {
                let mut guard = self.stop_notify.lock().unwrap();
                std::mem::take(&mut *guard)
            };
            if let Some(chan) = chan {
                if let Err(e) = chan.await {
                    error!("POSSIBLE BUG: unexpected error while shutting down {e:?}");
                }
            }
        });
    }

    pub fn should_stop(&self) -> bool {
        let stop_signal = self.stop_signal.clone();
        block_on(async { *stop_signal.read().await })
    }

    pub fn get_stop_signal(&self) -> Arc<RwLock<bool>> {
        self.stop_signal.clone()
    }

    pub async fn wait_shutdown(&self) {
        let chan = {
            let mut guard = self.stop_notify.lock().unwrap();
            std::mem::take(&mut *guard)
        };
        if let Some(chan) = chan {
            if let Err(e) = chan.await {
                error!("POSSIBLE BUG: unexpected error while shutting down {e:?}");
            }
        }
    }

    /// Parses an address in the format `<hostname>[<:port>]` and returns a
    /// `SocketAddr` with the resolved IP address. If a hostname is provided,
    /// it will be resolved using the system's DNS resolver. This function will
    /// exit the program if it fails to resolve the hostname or the provided
    /// address is invalid.
    fn get_ip_address(hostname: &str, default_port: u16) -> SocketAddr {
        if !hostname.contains(':') {
            let Ok(ip) = hostname.parse() else {
                error!("Invalid IP address: {hostname}");
                exit(1);
            };

            return SocketAddr::new(ip, default_port);
        }

        let ip = hostname.parse();
        match ip {
            Ok(ip) => ip,
            Err(_) => {
                let mut split = hostname.split(':');
                let hostname = split.next().unwrap();

                debug!("Resolving hostname: {hostname}");

                let ips: Vec<_> = match dns_lookup::lookup_host(hostname) {
                    Ok(ips) => ips,
                    Err(e) => {
                        error!("Could not resolve hostname: {e}");
                        exit(1);
                    }
                };

                if ips.is_empty() {
                    error!("No IP addresses found for hostname: {}", hostname);
                    exit(1);
                }

                let port = split
                    .next()
                    .map(|x| x.parse().unwrap_or(default_port))
                    .unwrap_or(default_port);

                SocketAddr::new(ips[0], port)
            }
        }
    }

    /// Actually runs florestad, spawning all modules and waiting until
    /// someone asks to stop.
    pub fn start(&self) {
        // Setup global logger
        let data_dir = self
            .config
            .data_dir
            .clone()
            .or_else(|| {
                dirs::home_dir().map(|x: PathBuf| {
                    format!(
                        "{}/{}/",
                        x.to_str().unwrap_or_default().to_owned(),
                        ".floresta",
                    )
                })
            })
            .unwrap_or("floresta".into());
        let data_dir = match self.config.network {
            Network::Bitcoin => data_dir,
            Network::Signet => data_dir + "/signet/",
            Network::Testnet => data_dir + "/testnet3/",
            Network::Testnet4 => data_dir + "/testnet4/",
            Network::Regtest => data_dir + "/regtest/",
            // TODO: handle possible Err
            _ => panic!("This network is not supported: {}", self.config.network),
        };

        // create the data directory if it doesn't exist
        if !std::path::Path::new(&data_dir).exists() {
            std::fs::create_dir_all(&data_dir).expect("Could not create data directory");
        }

        if self.config.log_to_stdout || self.config.log_to_file {
            Self::setup_logger(
                &data_dir,
                self.config.log_to_file,
                self.config.log_to_stdout,
                self.config.debug,
            )
            .expect("Failure to setup logger");
        }

        // The config file inside our datadir directory. Any datadir
        // passed as argument will be used instead
        let system_config_file = format!("{data_dir}/config.toml");
        let config_file = match &self.config.config_file {
            Some(path) => Self::get_config_file(path),
            None => Self::get_config_file(&system_config_file),
        };

        // Load the watch-only wallet
        debug!("Loading wallet");
        let mut wallet = Self::load_wallet(&data_dir);
        wallet.setup().expect("Could not initialize wallet");
        debug!("Done loading wallet");

        // Try to add more wallets to watch if needed
        let result = Self::setup_wallet(
            Self::get_both_vec(self.config.wallet_xpub.clone(), config_file.wallet.xpubs),
            Self::get_both_vec(
                self.config.wallet_descriptor.clone(),
                config_file.wallet.descriptors,
            ),
            Self::get_both_vec(config_file.wallet.addresses.clone(), None),
            &mut wallet,
            self.config.network,
        );

        if let Err(e) = result {
            log::error!("Something went wrong while setting wallet up: {e}");
            return;
        }

        info!("Loading blockchain database");
        let blockchain_state = Arc::new(Self::load_chain_state(
            data_dir.clone(),
            self.config.network,
            self.config
                .assume_valid
                .as_ref()
                .map(|value| value.parse().expect("Invalid assumevalid")),
        ));

        #[cfg(feature = "compact-filters")]
        let cfilters = if self.config.cfilters {
            // Block Filters
            let filter_store = FlatFiltersStore::new((data_dir.clone() + "/cfilters").into());
            let cfilters = Arc::new(NetworkFilters::new(filter_store));
            info!(
                "Loaded compact filters store at height: {:?}",
                cfilters.get_height().unwrap()
            );
            Some(cfilters)
        } else {
            None
        };

        #[cfg(not(feature = "compact-filters"))]
        let cfilters = None;

        // For now, we only have compatible bridges on signet
        let pow_fraud_proofs = match self.config.network {
            Network::Bitcoin => false,
            Network::Signet => true,
            Network::Testnet => false,
            Network::Regtest => false,
            _ => false,
        };

        // If this network already allows pow fraud proofs, we should use it instead of assumeutreexo
        let assume_utreexo = match (pow_fraud_proofs, self.config.assume_utreexo) {
            (false, true) => Some(
                floresta_chain::ChainParams::get_assume_utreexo(self.config.network)
                    .expect("Network already validated as supported"),
            ),
            _ => None,
        };

        let config = UtreexoNodeConfig {
            disable_dns_seeds: self.config.disable_dns_seeds,
            network: self.config.network,
            pow_fraud_proofs,
            proxy: self
                .config
                .proxy
                .as_ref()
                .map(|host| Self::get_ip_address(host, 9050)),
            datadir: data_dir.clone(),
            fixed_peer: self.config.connect.clone(),
            max_banscore: 50,
            compact_filters: self.config.cfilters,
            max_outbound: 10,
            max_inflight: 20,
            assume_utreexo: self.config.assumeutreexo_value.clone().or(assume_utreexo),
            backfill: self.config.backfill,
            filter_start_height: self.config.filters_start_height,
            user_agent: self.config.user_agent.clone(),
            allow_v1_fallback: self.config.allow_v1_fallback,
        };

        let acc = Pollard::new();
        let kill_signal = self.stop_signal.clone();

        // Chain Provider (p2p)
        let chain_provider = UtreexoNode::<_, RunningNode>::new(
            config,
            blockchain_state.clone(),
            Arc::new(tokio::sync::Mutex::new(Mempool::new(acc, 300_000_000))),
            cfilters.clone(),
            kill_signal.clone(),
            AddressMan::default(),
        )
        .expect("Could not create a chain provider");

        // ZMQ
        #[cfg(feature = "zmq-server")]
        {
            info!("Starting ZMQ server");
            if let Ok(zserver) = ZMQServer::new(
                self.config
                    .zmq_address
                    .as_ref()
                    .unwrap_or(&"tcp://127.0.0.1:5150".to_string()),
            ) {
                blockchain_state.subscribe(Arc::new(zserver));
                info!("Done!");
            } else {
                error!("Could not create zmq server, skipping");
            };
        }

        info!("Starting server");
        let wallet = Arc::new(wallet);

        // JSON-RPC
        #[cfg(feature = "json-rpc")]
        {
            let server = tokio::spawn(json_rpc::server::RpcImpl::create(
                blockchain_state.clone(),
                wallet.clone(),
                chain_provider.get_handle(),
                self.stop_signal.clone(),
                self.config.network,
                cfilters.clone(),
                self.config
                    .json_rpc_address
                    .as_ref()
                    .map(|x| Self::get_ip_address(x, 8332)),
                data_dir.clone() + "output.log",
            ));

            if self.json_rpc.set(server).is_err() {
                core::panic!("We should be the first one setting this");
            }
        }

        // Electrum
        let e_addr = self
            .config
            .electrum_address
            .clone()
            .map(|addr| Self::get_ip_address(&addr, 50001))
            .unwrap_or("0.0.0.0:50001".parse().expect("Hardcoded address"));

        // generate self-signed certificate if provided
        if self.config.gen_selfsigned_cert {
            // create ssl dir if not exists
            let ssl_dir = format!("{}ssl", &data_dir);
            if !Path::new(&ssl_dir).exists() {
                warn!("creating {}", &ssl_dir);
                fs::create_dir_all(&ssl_dir).expect("Could not create data directory");
            }

            //  create information for self-signed certificate about the current node
            let subject_alt_names = vec!["localhost".to_string()];

            // define file paths
            let key_path = format!("{}ssl/key.pem", &data_dir);
            let cert_path = format!("{}ssl/cert.pem", &data_dir);

            match Florestad::generate_selfsigned_certificate(
                key_path.clone(),
                cert_path.clone(),
                subject_alt_names,
            ) {
                Ok(()) => {
                    warn!("PKCS#8 private-key'{}' created", &key_path);
                    warn!("PKCS#8 self-signed certificate '{}' created", &cert_path);
                }
                Err(err) => {
                    warn!("Failed to generate SSL certificate: '{}'", err);
                }
            }
        }

        let ssl_e_addr = self
            .config
            .ssl_electrum_address
            .clone()
            .map(|addr| Self::get_ip_address(&addr, 50002))
            .unwrap_or("0.0.0.0:50002".parse().expect("Hardcoded address"));

        // Load TLS configuration if needed
        let tls_config = if !self.config.no_ssl {
            match self.create_tls_config(&data_dir) {
                Ok(config) => Some(config),
                Err(e) => {
                    warn!("Failed to load SSL certificates: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let tls_acceptor = tls_config.map(TlsAcceptor::from);

        let electrum_server = block_on(ElectrumServer::new(
            wallet,
            blockchain_state,
            cfilters,
            chain_provider.get_handle(),
        ))
        .expect("Could not create an Electrum Server");

        // Spawn all services

        // Non-TLS Electrum accept loop
        let non_tls_listener = match block_on(TcpListener::bind(e_addr)) {
            Ok(listener) => Arc::new(listener),
            Err(_) => {
                error!(
                    "Failed to bind to address {}. An Electrum server is probably already running.",
                    e_addr
                );
                std::process::exit(1);
            }
        };
        task::spawn(client_accept_loop(
            non_tls_listener,
            electrum_server.message_transmitter.clone(),
            None,
        ));

        // TLS Electrum accept loop
        if let Some(tls_acceptor) = tls_acceptor {
            let tls_listener = match block_on(TcpListener::bind(ssl_e_addr)) {
                Ok(listener) => Arc::new(listener),
                Err(_) => {
                    error!("Failed to bind to address {}. An SSL Electrum server is probably already running.", e_addr);
                    std::process::exit(1);
                }
            };

            info!("TLS server running on: {ssl_e_addr}");
            task::spawn(client_accept_loop(
                tls_listener,
                electrum_server.message_transmitter.clone(),
                Some(tls_acceptor),
            ));
        }

        // Electrum main loop
        task::spawn(electrum_server.main_loop());
        info!("Server running on: {}", e_addr);

        // Chain provider
        let (sender, receiver) = oneshot::channel();

        let mut recv = self.stop_notify.lock().unwrap();
        *recv = Some(receiver);

        task::spawn(chain_provider.run(sender));

        // Metrics
        #[cfg(feature = "metrics")]
        {
            let metrics_server_address =
                SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 3333);
            task::spawn(metrics::metrics_server(metrics_server_address));
            info!(
                "Started metrics server on: {}",
                metrics_server_address.to_string()
            );

            // Periodically update memory usage
            tokio::spawn(async {
                let interval = Duration::from_secs(5);
                let mut ticker = time::interval(interval);

                loop {
                    ticker.tick().await;
                    metrics::get_metrics().update_memory_usage();
                }
            });
        }
    }

    fn setup_logger(
        data_dir: &String,
        log_file: bool,
        log_to_stdout: bool,
        debug: bool,
    ) -> Result<(), fern::InitError> {
        let colors = ColoredLevelConfig::new()
            .error(Color::Red)
            .warn(Color::Yellow)
            .info(Color::Green)
            .debug(Color::Blue)
            .trace(Color::BrightBlack);

        let formatter = |use_colors: bool| {
            move |out: FormatCallback, message: &Arguments, record: &Record| {
                out.finish(format_args!(
                    "[{} {} {}] {}",
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                    match use_colors {
                        true => colors.color(record.level()).to_string(),
                        false => record.level().to_string(),
                    },
                    record.target(),
                    message
                ))
            }
        };

        let mut dispatchers = fern::Dispatch::new();
        let stdout_dispatcher = fern::Dispatch::new()
            .format(formatter(true))
            .level(if debug {
                log::LevelFilter::Debug
            } else {
                log::LevelFilter::Info
            })
            .chain(std::io::stdout());

        let file_dispatcher = fern::Dispatch::new()
            .format(formatter(false))
            .level(log::LevelFilter::Info)
            .chain(fern::log_file(format!("{data_dir}/output.log"))?);

        if log_file {
            dispatchers = dispatchers.chain(file_dispatcher);
        }

        if log_to_stdout {
            dispatchers = dispatchers.chain(stdout_dispatcher);
        }

        dispatchers.apply()?;

        Ok(())
    }

    pub fn from_config(config: Config) -> Self {
        Self {
            config,
            stop_signal: Arc::new(RwLock::new(false)),
            stop_notify: Arc::new(Mutex::new(None)),
            #[cfg(feature = "json-rpc")]
            json_rpc: OnceLock::new(),
        }
    }

    pub fn new() -> Self {
        Self::from_config(Config::default())
    }

    /// Loads a config file from disk, returns default if it cannot load it
    fn get_config_file(path: &str) -> ConfigFile {
        let data = ConfigFile::from_file(path);

        if let Ok(data) = data {
            data
        } else {
            match data.unwrap_err() {
                crate::error::Error::TomlParsing(e) => {
                    warn!("Could not parse config file, ignoring it");
                    debug!("{e}");
                    ConfigFile::default()
                }
                crate::error::Error::Io(e) => {
                    warn!("Could not read config file, ignoring it");
                    debug!("{e}");
                    ConfigFile::default()
                }
                // Shouldn't be any other error
                _ => unreachable!(),
            }
        }
    }

    fn get_key_from_env() -> Option<String> {
        let xpub = std::env::var("WALLET_XPUB");
        match xpub {
            Ok(key) => return Some(key),
            Err(e) => match e {
                std::env::VarError::NotPresent => {}
                std::env::VarError::NotUnicode(xpub) => error!("Invalid xpub {xpub:?}"),
            },
        }
        None
    }

    #[cfg(feature = "experimental-db")]
    fn load_chain_store(data_dir: String) -> ChainStore {
        let config = FlatChainStoreConfig::new(data_dir + "/chaindata");
        ChainStore::new(config).expect("failure while creating chainstate")
    }

    #[cfg(not(feature = "experimental-db"))]
    fn load_chain_state(
        data_dir: String,
        network: Network,
        assume_valid: Option<bitcoin::BlockHash>,
    ) -> ChainState<ChainStore<'static>> {
        let db = ChainStore::new(data_dir.clone()).expect("Could not read db");
        let assume_valid =
            assume_valid.map_or(AssumeValidArg::Hardcoded, AssumeValidArg::UserInput);

        match ChainState::<ChainStore>::load_chain_state(db, network, assume_valid) {
            Ok(chainstate) => chainstate,
            Err(err) => match err {
                BlockchainError::ChainNotInitialized => {
                    let db = ChainStore::new(data_dir).expect("Could not read db");

                    ChainState::<ChainStore>::new(db, network, assume_valid)
                }
                _ => unreachable!(),
            },
        }
    }

    #[cfg(feature = "experimental-db")]
    fn load_chain_state(
        data_dir: String,
        network: Network,
        assume_valid: Option<bitcoin::BlockHash>,
    ) -> ChainState<ChainStore> {
        let db = Self::load_chain_store(data_dir.clone());
        let assume_valid =
            assume_valid.map_or(AssumeValidArg::Hardcoded, AssumeValidArg::UserInput);

        match ChainState::<ChainStore>::load_chain_state(db, network, assume_valid) {
            Ok(chainstate) => chainstate,
            Err(err) => match err {
                BlockchainError::ChainNotInitialized => {
                    let db = Self::load_chain_store(data_dir);

                    ChainState::<ChainStore>::new(db, network, assume_valid)
                }
                _ => unreachable!(),
            },
        }
    }

    fn load_wallet(data_dir: &String) -> AddressCache<KvDatabase> {
        match KvDatabase::new(data_dir.to_owned()) {
            Ok(database) => AddressCache::new(database),
            Err(_) => {
                error!("Cannot obtain a lock on data directory {data_dir}. Floresta is probably already running.");
                std::process::exit(1);
            }
        }
    }

    fn setup_wallet<D: AddressCacheDatabase>(
        mut xpubs: Vec<String>,
        descriptors: Vec<String>,
        addresses: Vec<String>,
        wallet: &mut AddressCache<D>,
        network: Network,
    ) -> anyhow::Result<()> {
        if let Some(key) = Self::get_key_from_env() {
            xpubs.push(key);
        }
        let setup = InitialWalletSetup::build(&xpubs, &descriptors, &addresses, network, 100)?;
        for descriptor in setup.descriptors {
            let descriptor = descriptor.to_string();
            if !wallet.is_cached(&descriptor)? {
                wallet.push_descriptor(&descriptor)?;
            }
        }
        for addresses in setup.addresses {
            wallet.cache_address(addresses.script_pubkey());
        }
        info!("Wallet setup completed!");
        anyhow::Ok(())
    }

    fn get_both_vec<T>(a: Option<Vec<T>>, b: Option<Vec<T>>) -> Vec<T> {
        let mut result: Vec<T> = Vec::new();
        if let Some(a) = a {
            result.extend(a);
        }
        if let Some(b) = b {
            result.extend(b);
        }
        result
    }

    /// Create a self_signed certificate signed by
    /// a private key created on the fly
    pub fn generate_selfsigned_certificate(
        key_path: String,
        cert_path: String,
        subject_alt_names: Vec<String>,
    ) -> Result<(), error::Error> {
        // Generate a key pair
        let key_pair = KeyPair::generate().map_err(error::Error::CouldNotGenerateKeypair)?;

        // Generate self-signed certificate
        let mut params = CertificateParams::new(subject_alt_names)
            .map_err(error::Error::CouldNotGenerateCertParam)?;

        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let selfcert = params
            .self_signed(&key_pair)
            .map_err(error::Error::CouldNotGenerateSelfSignedCert)?;

        // Create files
        fs::write(&key_path, key_pair.serialize_pem())
            .map_err(|err| error::Error::CouldNotWriteFile(key_path, err))?;

        fs::write(&cert_path, selfcert.pem())
            .map_err(|err| error::Error::CouldNotWriteFile(cert_path, err))?;

        Ok(())
    }

    /// Create tls configuration with a PKCS#8 formatted key and certificates and
    /// defaults to `<data-dir>/ssl/cert.pem` and `<data-dir>/ssl/key.pem`.
    ///
    /// It will check if those files are well formated to PKCS#8 structure
    /// and if it was in wrong structure, will exit with logs.
    ///
    /// If pass the check process, it will try to open those files and, if not exist,
    /// florestad will skip the SSL configuration.
    fn create_tls_config(&self, data_dir: &str) -> Result<Arc<ServerConfig>, error::Error> {
        // Use an agnostic way to build paths for platforms and fix the differences
        // in how Unix and Windows represent strings, maybe a user could use a weird
        // string on his/her path.
        //
        // See more at https://doc.rust-lang.org/std/ffi/struct.OsStr.html#method.to_string_lossy
        let cert_path = self.config.ssl_cert_path.clone().unwrap_or_else(|| {
            PathBuf::from(&data_dir)
                .join("ssl")
                .join("cert.pem")
                .to_string_lossy()
                .into_owned()
        });

        let key_path = self.config.ssl_key_path.clone().unwrap_or_else(|| {
            PathBuf::from(&data_dir)
                .join("ssl")
                .join("key.pem")
                .to_string_lossy()
                .into_owned()
        });

        // Convert paths to Path for system-agnostic handling
        let cert_path = Path::new(&cert_path);
        let key_path = Path::new(&key_path);

        // Check if certificate really exists and handle error if not exists
        let cert_file = File::open(cert_path)
            .map_err(|e| error::Error::CouldNotOpenCertFile(cert_path.display().to_string(), e))?;

        // Check if private key really exists and handle error if not exists
        let key_file = File::open(key_path).map_err(|e| {
            error::Error::CouldNotOpenPrivKeyFile(cert_path.display().to_string(), e)
        })?;

        // Parse certificate chain and handle error if exist any
        let cert_chain = certs(&mut BufReader::new(cert_file))
            .map_err(|_e| error::Error::InvalidCert(cert_path.display().to_string()))?;

        // Create private key vector and handle error if exist any
        let mut keys = pkcs8_private_keys(&mut BufReader::new(key_file))
            .map_err(|_e| error::Error::InvalidPrivKey(key_path.display().to_string()))?;

        // Check if the key's vector are empty
        if keys.is_empty() {
            return Err(error::Error::EmptyPrivKeySet(
                key_path.display().to_string(),
            ));
        }

        // Check if nothing goes wrong
        let mut config = ServerConfig::new(Arc::new(NoClientAuth));
        config
            .set_single_cert(cert_chain, keys.remove(0))
            .map_err(error::Error::CouldNotConfigureTLS)?;

        Ok(Arc::new(config))
    }
}

impl Default for Florestad {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Config> for Florestad {
    fn from(config: Config) -> Self {
        Self {
            config,
            stop_signal: Arc::new(RwLock::new(false)),
            stop_notify: Arc::new(Mutex::new(None)),
            #[cfg(feature = "json-rpc")]
            json_rpc: OnceLock::new(),
        }
    }
}
