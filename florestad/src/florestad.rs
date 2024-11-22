use core::panic;
use std::fmt::Arguments;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::net::SocketAddr;
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
#[cfg(feature = "zmq-server")]
use floresta_chain::pruned_utreexo::BlockchainInterface;
pub use floresta_chain::AssumeUtreexoValue;
use floresta_chain::AssumeValidArg;
use floresta_chain::BlockchainError;
use floresta_chain::ChainState;
use floresta_chain::KvChainStore;
#[cfg(feature = "compact-filters")]
use floresta_compact_filters::flat_filters_store::FlatFiltersStore;
#[cfg(feature = "compact-filters")]
use floresta_compact_filters::network_filters::NetworkFilters;
use floresta_electrum::electrum_protocol::client_accept_loop;
use floresta_electrum::electrum_protocol::ElectrumServer;
use floresta_watch_only::kv_database::KvDatabase;
use floresta_watch_only::AddressCache;
use floresta_watch_only::AddressCacheDatabase;
use floresta_wire::mempool::Mempool;
use floresta_wire::node::UtreexoNode;
use floresta_wire::UtreexoNodeConfig;
use futures::channel::oneshot;
use futures::executor::block_on;
use log::debug;
use log::error;
use log::info;
use log::warn;
use log::Record;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::task;
use tokio_rustls::rustls::internal::pemfile::certs;
use tokio_rustls::rustls::internal::pemfile::pkcs8_private_keys;
use tokio_rustls::rustls::NoClientAuth;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::config_file::ConfigFile;
#[cfg(feature = "json-rpc")]
use crate::json_rpc;
use crate::wallet_input::InitialWalletSetup;
#[cfg(feature = "zmq-server")]
use crate::zmq::ZMQServer;

#[derive(Default, Clone)]
/// General configuration for the floresta daemon.
///
/// Those configs should be passed in by anyone that wants to start a floresta instance. Some of
/// these are also exposed through the config file.
pub struct Config {
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
    /// This should be a list of ouptut descriptors that we should add to our watch-only wallet.
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
    pub network: crate::Network,
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
    /// Path to the SSL certificate file
    pub ssl_cert_path: Option<String>,
    /// Path to the SSL private key file
    pub ssl_key_path: Option<String>,
    /// Whether to disable SSL for the Electrum server
    pub no_ssl: bool,
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
    json_rpc: OnceLock<jsonrpc_http_server::Server>,
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

    /// Actually runs florestad, spawning all modules and waiting util
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
            crate::Network::Bitcoin => data_dir,
            crate::Network::Signet => data_dir + "/signet/",
            crate::Network::Testnet => data_dir + "/testnet3/",
            crate::Network::Regtest => data_dir + "/regtest/",
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
            .expect("failure to setup logger");
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

        info!("loading blockchain database");
        let datadir2 = data_dir.clone();
        let blockchain_state = Arc::new(Self::load_chain_state(
            datadir2,
            Self::get_net(&self.config.network),
            self.config
                .assume_valid
                .as_ref()
                .map(|value| value.parse().expect("invalid assumevalid")),
        ));

        #[cfg(feature = "compact-filters")]
        let cfilters = if self.config.cfilters {
            // Block Filters
            let filter_store = FlatFiltersStore::new((data_dir.clone() + "/cfilters").into());
            let cfilters = Arc::new(NetworkFilters::new(filter_store));
            info!(
                "loaded compact filters store at height: {:?}",
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
            crate::Network::Bitcoin => false,
            crate::Network::Signet => true,
            crate::Network::Testnet => false,
            crate::Network::Regtest => false,
        };

        // If this network already allows pow fraud proofs, we should use it instead of assumeutreexo
        let assume_utreexo = match (pow_fraud_proofs, self.config.assume_utreexo) {
            (false, true) => Some(floresta_chain::ChainParams::get_assume_utreexo(
                Self::get_net(&self.config.network).into(),
            )),
            _ => None,
        };

        let config = UtreexoNodeConfig {
            network: Self::get_net(&self.config.network),
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
            backfill: false,
            filter_start_height: self.config.filters_start_height,
            user_agent: self.config.user_agent.clone(),
        };

        // Chain Provider (p2p)
        let chain_provider = UtreexoNode::new(
            config,
            blockchain_state.clone(),
            Arc::new(tokio::sync::RwLock::new(Mempool::new())),
            cfilters.clone(),
        )
        .expect("Could not create a chain provider");

        // ZMQ
        #[cfg(feature = "zmq-server")]
        {
            info!("Starting ZMQ server");
            if let Ok(zserver) = ZMQServer::new(
                &self
                    .config
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
            let runtime_handle = tokio::runtime::Handle::current();

            let server = json_rpc::server::RpcImpl::create(
                blockchain_state.clone(),
                wallet.clone(),
                chain_provider.get_handle(),
                self.stop_signal.clone(),
                Self::get_net(&self.config.network),
                cfilters.clone(),
                self.config
                    .json_rpc_address
                    .as_ref()
                    .map(|x| Self::get_ip_address(x, 8332)),
                runtime_handle,
            );

            if self.json_rpc.set(server).is_err() {
                panic!("we should be the first one setting this");
            }
        }

        // Electrum
        let e_addr = self
            .config
            .electrum_address
            .clone()
            .map(|addr| Self::get_ip_address(&addr, 50001))
            .unwrap_or("0.0.0.0:50001".parse().expect("hardcoded address"));

        let ssl_e_addr = self
            .config
            .ssl_electrum_address
            .clone()
            .map(|addr| Self::get_ip_address(&addr, 50002))
            .unwrap_or("0.0.0.0:50002".parse().expect("hardcoded address"));

        // Load TLS configuration if needed
        let tls_config = if !self.config.no_ssl {
            match self.create_tls_config(&data_dir) {
                Ok(config) => Some(config),
                Err(_) => {
                    warn!("Failed to load SSL certificates, ignoring SSL");
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
        let non_tls_listener = Arc::new(
            block_on(TcpListener::bind(e_addr))
                .unwrap_or_else(|e| panic!("Cannot bind to electrum address {}: {}", e_addr, e)),
        );

        task::spawn(client_accept_loop(
            non_tls_listener,
            electrum_server.message_transmitter.clone(),
            None,
        ));

        // TLS Electrum accept loop
        if let Some(tls_acceptor) = tls_acceptor {
            let tls_listener =
                Arc::new(block_on(TcpListener::bind(ssl_e_addr)).unwrap_or_else(|e| {
                    panic!("Cannot bind to ssl electrum address {}: {}", ssl_e_addr, e)
                }));
            task::spawn(client_accept_loop(
                tls_listener,
                electrum_server.message_transmitter.clone(),
                Some(tls_acceptor),
            ));
        }

        // Electrum main loop
        task::spawn(electrum_server.main_loop());
        info!("Server running on: {}", e_addr);

        if !self.config.no_ssl {
            info!("TLS server running on: {ssl_e_addr}");
        }

        // Chain provider
        let kill_signal = self.stop_signal.clone();
        let (sender, receiver) = oneshot::channel();

        let mut recv = self.stop_notify.lock().unwrap();
        *recv = Some(receiver);

        task::spawn(chain_provider.run(kill_signal, sender));
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
            .chain(fern::log_file(format!("{}/output.log", data_dir))?);

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

    fn load_chain_state(
        data_dir: String,
        network: Network,
        assume_valid: Option<bitcoin::BlockHash>,
    ) -> ChainState<KvChainStore<'static>> {
        let db = KvChainStore::new(data_dir.to_string()).expect("Could not read db");
        let assume_valid =
            assume_valid.map_or(AssumeValidArg::Hardcoded, AssumeValidArg::UserInput);

        match ChainState::<KvChainStore>::load_chain_state(db, network.into(), assume_valid) {
            Ok(chainstate) => chainstate,
            Err(err) => match err {
                BlockchainError::ChainNotInitialized => {
                    let db = KvChainStore::new(data_dir.to_string()).expect("Could not read db");

                    ChainState::<KvChainStore>::new(db, network.into(), assume_valid)
                }
                _ => unreachable!(),
            },
        }
    }

    fn load_wallet(data_dir: &String) -> AddressCache<KvDatabase> {
        let database = KvDatabase::new(data_dir.to_owned()).expect("Could not create a database");
        AddressCache::new(database)
    }

    fn get_net(net: &crate::Network) -> bitcoin::Network {
        match net {
            crate::Network::Bitcoin => bitcoin::Network::Bitcoin,
            crate::Network::Signet => bitcoin::Network::Signet,
            crate::Network::Testnet => bitcoin::Network::Testnet,
            crate::Network::Regtest => bitcoin::Network::Regtest,
        }
    }

    fn setup_wallet<D: AddressCacheDatabase>(
        mut xpubs: Vec<String>,
        descriptors: Vec<String>,
        addresses: Vec<String>,
        wallet: &mut AddressCache<D>,
        network: crate::Network,
    ) -> anyhow::Result<()> {
        if let Some(key) = Self::get_key_from_env() {
            xpubs.push(key);
        }
        let setup = InitialWalletSetup::build(
            &xpubs,
            &descriptors,
            &addresses,
            Self::get_net(&network),
            100,
        )?;
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

    fn create_tls_config(&self, data_dir: &str) -> io::Result<Arc<ServerConfig>> {
        let cert_path = self
            .config
            .ssl_cert_path
            .clone()
            .unwrap_or_else(|| data_dir.to_owned() + "ssl/cert.pem");
        let key_path = self
            .config
            .ssl_cert_path
            .clone()
            .unwrap_or_else(|| data_dir.to_owned() + "ssl/key.pem");

        let cert_file = File::open(cert_path)?;
        let key_file = File::open(key_path)?;
        let cert_chain = certs(&mut BufReader::new(cert_file)).unwrap();
        let mut keys = pkcs8_private_keys(&mut BufReader::new(key_file)).unwrap();
        let mut config = ServerConfig::new(Arc::new(NoClientAuth));
        config.set_single_cert(cert_chain, keys.remove(0)).unwrap();
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
