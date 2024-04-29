// Written in 2022 by Davidson Souza.
// SPDX-License-Identifier: CC0-1.0

//! This is a modular-(ish) utreexo powered wallet backend and fully validating node, it's
//! developed as an experiment to showcase utreexo. This wallet also comes with an Electrum
//! server out-of-the-box, for people to try out with their favorite wallet.
//! This codebase consists of three main parts: a blockchain backend, that gets all information
//! we need from the network. An Electrum Server that talks full Electrum protocol and can be
//! used with any wallet that understands this protocol. Finally, it has the `AddressCache`,
//! a watch-only wallet that keeps track of your wallet's transactions.

// Coding conventions (lexicographically sorted)
#![deny(arithmetic_overflow)]
#![deny(clippy::all)]
#![deny(missing_docs)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(non_upper_case_globals)]
#![deny(unused)]

mod cli;
mod config_file;
mod error;
#[cfg(feature = "json-rpc")]
mod json_rpc;
mod slip132;
mod wallet_input;
#[cfg(feature = "zmq-server")]
mod zmq;

use std::fmt::Arguments;
use std::path::PathBuf;
use std::process::exit;
use std::str::FromStr;
use std::sync::Arc;

use async_std::sync::RwLock;
use async_std::task::block_on;
use async_std::task::{self};
use bitcoin::BlockHash;
use bitcoin::Network;
use clap::Parser;
use cli::Cli;
use cli::Commands;
use cli::FilterType;
use config_file::ConfigFile;
use fern::colors::Color;
use fern::colors::ColoredLevelConfig;
use fern::FormatCallback;
use floresta_chain::pruned_utreexo::BlockchainInterface;
use floresta_chain::AssumeValidArg;
use floresta_chain::BlockchainError;
use floresta_chain::ChainState;
use floresta_chain::KvChainStore;
use floresta_common::constants::DIR_NAME;
use floresta_compact_filters::kv_filter_database::KvFilterStore;
use floresta_compact_filters::FilterBackendBuilder;
use floresta_electrum::electrum_protocol::client_accept_loop;
use floresta_electrum::electrum_protocol::ElectrumServer;
use floresta_watch_only::kv_database::KvDatabase;
use floresta_watch_only::AddressCache;
use floresta_watch_only::AddressCacheDatabase;
use floresta_wire::address_man::LocalAddress;
use floresta_wire::mempool::Mempool;
use floresta_wire::node::UtreexoNode;
use floresta_wire::running_node::RunningNode;
use floresta_wire::UtreexoNodeConfig;
use log::debug;
use log::error;
use log::info;
use log::Record;
#[cfg(feature = "zmq-server")]
use zmq::ZMQServer;

use crate::wallet_input::InitialWalletSetup;

/// Information needed to initialize and run florestad. We use this because there may
/// be variations on how users call `florestad` from the command-line, so we gropu up
/// all information needed and call a unique, generic function that does the actual
/// heavy lifting.
#[derive(Default, Clone)]
struct Ctx {
    data_dir: Option<String>,
    assume_valid: Option<BlockHash>,
    wallet_xpub: Option<Vec<String>>,
    wallet_descriptor: Option<Vec<String>>,
    rescan: Option<u32>,
    config_file: Option<String>,
    proxy: Option<String>,
    network: cli::Network,
    cfilters: bool,
    cfilter_types: Vec<FilterType>,
    #[cfg(feature = "zmq-server")]
    zmq_address: Option<String>,
    connect: Option<String>,
    #[cfg(feature = "json-rpc")]
    json_rpc_address: Option<String>,
    electrum_address: Option<String>,
}

fn setup_logger(data_dir: &String, log_file: bool) -> Result<(), fern::InitError> {
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
    let stdout_dispatcher = fern::Dispatch::new()
        .format(formatter(true))
        .level(log::LevelFilter::Info)
        .chain(std::io::stdout());

    match log_file {
        true => {
            let file_dispatcher = fern::Dispatch::new()
                .format(formatter(false))
                .level(log::LevelFilter::Info)
                .chain(fern::log_file(format!("{}/output.log", data_dir))?);
            fern::Dispatch::new()
                .chain(stdout_dispatcher)
                .chain(file_dispatcher)
                .apply()?;
        }
        false => {
            fern::Dispatch::new().chain(stdout_dispatcher).apply()?;
        }
    }

    Ok(())
}

fn main() {
    let params = Cli::parse();
    match params.command {
        #[cfg(feature = "experimental-p2p")]
        Some(Commands::Run {
            data_dir,
            assume_valid,
            wallet_xpub,
            wallet_descriptor,
            rescan,
            proxy,
            zmq_address: _zmq_address,
            cfilters,
            cfilter_types,
            connect,
            rpc_address,
            electrum_address,
        }) => {
            // By default, we build filters for WPKH and TR outputs, as they are the newest.
            // We also build the `inputs` filters to find spends
            let cfilter_types = match cfilter_types {
                Some(cfilters) if !cfilters.is_empty() => cfilters,
                _ => {
                    vec![FilterType::SpkWPKH, FilterType::SpkTR, FilterType::Inputs]
                }
            };

            let ctx = Ctx {
                data_dir,
                assume_valid,
                wallet_xpub,
                wallet_descriptor,
                rescan,
                proxy,
                config_file: params.config_file,
                network: params.network,
                cfilters,
                cfilter_types,
                #[cfg(feature = "zmq-server")]
                zmq_address: _zmq_address,
                connect,
                #[cfg(feature = "json-rpc")]
                json_rpc_address: rpc_address,
                electrum_address,
            };

            run_with_ctx(ctx, params.log_file);
        }

        // We may have more commands here, like setup and dump wallet
        None => {
            let cfilter_types = vec![FilterType::SpkWPKH, FilterType::SpkTR, FilterType::Inputs];

            let ctx = Ctx {
                config_file: params.config_file,
                network: params.network,
                cfilters: true,
                cfilter_types,
                ..Default::default()
            };
            run_with_ctx(ctx, params.log_file);
        }
    }
}

/// Actually runs florestad, spawning all modules and waiting util
/// someone asks to stop.
fn run_with_ctx(ctx: Ctx, log_file: bool) {
    let kill_signal = Arc::new(RwLock::new(false));

    let data_dir = ctx
        .data_dir
        .or_else(|| {
            dirs::home_dir().map(|x: PathBuf| {
                format!(
                    "{}/{}/",
                    x.to_str().unwrap_or_default().to_owned(),
                    DIR_NAME,
                )
            })
        })
        .unwrap_or("floresta".into());

    // setup logger
    match log_file {
        true => {
            setup_logger(&data_dir, true).expect("Could not setup logger");
        }
        false => {
            setup_logger(&data_dir, false).expect("Could not setup logger");
        }
    }

    let data_dir = match ctx.network {
        cli::Network::Bitcoin => data_dir,
        cli::Network::Signet => data_dir + "/signet/",
        cli::Network::Testnet => data_dir + "/testnet3/",
        cli::Network::Regtest => data_dir + "/regtest/",
    };

    // The config file inside our datadir directory. Any datadir
    // passed as argument will be used instead
    let system_config_file = format!("{data_dir}/config.toml");
    let config_file = match ctx.config_file {
        Some(path) => get_config_file(&path),
        None => get_config_file(&system_config_file),
    };

    // Load the watch-only wallet
    debug!("Loading wallet");
    let mut wallet = load_wallet(&data_dir);
    wallet.setup().expect("Could not initialize wallet");
    debug!("Done loading wallet");

    // Try to add more wallets to watch if needed
    let result = setup_wallet(
        get_both_vec(ctx.wallet_xpub, config_file.wallet.xpubs),
        get_both_vec(ctx.wallet_descriptor, config_file.wallet.descriptors),
        get_both_vec(config_file.wallet.addresses, None),
        &mut wallet,
        ctx.network.clone(),
    );
    if let Err(e) = result {
        log::error!("Something went wrong while setting wallet up: {e}");
        return;
    }
    info!("Starting sync worker, this might take a while!");

    debug!("Loading database...");
    let blockchain_state = Arc::new(load_chain_state(
        &data_dir,
        get_net(&ctx.network),
        ctx.assume_valid,
    ));
    if let Some(height) = ctx.rescan {
        blockchain_state
            .rescan(height)
            .expect("Fail while setting rescan");
    }
    #[cfg(feature = "compact-filters")]
    let cfilters = if ctx.cfilters {
        // Block Filters
        let key = if let Ok(file) = std::fs::read(format!("{data_dir}/cfilters_key")) {
            let mut key = [0_u8; 32];
            key.copy_from_slice(&file[0..32]);
            key
        } else {
            let key = rand::random::<[u8; 32]>();
            std::fs::write(format!("{data_dir}/cfilters_key"), key)
                .expect("couldn't write to datadir");
            key
        };
        let filters_dir = format!("{data_dir}/cfilters");
        let cfilters_db = KvFilterStore::new(&filters_dir.into());

        let mut filters = FilterBackendBuilder::default()
            .key_hash(key)
            .use_storage(Box::new(cfilters_db));

        for filter_type in ctx.cfilter_types {
            filters = match filter_type {
                FilterType::All => filters
                    .index_txids(true)
                    .index_input(true)
                    .add_address_type(floresta_compact_filters::OutputTypes::SH)
                    .add_address_type(floresta_compact_filters::OutputTypes::PKH)
                    .add_address_type(floresta_compact_filters::OutputTypes::WSH)
                    .add_address_type(floresta_compact_filters::OutputTypes::WPKH)
                    .add_address_type(floresta_compact_filters::OutputTypes::TR),

                FilterType::TxId => filters.index_txids(true),
                FilterType::Inputs => filters.index_input(true),

                FilterType::SpkPKH => {
                    filters.add_address_type(floresta_compact_filters::OutputTypes::PKH)
                }
                FilterType::SpkPSH => {
                    filters.add_address_type(floresta_compact_filters::OutputTypes::SH)
                }
                FilterType::SpkWPKH => {
                    filters.add_address_type(floresta_compact_filters::OutputTypes::WPKH)
                }
                FilterType::SpkWSH => {
                    filters.add_address_type(floresta_compact_filters::OutputTypes::WSH)
                }
                FilterType::SpkTR => {
                    filters.add_address_type(floresta_compact_filters::OutputTypes::TR)
                }
            };
        }
        let cfilters = Arc::new(filters.build());
        blockchain_state.subscribe(cfilters.clone());
        Some(cfilters)
    } else {
        None
    };
    #[cfg(not(feature = "compact-filters"))]
    let cfilters = None;

    // Handle the `-connect` cli option
    let connect = match ctx.connect.map(|host| LocalAddress::from_str(&host)) {
        Some(Ok(host)) => {
            debug!("Connecting to {:?}", host);
            Some(host)
        }
        Some(Err(e)) => {
            error!("Invalid host: {}", e);
            exit(-1);
        }
        None => None,
    };

    // Chain Provider (p2p)

    // For now, we only have compatible bridges on signet, so you can't
    // use this on mainnet or testnet
    let pow_fraud_proofs = match ctx.network {
        cli::Network::Bitcoin => false,
        cli::Network::Signet => true,
        cli::Network::Testnet => false,
        cli::Network::Regtest => false,
    };

    let config = UtreexoNodeConfig {
        network: get_net(&ctx.network),
        compact_filters: ctx.cfilters,
        datadir: data_dir.clone(),
        proxy: ctx.proxy.map(|x| x.parse().expect("Invalid proxy address")),
        fixed_peer: connect,
        pow_fraud_proofs,
        ..Default::default()
    };

    let chain_provider = UtreexoNode::<RunningNode, Arc<ChainState<KvChainStore>>>::new(
        config,
        blockchain_state.clone(),
        Arc::new(async_std::sync::RwLock::new(Mempool::new())),
    );

    // ZMQ
    #[cfg(feature = "zmq-server")]
    {
        info!("Starting ZMQ server");
        if let Ok(zserver) =
            ZMQServer::new(&ctx.zmq_address.unwrap_or("tcp://127.0.0.1:5150".into()))
        {
            blockchain_state.subscribe(Arc::new(zserver));
            info!("Done!");
        } else {
            error!("Could not create zmq server, skipping");
        };
    }

    info!("Starting server");
    let wallet = Arc::new(RwLock::new(wallet));

    // JSON-RPC
    #[cfg(feature = "json-rpc")]
    let _server = json_rpc::server::RpcImpl::create(
        blockchain_state.clone(),
        wallet.clone(),
        &get_net(&ctx.network),
        chain_provider.get_handle(),
        kill_signal.clone(),
        get_net(&ctx.network),
        cfilters.clone(),
        ctx.json_rpc_address
            .map(|x| x.parse().expect("Invalid json rpc address")),
    );

    // Electrum
    let electrum_address = ctx.electrum_address.unwrap_or("0.0.0.0:50001".into());
    let electrum_server = block_on(ElectrumServer::new(
        electrum_address,
        wallet,
        blockchain_state,
        cfilters,
        chain_provider.get_handle(),
    ))
    .expect("Could not create an Electrum Server");

    // Spawn all services

    // Electrum accept loop
    task::spawn(client_accept_loop(
        electrum_server.tcp_listener.clone(),
        electrum_server.message_transmitter.clone(),
    ));
    // Electrum main loop
    task::spawn(electrum_server.main_loop());
    info!("Server running on: 0.0.0.0:50001");

    let _kill_signal = kill_signal.clone();
    ctrlc::set_handler(move || {
        if *block_on(_kill_signal.write()) {
            info!("Already shutting down, please wait");
        }
        *block_on(_kill_signal.write()) = true;
    })
    .expect("Error setting Ctrl-C handler");
    // Chain provider
    // If chain provider dies, we die too
    task::block_on(chain_provider.run(kill_signal));
}

/// Loads a config file from disk, returns default if some error happens
fn get_config_file(path: &str) -> ConfigFile {
    let data = ConfigFile::from_file(path);

    if let Ok(data) = data {
        data
    } else {
        match data.unwrap_err() {
            error::Error::TomlParsing(e) => {
                error!("Error while parsing config file, ignoring it");
                debug!("{e}");
                ConfigFile::default()
            }
            error::Error::Io(e) => {
                error!("Error reading config file, ignoring it");
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
    data_dir: &String,
    network: Network,
    assume_valid: Option<bitcoin::BlockHash>,
) -> ChainState<KvChainStore> {
    let db = KvChainStore::new(data_dir.to_string()).expect("Could not read db");
    let assume_valid_arg =
        assume_valid.map_or(AssumeValidArg::Hardcoded, AssumeValidArg::UserInput);

    match ChainState::<KvChainStore>::load_chain_state(db, network.into(), assume_valid_arg) {
        Ok(chainstate) => chainstate,
        Err(err) => match err {
            BlockchainError::ChainNotInitialized => {
                let db = KvChainStore::new(data_dir.to_string()).expect("Could not read db");

                ChainState::<KvChainStore>::new(db, network.into(), assume_valid_arg)
            }
            _ => unreachable!(),
        },
    }
}
fn load_wallet(data_dir: &String) -> AddressCache<KvDatabase> {
    let database = KvDatabase::new(data_dir.to_owned()).expect("Could not create a database");
    AddressCache::new(database)
}
#[cfg(not(feature = "experimental-p2p"))]
fn create_rpc_connection(
    hostname: &String,
    rpc_port: u32,
    username: Option<String>,
    password: Option<String>,
) -> Arc<BTCDClient> {
    let config = BTCDConfigs::new(
        false,
        username,
        password,
        hostname.to_owned(),
        Some(rpc_port as usize),
    );
    let connection = BTCDClient::new(config);
    if connection.is_err() {
        error!("Could not create RPC connection, check your configs");
        std::process::exit(1);
    }
    Arc::new(connection.expect("We checked this above, it's impossible to be Err"))
}

fn get_net(net: &cli::Network) -> Network {
    match net {
        cli::Network::Bitcoin => Network::Bitcoin,
        cli::Network::Signet => Network::Signet,
        cli::Network::Testnet => Network::Testnet,
        cli::Network::Regtest => Network::Regtest,
    }
}

fn setup_wallet<D: AddressCacheDatabase>(
    mut xpubs: Vec<String>,
    descriptors: Vec<String>,
    addresses: Vec<String>,
    wallet: &mut AddressCache<D>,
    network: cli::Network,
) -> anyhow::Result<()> {
    if let Some(key) = get_key_from_env() {
        xpubs.push(key);
    }
    let setup =
        InitialWalletSetup::build(&xpubs, &descriptors, &addresses, get_net(&network), 100)?;
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

#[cfg(not(feature = "experimental-p2p"))]
/// Finds out whether our RPC works or not
fn test_rpc(rpc: &BTCDClient) -> bool {
    use btcd_rpc::client::BtcdRpc;
    if rpc.getbestblock().is_ok() {
        return true;
    }
    false
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
