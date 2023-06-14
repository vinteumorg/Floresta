// Written in 2022 by Davidson Souza.
// SPDX-License-Identifier: CC0-1.0

//! This is a modular-(ish) utreexo powered wallet backend and fully validating node, it's
//! developed as an experiment to showcase utreexo. This wallet also comes with an Electrum
//! server out-of-the-box, for people to try out with their favorite wallet.
//! This codebase consists of three main parts: a blockchain backend, that gets all information
//! we need from the network. An Electrum Server that talks full Electrum protocol and can be
//! used with any wallet that understands this protocol. Finally, it has the `AddressCache`,
//! a watch-only wallet that keeps track of your wallet's transactions.
//!
//! Right now, the blockchain backend uses a running utreexod's RPC to get needed data, this
//! is because Utreexo p2p messages are WIP, and we want to try out utreexo before that, so we use
//! a client-server base to test, but this is not final nor the goal.

// Coding conventions (lexicographically sorted)
#![deny(arithmetic_overflow)]
#![deny(clippy::all)]
// FIXME: Rethink enum variant naming
#![allow(clippy::enum_variant_names)]
#![deny(missing_docs)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(non_upper_case_globals)]
#![deny(unused)]

mod address_cache;
mod blockchain;
mod cli;
mod config_file;
mod electrum;
mod error;
#[cfg(feature = "json-rpc")]
mod json_rpc;
mod version;
mod wallet_input;

use std::{path::PathBuf, sync::Arc};

use address_cache::{kv_database::KvDatabase, AddressCache, AddressCacheDatabase};
use async_std::{
    sync::RwLock,
    task::{self, block_on},
};

use bitcoin::Network;
use blockchain::{chain_state::ChainState, chainstore::KvChainStore};
#[cfg(not(feature = "experimental-p2p"))]
use btcd_rpc::client::{BTCDClient, BTCDConfigs};
use clap::Parser;
use cli::{Cli, Commands};
use config_file::ConfigFile;
use log::{debug, error, info};
use pretty_env_logger::env_logger::{Env, TimestampPrecision};

#[cfg(not(feature = "experimental-p2p"))]
use crate::blockchain::cli_blockchain::UtreexodBackend;

#[cfg(feature = "experimental-p2p")]
use crate::blockchain::p2p_blockchain::{mempool::Mempool, node::UtreexoNode};
use crate::{blockchain::BlockchainInterface, version::DIR_NAME, wallet_input::InitialWalletSetup};

fn main() {
    // Setup global logger
    pretty_env_logger::env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .format_timestamp(Some(TimestampPrecision::Seconds))
        .format_module_path(true)
        .init();

    let params = Cli::parse();
    let data = get_config_file(&params);
    match params.command {
        #[cfg(not(feature = "experimental-p2p"))]
        Commands::Run {
            data_dir,
            rpc_user,
            rpc_password,
            rpc_host,
            batch_sync,
            wallet_addresses,
            use_batch_sync,
            rpc_port,
            wallet_xpub,
            assume_valid,
        } => {
            // Catch user CTR + C for terminating our application
            let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
            signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&shutdown))
                .expect("Could no register for SIGTERM");
            let data_dir = get_one_or_another(
                data_dir,
                dirs::home_dir().map(|x: PathBuf| {
                    format!(
                        "{}/{}/",
                        x.to_str().unwrap_or_default().to_owned(),
                        DIR_NAME,
                    )
                }),
                "wallet".into(),
            );
            let data_dir = match params.network {
                cli::Network::Bitcoin => data_dir,
                cli::Network::Signet => data_dir + "/signet/",
                cli::Network::Testnet => data_dir + "/testnet3/",
                cli::Network::Regtest => data_dir + "/regtest/",
            };

            debug!("Loading wallet");
            let mut wallet = load_wallet(&data_dir);
            wallet.setup().expect("Could not initialize wallet");
            debug!("Done loading wallet");
            let result = setup_wallet(
                get_both_vec(wallet_xpub, data.wallet.xpubs),
                get_both_vec(None, data.wallet.descriptors),
                get_both_vec(data.wallet.addresses, wallet_addresses),
                &mut wallet,
                params.network.clone(),
            );
            if let Err(e) = result {
                log::error!("Something went wrong while setting wallet up: {e}");
                return;
            }
            let rpc = create_rpc_connection(
                &get_one_or_another(rpc_host, data.rpc.rpc_host, "localhost".into()),
                get_one_or_another(rpc_port, data.rpc.rpc_port, 8332),
                Some(get_one_or_another(rpc_user, data.rpc.rpc_user, "".into())),
                Some(get_one_or_another(
                    rpc_password,
                    data.rpc.rpc_password,
                    "".into(),
                )),
            );

            #[cfg(not(feature = "experimental-p2p"))]
            if !test_rpc(&rpc) {
                info!("Unable to connect with rpc");
                return;
            }
            info!("Starting sync worker, this might take a while!");

            debug!("Loading database...");
            let blockchain_state = Arc::new(load_chain_state(
                &data_dir,
                get_net(&params.network),
                assume_valid,
            ));

            debug!("Done loading wallet");

            let chain_provider = UtreexodBackend {
                chainstate: blockchain_state.clone(),
                rpc,
                batch_sync_hostname: get_one_or_another(
                    batch_sync,
                    data.misc.batch_sync,
                    "".into(),
                ),
                use_batch_sync,
                term: shutdown,
            };
            info!("Starting server");
            // Create a new electrum server, we need to block_on because `ElectrumServer::new` is `async`
            // but our main isn't, so we can't `.await` on it.
            let electrum_server = block_on(electrum::electrum_protocol::ElectrumServer::new(
                "0.0.0.0:50001",
                wallet,
                blockchain_state,
            ))
            .unwrap();

            task::spawn(electrum::electrum_protocol::accept_loop(
                electrum_server.listener.clone().unwrap(),
                electrum_server.notify_tx.clone(),
            ));
            task::spawn(electrum_server.main_loop());
            info!("Server running on: 0.0.0.0:50001");
            task::block_on(chain_provider.run());
        }
        #[cfg(feature = "experimental-p2p")]
        Commands::Run {
            data_dir,
            assume_valid,
            wallet_xpub,
            wallet_descriptor,
            rescan,
        } => {
            let kill_signal = Arc::new(RwLock::new(false));

            let data_dir = get_one_or_another(
                data_dir,
                dirs::home_dir().map(|x: PathBuf| {
                    format!(
                        "{}/{}/",
                        x.to_str().unwrap_or_default().to_owned(),
                        DIR_NAME,
                    )
                }),
                "wallet".into(),
            );
            let data_dir = match params.network {
                cli::Network::Bitcoin => data_dir,
                cli::Network::Signet => data_dir + "/signet/",
                cli::Network::Testnet => data_dir + "/testnet3/",
                cli::Network::Regtest => data_dir + "/regtest/",
            };
            debug!("Loading wallet");
            let mut wallet = load_wallet(&data_dir);
            wallet.setup().expect("Could not initialize wallet");
            debug!("Done loading wallet");
            let result = setup_wallet(
                get_both_vec(wallet_xpub, data.wallet.xpubs),
                get_both_vec(wallet_descriptor, data.wallet.descriptors),
                get_both_vec(data.wallet.addresses, None),
                &mut wallet,
                params.network.clone(),
            );
            if let Err(e) = result {
                log::error!("Something went wrong while setting wallet up: {e}");
                return;
            }
            info!("Starting sync worker, this might take a while!");

            debug!("Loading database...");
            let blockchain_state = Arc::new(load_chain_state(
                &data_dir,
                get_net(&params.network),
                assume_valid,
            ));
            if let Some(height) = rescan {
                blockchain_state
                    .rescan(height)
                    .expect("Fail while setting rescan");
            }
            debug!("Done loading database");

            let chain_provider = UtreexoNode::new(
                blockchain_state.clone(),
                Arc::new(async_std::sync::RwLock::new(Mempool::new())),
                get_net(&params.network),
                data_dir,
            );
            info!("Starting server");
            let wallet = Arc::new(RwLock::new(wallet));
            // Create a new electrum server, we need to block_on because `ElectrumServer::new` is `async`
            // but our main isn't, so we can't `.await` on it.
            #[cfg(feature = "json-rpc")]
            let _server = json_rpc::server::RpcImpl::create(
                blockchain_state.clone(),
                wallet.clone(),
                &get_net(&params.network),
                chain_provider.get_handle(),
                kill_signal.clone(),
            );
            let electrum_server = block_on(electrum::electrum_protocol::ElectrumServer::new(
                "0.0.0.0:50001",
                wallet,
                blockchain_state,
            ))
            .expect("Could not create an Electrum Server");

            task::spawn(electrum::electrum_protocol::accept_loop(
                electrum_server
                    .listener
                    .clone()
                    .expect("Listener can't be none by this far"),
                electrum_server.notify_tx.clone(),
            ));
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
            task::block_on(chain_provider.run(&kill_signal));
        }
    }
}
/// Loads a config file from disk, returns default if some error happens
fn get_config_file(params: &cli::Cli) -> ConfigFile {
    let data = if let Some(file_name) = &params.config_file {
        ConfigFile::from_file(file_name)
    } else {
        // File not passed in, use default
        return ConfigFile::default();
    };
    if let Ok(data) = data {
        data
    } else {
        match data.unwrap_err() {
            error::Error::TomlParsingError(e) => {
                error!("Error while parsing config file, ignoring it");
                debug!("{e}");
                ConfigFile::default()
            }
            error::Error::IoError(e) => {
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
    match ChainState::<KvChainStore>::load_chain_state(db, network, assume_valid) {
        Ok(chainstate) => chainstate,
        Err(err) => match err {
            blockchain::error::BlockchainError::ChainNotInitialized => {
                let db = KvChainStore::new(data_dir.to_string()).expect("Could not read db");

                ChainState::<KvChainStore>::new(db, network, assume_valid)
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
) -> Result<(), crate::error::Error> {
    let env_key = get_key_from_env();
    if let Some(key) = env_key {
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
    Ok(())
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
/// Returns the value that is defined, if a is defined, return a. If b is defined and
/// a not, returns b. If a and b is defined, returns a, etc.
fn get_one_or_another<A, B, Return>(a: Option<A>, b: Option<B>, default: Return) -> Return
where
    A: Into<Return>,
    B: Into<Return>,
{
    if let Some(a) = a {
        return a.into();
    }
    if let Some(b) = b {
        return b.into();
    }

    default
}

fn get_both_vec<T>(a: Option<Vec<T>>, b: Option<Vec<T>>) -> Vec<T> {
    let mut result: Vec<T> = vec![];
    if let Some(a) = a {
        result.extend(a.into_iter());
    }
    if let Some(b) = b {
        result.extend(b.into_iter());
    }
    result
}
