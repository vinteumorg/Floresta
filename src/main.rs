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
#![deny(clippy::absurd_extreme_comparisons)]
#![deny(clippy::almost_swapped)]
#![deny(clippy::assign_op_pattern)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::borrowed_box)]
#![deny(clippy::boxed_local)]
#![deny(clippy::drop_copy)]
// FIXME: Rethink enum variant naming
#![allow(clippy::enum_variant_names)]
#![deny(clippy::needless_lifetimes)]
#![deny(clippy::wildcard_imports)]
#![deny(clippy::while_let_loop)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(non_upper_case_globals)]
#![deny(unused)]

mod address_cache;
mod blockchain;
mod cli;
mod electrum;
mod error;

use std::{process::exit, sync::Arc};

use address_cache::{kv_database::KvDatabase, AddressCache, AddressCacheDatabase};
use async_std::task::{self, block_on};

use bitcoin::Network;
use blockchain::{chain_state::ChainState, chainstore::KvChainStore};
use btcd_rpc::client::{BTCDClient, BTCDConfigs, BtcdRpc};
use clap::Parser;
use cli::{Cli, Commands};
use log::{debug, error, info};
use miniscript::{Descriptor, DescriptorPublicKey};
use pretty_env_logger::env_logger::TimestampPrecision;
use std::str::FromStr;

use crate::blockchain::cli_blockchain::UtreexodBackend;

fn main() {
    // Setup global logger
    pretty_env_logger::formatted_timed_builder()
        .filter_level(log::LevelFilter::Info)
        .format_timestamp(Some(TimestampPrecision::Seconds))
        .format_module_path(false)
        .init();

    let params = Cli::parse();
    match params.command {
        Commands::Run {
            data_dir,
            rpc_user,
            rpc_password,
            rpc_host,
        } => {
            let rpc = create_rpc_connection(rpc_host, Some(rpc_user), Some(rpc_password));
            if !test_rpc(&rpc) {
                info!("Unable to connect with rpc");
                return;
            }
            info!("Starting sync worker, this might take a while!");
            debug!("Loading wallet");
            let cache = load_wallet(data_dir.clone());
            debug!("Done loading wallet");

            debug!("Loading database...");
            let blockchain_state = Arc::new(load_chain_state(&data_dir, get_net(&params.network)));

            debug!("Done loading wallet");
            let chain_provider = UtreexodBackend {
                chainstate: blockchain_state.clone(),
                rpc,
            };
            info!("Starting server");
            // Create a new electrum server, we need to block_on because `ElectrumServer::new` is `async`
            // but our main isn't, so we can't `.await` on it.
            let electrum_server = block_on(electrum::electrum_protocol::ElectrumServer::new(
                "127.0.0.1:50001",
                cache,
                blockchain_state,
            ))
            .unwrap();

            task::spawn(electrum::electrum_protocol::accept_loop(
                electrum_server.listener.clone().unwrap(),
                electrum_server.notify_tx.clone(),
            ));
            task::spawn(chain_provider.run());
            info!("Server running on: 127.0.0.0.1:50001");
            task::block_on(electrum_server.main_loop()).expect("Main loop failed");
        }
        Commands::Setup {
            data_dir,
            wallet_xpub,
        } => {
            let wallet = load_wallet(data_dir);
            setup_wallet(wallet_xpub, wallet, params.network);
        }
    }
}
fn load_chain_state(data_dir: &String, network: Network) -> ChainState<KvChainStore> {
    let db = KvChainStore::new(data_dir.to_string()).expect("Could not read db");
    match ChainState::<KvChainStore>::load_chain_state(db) {
        Ok(chainstate) => chainstate,
        Err(err) => match err {
            blockchain::error::BlockchainError::ChainNotInitialized => {
                let db = KvChainStore::new(data_dir.to_string()).expect("Could not read db");

                ChainState::<KvChainStore>::new(db, network)
            }
            _ => unreachable!(),
        },
    }
}
fn load_wallet(data_dir: String) -> AddressCache<KvDatabase> {
    let database = KvDatabase::new(data_dir.clone()).expect("Could not create a database");
    AddressCache::new(database)
}
fn create_rpc_connection(
    hostname: String,
    username: Option<String>,
    password: Option<String>,
) -> Arc<BTCDClient> {
    let mut hostname = hostname.split(':');
    let address = if let Some(address) = hostname.next() {
        address.to_string()
    } else {
        "localhost".to_string()
    };
    let port = if let Some(port) = hostname.next() {
        port.parse().unwrap_or(8332)
    } else {
        8332
    };

    let config = BTCDConfigs::new(false, username, password, Some(address), Some(port));

    Arc::new(BTCDClient::new(config).unwrap())
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
    xpub: String,
    mut wallet: AddressCache<D>,
    network: cli::Network,
) {
    if let Err(e) = wallet.setup(xpub.clone()) {
        error!("Could not setup wallet: {e}");
        exit(1);
    }
    let main_desc = format!("wpkh({xpub}/0/*)");
    let change_desc = format!("wpkh({xpub}/1/*)");

    derive_addresses(main_desc, &mut wallet, &network);
    derive_addresses(change_desc, &mut wallet, &network);

    info!("Wallet setup completed! You can now execute run");
}
fn derive_addresses<D: AddressCacheDatabase>(
    descriptor: String,
    wallet: &mut AddressCache<D>,
    network: &cli::Network,
) {
    let desc = Descriptor::<DescriptorPublicKey>::from_str(descriptor.as_str())
        .expect("Error while parsing descriptor");
    for index in 0..100 {
        let address = desc
            .at_derivation_index(index)
            .address(get_net(&network))
            .expect("Error while deriving address. Is this an active descriptor?");
        wallet.cache_address(address.script_pubkey());
    }
}
/// Finds out whether our RPC works or not
fn test_rpc(rpc: &BTCDClient) -> bool {
    if rpc.getbestblock().is_ok() {
        return true;
    }
    false
}
