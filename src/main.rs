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

// Coding conventions
#![deny(clippy::needless_lifetimes)]
#![deny(unused)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(arithmetic_overflow)]
#![deny(clippy::absurd_extreme_comparisons)]
#![deny(non_upper_case_globals)]
#![deny(unused_mut)]
#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(unused_must_use)]
// FIXME: Rethink enum variant naming
#![allow(clippy::enum_variant_names)]

mod address_cache;
mod blockchain;
mod cli;
mod electrum;
mod error;

use std::{process::exit, sync::Arc};

use crate::electrum::electrum_protocol::Message;
use address_cache::{kv_database::KvDatabase, AddressCache, AddressCacheDatabase};
use async_std::task::{self, block_on};
use bitcoin::Network;
use blockchain::{
    chainstore::{ChainStore, KvChainStore},
    sync::BlockchainSync,
    ChainWatch,
};
use btcd_rpc::client::{BTCDClient, BTCDConfigs, BtcdRpc};
use clap::Parser;
use cli::{Cli, Commands};
use log::{log, Level};
use miniscript::{Descriptor, DescriptorPublicKey};
use std::str::FromStr;
fn main() {
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
                log!(Level::Error, "Unable to connect with rpc");
                return;
            }
            log!(
                Level::Info,
                "Starting sync worker, this might take a while!"
            );
            let cache = load_wallet(data_dir);
            let cache = start_sync(&rpc, cache).expect("Could not sync");
            log!(Level::Info, "Starting server...");
            let electrum_server = block_on(electrum::electrum_protocol::ElectrumServer::new(
                "127.0.0.1:50001",
                rpc.clone(),
                cache,
            ))
            .unwrap();

            let notify_sender = electrum_server.notify_tx.clone();
            let timer = timer::Timer::new();
            let mut current_block = ChainWatch::get_block(&rpc);
            let rpc = electrum_server.rpc.clone();
            timer
                .schedule_repeating(chrono::Duration::seconds(5), move || {
                    let new_block = ChainWatch::get_block(&rpc);
                    if new_block > current_block {
                        let _ = notify_sender.send(Message::NewBlock);
                        current_block = new_block;
                    }
                })
                .ignore();
            task::spawn(electrum::electrum_protocol::accept_loop(
                electrum_server.listener.clone().unwrap(),
                electrum_server.notify_tx.clone(),
            ));
            task::block_on(electrum_server.main_loop()).expect("Main loop failed");
        }
        Commands::Setup {
            data_dir,
            wallet_descriptor,
        } => {
            let wallet = load_wallet(data_dir);
            setup_wallet(wallet_descriptor, wallet);
        }
    }
}

fn load_wallet(data_dir: String) -> AddressCache<KvDatabase, KvChainStore> {
    let database = KvDatabase::new(data_dir.clone()).expect("Could not create a database");
    let chain_store = KvChainStore::new(data_dir).unwrap();

    AddressCache::new(database, chain_store)
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
fn setup_wallet<D: AddressCacheDatabase, S: ChainStore>(
    descriptor: String,
    mut wallet: AddressCache<D, S>,
) {
    if let Err(e) = wallet.setup(descriptor.clone()) {
        log!(Level::Error, "Could not setup wallet: {e}");
        exit(1);
    }

    let desc =
        Descriptor::<DescriptorPublicKey>::from_str(format!("wpkh({}/0/*)", descriptor).as_str())
            .expect("Error while parsing descriptor");
    for index in 0..100 {
        let address = desc
            .at_derivation_index(index)
            .address(Network::Signet)
            .expect("Error while deriving address. Is this an active descriptor?");
        wallet.cache_address(address.script_pubkey());
    }
    log!(
        Level::Info,
        "Wallet setup completed! You can now execute run"
    );
}
fn start_sync<D: AddressCacheDatabase, Rpc: BtcdRpc, S: ChainStore>(
    rpc: &Arc<Rpc>,
    mut address_cache: AddressCache<D, S>,
) -> Result<AddressCache<D, S>, error::Error> {
    let current_hight = rpc.getbestblock()?.height as u32;
    let sync_range = address_cache.get_sync_limits(current_hight);
    if let Err(crate::error::Error::WalletNotInitialized) = sync_range {
        log!(Level::Error, "Wallet not set up!");

        exit(1);
    }

    BlockchainSync::sync_range(&**rpc, &mut address_cache, sync_range?)?;
    Ok(address_cache)
}
/// Finds out whether our RPC works or not
fn test_rpc(rpc: &BTCDClient) -> bool {
    if rpc.getinfo().is_ok() {
        return true;
    }
    false
}
