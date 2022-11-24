mod blockchain;
mod cli;
mod electrum;

use std::{process::exit, sync::Arc};

use async_std::task::{self, block_on};
use bdk::{
    bitcoin::Network, blockchain::Blockchain, database::SqliteDatabase, SyncOptions, Wallet,
};
use blockchain::{ChainWatch, UtreexodBackend};
use btcd_rpc::client::{BTCDClient, BTCDConfigs, BtcdRpc};
use clap::Parser;
use cli::{Cli, Commands};
use rustreexo::accumulator::stump::Stump;
use std::fs::DirBuilder;

use crate::electrum::electrum_protocol::Message;
fn main() {
    let params = Cli::parse();
    match params.command {
        Commands::Run {
            data_dir,
            wallet_desc,
            rpc_user,
            rpc_password,
            rpc_host,
        } => {
            let blockchain = create_rpc_connection(rpc_host, Some(rpc_user), Some(rpc_password));
            if !test_rpc(&blockchain.rpc) {
                println!("Unable to connect with rpc");
                return;
            }
            let wallet = load_wallet(data_dir.unwrap(), wallet_desc.unwrap());
            let wallet = start_sync(wallet, &blockchain).expect("Could not sync");

            let electrum_server = block_on(electrum::electrum_protocol::ElectrumServer::new(
                "127.0.0.1:8333",
                wallet,
                blockchain,
            ))
            .unwrap();

            let notify_sender = electrum_server.notify_tx.clone();
            let timer = timer::Timer::new();
            let mut current_block = ChainWatch::get_block(&electrum_server.rpc);
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
            wallet_desc,
            data_dir,
        } => {
            // It's safe to unwrap data_dir because there is a default value for it.
            setup(data_dir.unwrap(), wallet_desc);
        }
    }
}

fn setup(data_dir: String, descriptor: String) -> Wallet<SqliteDatabase> {
    let builder = DirBuilder::new().recursive(true).create(data_dir.clone());
    if let Err(_) = builder {
        println!("Invalid data_dir param {data_dir}");
        exit(1);
    }
    let database = SqliteDatabase::new(data_dir + "wallet.sqlite");
    let wallet = Wallet::new(descriptor.as_str(), None, Network::Signet, database);
    if let Err(err) = wallet {
        println!("Unexpected error while creating wallet: {err}");
        exit(1);
    }
    wallet.unwrap()
}
fn load_wallet(data_dir: String, descriptor: String) -> Wallet<SqliteDatabase> {
    let database = SqliteDatabase::new(data_dir + "wallet.sqlite");
    let wallet = Wallet::new(descriptor.as_str(), None, Network::Signet, database);
    if let Err(err) = wallet {
        println!("Unexpected error while creating wallet: {err}");
        exit(1);
    }
    wallet.unwrap()
}
fn create_rpc_connection(
    hostname: String,
    username: Option<String>,
    password: Option<String>,
) -> UtreexodBackend {
    let mut hostname = hostname.split(":");
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

    let rpc = Arc::new(BTCDClient::new(config).unwrap());
    UtreexodBackend {
        rpc: rpc.clone(),
        accumulator: Stump::new(),
    }
}

fn start_sync<BlockchainImplementation: Blockchain>(
    wallet: Wallet<SqliteDatabase>,
    blockchain: &BlockchainImplementation,
) -> Result<Wallet<SqliteDatabase>, bdk::Error> {
    wallet.sync(blockchain, SyncOptions::default())?;

    Ok(wallet)
}
/// Finds out whether our RPC works or not
fn test_rpc(rpc: &BTCDClient) -> bool{
    if let Ok(_) = rpc.getinfo() {
        return true;
    }
    false
}