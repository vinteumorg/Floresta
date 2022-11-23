mod blockchain;
mod electrum;

use std::sync::Arc;

use async_std::task::{self, block_on};
use bdk::{bitcoin::Network, database::SqliteDatabase, Wallet};
use blockchain::{ChainWatch, UtreexodBackend};
use btcd_rpc::client::{BTCDClient, BTCDConfigs};
use rustreexo::accumulator::stump::Stump;

use crate::electrum::electrum_protocol::Message;
fn main() {
    let default_dir = "/home/erik/.utreexod_wallet/".to_string();
    let dir = default_dir;
    let descriptor = "wpkh(tpubD6NzVbkrYhZ4X2yy78HWrr1M9NT8dKeWfzNiQqDdMqqa9UmmGztGGz6TaLFGsLfdft5iu32gxq1T4eMNxExNNWzVCpf9Y6JZi5TnqoC9wJq)";

    let config = BTCDConfigs::new(
        false,
        Some("SomeUsername".into()),
        Some("CorrectHorseBattleStaple".into()),
        Some("localhost".into()),
        Some(38332),
    );
    let rpc = Arc::new(BTCDClient::new(config).unwrap());
    let blockchain = UtreexodBackend {
        rpc: rpc.clone(),
        accumulator: Stump::new(),
    };

    let database = SqliteDatabase::new(dir);
    let wallet = Wallet::new(descriptor, None, Network::Signet, database).unwrap();
    let electrum_server = block_on(electrum::electrum_protocol::ElectrumServer::new(
        "127.0.0.1:8333",
        wallet,
        blockchain,
    ))
    .unwrap();
    let notify_sender = electrum_server.notify_tx.clone();
    let timer = timer::Timer::new();
    let mut current_block = ChainWatch::get_block(&rpc);
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
