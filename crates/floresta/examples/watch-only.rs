// SPDX-License-Identifier: MIT

//! This example shows how to create a watch-only wallet, and drive it.

use bitcoin::{hashes::hex::FromHex, Script};
use floresta_common::get_spk_hash;
use floresta_watch_only::{kv_database::KvDatabase, AddressCache};

fn main() {
    let chain_data = KvDatabase::new("chain_data".into()).unwrap();
    let wallet = AddressCache::new(chain_data);
    wallet
        .push_descriptor("wpkh([c258d2a6/0'/0'/0']tpubD6NzVbkrYhZ")
        .unwrap();
    let hash =
        get_spk_hash(&Script::from_hex("0014c258d2a6f2b4b2d7e0a1f0b1a7b7a6a7b7a6a7b7").unwrap());
    let history = wallet
        .get_address_history(&hash)
        .iter()
        .map(|tx| tx.hash)
        .collect::<Vec<_>>();
    let balance = wallet.get_address_balance(&hash);
    let utxos = wallet.get_address_utxos(&hash);

    println!("History: {:?}", history);
    println!("Balance: {:?}", balance);
    println!("UTXOs: {:?}", utxos);
}
