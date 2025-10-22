#![allow(dead_code)]

use std::env;
use std::fs;
use std::path::Path;
use std::process::Child;

use electrsd::corepc_node::get_available_port;
use floresta_rpc::jsonrpc_client::Client;
use floresta_rpc::rpc::FlorestaRPC;
use rcgen::generate_simple_self_signed;
use rcgen::CertifiedKey;

use crate::common::run_node;
use crate::common::wait_for_condition_node_started;
use crate::common::XPUB_STR;

const VIEW_LOGS: bool = false;

pub(crate) struct Florestad {
    process: Child,
    pub(crate) client: Client,
    pub(crate) directory: String,
}

pub(crate) fn setup_florestad() -> Florestad {
    // CARGO_MANIFEST_DIR is always floresta-cli's directory; PWD changes based on where the
    // command is executed.
    let root = format!("{}/..", env!("CARGO_MANIFEST_DIR"));
    let release_path = format!("{root}/target/release/florestad");
    let debug_path = format!("{root}/target/debug/florestad");

    let release_found = Path::new(&release_path).try_exists().unwrap();
    // If release target not found, default to the debug path
    let florestad_path: String = match release_found {
        true => release_path,
        false => debug_path,
    };

    // Makes a temporary directory to store the chain db, TLS certificate, logs, etc.
    let test_code = rand::random::<u64>();
    let dirname = format!("{root}/tmp/floresta.{test_code}");
    fs::DirBuilder::new()
        .recursive(true)
        .create(&dirname)
        .unwrap();

    // Generate TLS private key and certificate using rcgen
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    fs::create_dir_all(format!("{dirname}/regtest/tls")).unwrap();
    fs::write(format!("{dirname}/regtest/tls/cert.pem"), cert_pem).unwrap();
    fs::write(format!("{dirname}/regtest/tls/key.pem"), key_pem).unwrap();

    let rpc_port = get_available_port().unwrap();
    let electrum_port = get_available_port().unwrap();
    let data_dir_arg = format!("--data-dir={}", dirname.clone());
    let wallet_xpub_arg = format!("--wallet-xpub={}", XPUB_STR);
    let rpc_address_arg = format!("--rpc-address=127.0.0.1:{}", rpc_port);
    let electrum_address_arg = format!("--electrum-address=127.0.0.1:{}", electrum_port);

    let args = vec![
        "--network=regtest",
        // "--debug",
        // "--no-assume-utreexo",
        &electrum_address_arg,
        &data_dir_arg,
        &wallet_xpub_arg,
        &rpc_address_arg,
    ];

    let process = run_node(florestad_path, args, VIEW_LOGS);

    let client = Client::new(format!("http://127.0.0.1:{rpc_port}"));

    wait_for_condition_node_started(|| client.get_blockchain_info().is_ok()).unwrap();

    Florestad {
        process,
        client,
        directory: dirname,
    }
}
