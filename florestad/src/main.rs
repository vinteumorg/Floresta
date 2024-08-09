// SPDX-License-Identifier: MIT

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

mod cli;

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use cli::Cli;
#[cfg(unix)]
use daemonize::Daemonize;
use florestad::Config;
use florestad::Florestad;
use futures::executor::block_on;
use log::info;
use tokio::sync::RwLock;
use tokio::time::sleep;

fn main() {
    let params = Cli::parse();

    let config = Config {
        network: params.network.into(),
        debug: params.debug,
        data_dir: params.data_dir.clone(),
        cfilters: params.cfilters,
        proxy: params.proxy,
        assume_utreexo: params.assume_utreexo,
        connect: params.connect,
        wallet_xpub: params.wallet_xpub,
        config_file: params.config_file,
        #[cfg(unix)]
        log_to_file: params.log_to_file || params.daemon,
        #[cfg(not(unix))]
        log_to_file: params.log_to_file,
        assume_valid: params.assume_valid,
        log_to_stdout: true,
        #[cfg(feature = "zmq-server")]
        zmq_address: params.zmq_address,
        #[cfg(feature = "json-rpc")]
        json_rpc_address: params.rpc_address,
        electrum_address: params.electrum_address,
        ssl_electrum_address: params.ssl_electrum_address,
        wallet_descriptor: params.wallet_descriptor,
        filters_start_height: params.filters_start_height,
        user_agent: format!("/Floresta:{}/", env!("GIT_DESCRIBE")),
        assumeutreexo_value: None,
        ssl_cert_path: params.ssl_cert_path,
        ssl_key_path: params.ssl_key_path,
        no_ssl: params.no_ssl,
        allow_v1_fallback: !params.no_v1_fallback,
    };

    #[cfg(unix)]
    if params.daemon {
        let mut daemon = Daemonize::new();
        if let Some(pid_file) = params.pid_file {
            daemon = daemon.pid_file(pid_file);
        }
        daemon.start().expect("Failed to daemonize");
    }

    let _rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .max_blocking_threads(2)
        .thread_keep_alive(Duration::from_secs(60))
        .thread_name("florestad")
        .build()
        .unwrap();

    let stop_signal = Arc::new(RwLock::new(false));
    let florestad = Florestad::from(config);

    _rt.block_on(async {
        florestad.start();
        let _stop_signal = stop_signal.clone();
        ctrlc::set_handler(move || {
            block_on(async {
                *(_stop_signal.write().await) = true;
            })
        })
        .expect("Could not setup ctr+c handler");

        loop {
            if florestad.should_stop() || *stop_signal.read().await {
                info!("Shutting down florestad");
                florestad.stop();
                florestad.wait_shutdown().await;
                break;
            }

            sleep(Duration::from_secs(5)).await;
        }
    });

    // drop them outside the async block, so we won't cause a nested drop of the runtime
    // due to the rpc server, causing a panic.
    drop(florestad);
    drop(_rt);
}
