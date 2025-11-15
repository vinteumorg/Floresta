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
use log::info;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tokio::time::timeout;

fn main() {
    #[cfg(feature = "tokio-console")]
    {
        // Initialize tokio-console for debugging
        console_subscriber::init();
    }

    let params = Cli::parse();

    let config = Config {
        disable_dns_seeds: params.connect.is_some() || params.disable_dns_seeds,
        network: params.network,
        debug: params.debug,
        data_dir: params.data_dir.clone(),
        cfilters: !params.no_cfilters,
        proxy: params.proxy,
        assume_utreexo: !params.no_assume_utreexo,
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
        generate_cert: params.generate_cert,
        wallet_descriptor: params.wallet_descriptor,
        filters_start_height: params.filters_start_height,
        user_agent: format!("/Floresta:{}/", env!("GIT_DESCRIBE")),
        assumeutreexo_value: None,
        electrum_address: params.electrum_address,
        enable_electrum_tls: params.enable_electrum_tls,
        electrum_address_tls: params.electrum_address_tls,
        tls_cert_path: params.tls_cert_path,
        tls_key_path: params.tls_key_path,
        allow_v1_fallback: params.allow_v1_fallback,
        backfill: !params.no_backfill,
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

    let signal = Arc::new(RwLock::new(false));
    let _signal = signal.clone();

    _rt.spawn(async move {
        // This is used to signal the runtime to stop gracefully.
        // It will be set to true when we receive a Ctrl-C or a stop signal.
        tokio::signal::ctrl_c().await.unwrap();
        let mut sig = signal.write().await;
        *sig = true;
    });

    let florestad = Florestad::from(config);
    _rt.block_on(async {
        florestad.start().await;

        // wait for shutdown
        loop {
            if florestad.should_stop().await || *_signal.read().await {
                info!("Stopping Florestad");
                florestad.stop().await;
                let _ = timeout(Duration::from_secs(10), florestad.wait_shutdown()).await;
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
