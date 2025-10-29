#![allow(dead_code)]

use std::env;

use electrsd::corepc_client::client_sync::Auth;
use electrsd::corepc_node;
use electrsd::corepc_node::Client as BitcoindClient;
use electrsd::corepc_node::Node;

use crate::common::run_node;
use crate::common::wait_for_condition;
use crate::common::DESCRIPTOR_EXTERNAL;
use crate::common::DESCRIPTOR_INTERNAL;

const VIEW_LOGS: bool = false;
const WALLET_NAME: &str = "floresta_test";

pub(crate) fn setup_bitcoind(v2_transport: bool) -> Node {
    let bitcoind_exe = env::var("BITCOIND_EXE")
        .ok()
        .or_else(|| corepc_node::downloaded_exe_path().ok())
        .expect(
            "you need to provide an env var BITCOIND_EXE or specify a bitcoind version feature",
        );

    let mut bitcoind_conf = corepc_node::Conf::default();
    bitcoind_conf.network = "regtest";
    bitcoind_conf.args.push("-rest");
    bitcoind_conf.p2p = corepc_node::P2P::Yes;
    if !v2_transport {
        bitcoind_conf.args.push("-v2transport=0");
    }
    bitcoind_conf.view_stdout = VIEW_LOGS;
    bitcoind_conf.wallet = Some(WALLET_NAME.to_string());
    let bitcoind = Node::with_conf(bitcoind_exe, &bitcoind_conf).unwrap();

    let args = vec![
        serde_json::json!({
            "desc": DESCRIPTOR_INTERNAL,
            "timestamp": 1455191478,
            "label": "address internal",
            "internal": true,
            "active": true
        }),
        serde_json::json!({
            "desc": DESCRIPTOR_EXTERNAL,
            "label": "address receive",
            "timestamp": 1455191480,
            "active": true
        }),
    ];
    let _: serde_json::Value = bitcoind
        .client
        .call("importdescriptors", &[serde_json::Value::Array(args)])
        .expect("importdescriptors failed");

    bitcoind
}

pub(crate) fn setup_bitcoind_by_bitcoind(bitcoind: &mut Node, v2_transport: bool) {
    let bitcoind_exe = env::var("BITCOIND_EXE")
        .ok()
        .or_else(|| corepc_node::downloaded_exe_path().ok())
        .expect(
            "you need to provide an env var BITCOIND_EXE or specify a bitcoind version feature",
        );

    let args_p2p_port = format!("-bind={}", bitcoind.params.p2p_socket.unwrap());
    let rpcport_arg = format!("-rpcport={}", bitcoind.params.rpc_socket.port());
    let data_dir_arg = format!("-datadir={}", bitcoind.workdir().display());
    let rpc = "bitcoind".to_string();
    let rpc_user_arg = format!("-rpcuser={}", rpc);
    let rpc_password_arg = format!("-rpcpassword={}", rpc);
    let v2_tranpost_arg = if v2_transport {
        "-v2transport=1"
    } else {
        "-v2transport=0"
    };

    let args = vec![
        "-regtest",
        "-rpcthreads=1",
        &data_dir_arg,
        &args_p2p_port,
        &rpcport_arg,
        &rpc_user_arg,
        &rpc_password_arg,
        &v2_tranpost_arg,
    ];

    let _ = run_node(bitcoind_exe, args, VIEW_LOGS);

    let rpc_url = bitcoind.rpc_url_with_wallet(WALLET_NAME);
    bitcoind.client =
        BitcoindClient::new_with_auth(&rpc_url, Auth::UserPass(rpc.clone(), rpc)).unwrap();

    wait_for_condition(|| bitcoind.client.get_rpc_info().is_ok()).unwrap();
}
