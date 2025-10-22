#![allow(dead_code)]

use std::env;
use std::fs;
use std::net::SocketAddrV4;
use std::process::Child;

use electrsd::corepc_node::get_available_port;
use floresta_rpc::jsonrpc_client::Client;
use floresta_rpc::jsonrpc_client::JsonRPCConfig;
use floresta_rpc::rpc_types::Error;
use serde_json::json;
use serde_json::Value;

use crate::common::run_node;
use crate::common::wait_for_condition_node_started;
use crate::common::ADDRESS_STR;

const VIEW_LOGS: bool = false;

pub struct Utreexod {
    process: Child,
    pub(crate) client: RpcUtreexod,
    pub(crate) p2p: SocketAddrV4,
}

impl Utreexod {
    pub(crate) fn setup() -> Self {
        let utreexod_exe = env::var("UTREEXOD_EXE")
            .ok()
            .or_else(|| Some("/tmp/floresta-func-tests/binaries/utreexod".to_string()))
            .expect("you need to provide an env var UTREEXOD_EXE or specify a utreexod path");

        // Data directory to avoid write errors
        let test_code = rand::random::<u64>();
        let data_dir = format!("/tmp/utreexod-data-{}", test_code);
        fs::create_dir_all(&data_dir).expect("Failed to create data directory");

        // Ports for RPC and P2P
        let rpc_port = get_available_port().expect("Failed to get available RPC port");
        let p2p_port = get_available_port().expect("Failed to get available P2P port");

        // Arguments for utreexod (based on btcd)
        let bind_arg = format!("--listen=0.0.0.0:{}", p2p_port);
        let rpcport_arg = format!("--rpclisten=127.0.0.1:{}", rpc_port);
        let datadir_arg = format!("--datadir={}", data_dir);
        let mining_addr_arg = format!("--miningaddr={}", ADDRESS_STR);
        let args = vec![
            "--regtest",
            "--debuglevel=debug",
            "--prune=0",
            &bind_arg,
            &rpcport_arg,
            &mining_addr_arg,
            "--rpcuser=floresta",
            "--rpcpass=floresta",
            "--notls",
            "--utreexoproofindex",
            &datadir_arg,
        ];

        let process = run_node(utreexod_exe, args, VIEW_LOGS);

        // Create the RPC client
        let url = format!("http://127.0.0.1:{}", rpc_port);
        let client = RpcUtreexod::new(url, Some("floresta".into()), Some("floresta".into()));

        wait_for_condition_node_started(|| client.get_blockchain_info().is_ok()).unwrap();

        let p2p = format!("127.0.0.1:{}", p2p_port);

        Utreexod {
            process,
            client,
            p2p: p2p.parse().unwrap(),
        }
    }
}

pub struct RpcUtreexod {
    client: Client,
}

impl RpcUtreexod {
    fn new(url: String, user: Option<String>, pass: Option<String>) -> Self {
        let config = JsonRPCConfig { url, user, pass };
        let client = Client::new_with_config(config);
        Self { client }
    }

    pub fn call(&self, method: &str, args: &[Value]) -> Result<Value, Error> {
        self.client.rpc_call(method, args)
    }

    pub fn get_blockchain_info(&self) -> Result<Value, Error> {
        self.call("getblockchaininfo", &[])
    }

    pub fn stop(&self) -> Result<Value, Error> {
        self.call("stop", &[])
    }

    pub fn get_new_address(&self) -> Result<Value, Error> {
        self.call("getnewaddress", &[])
    }

    pub fn generate(&self, blocks: u32) -> Result<Value, Error> {
        self.call("generate", &[json!(blocks)])
    }

    pub fn get_utreexo_roots(&self, block_hash: &str) -> Result<Value, Error> {
        self.call("getutreexoroots", &[json!(block_hash)])
    }

    pub fn send_to_address(&self, address: &str, amount: f64) -> Result<Value, Error> {
        self.call("sendtoaddress", &[json!(address), json!(amount)])
    }

    pub fn get_balance(&self) -> Result<Value, Error> {
        self.call("getbalance", &[])
    }

    pub fn get_peer_info(&self) -> Result<Value, Error> {
        self.call("getpeerinfo", &[])
    }

    pub fn invalidate_block(&self, blockhash: &str) -> Result<Value, Error> {
        self.call("invalidateblock", &[json!(blockhash)])
    }

    pub fn get_blockhash(&self, height: u32) -> Result<Value, Error> {
        self.call("getblockhash", &[json!(height)])
    }

    pub fn addnode(&self, node: &str, command: &str) -> Result<Value, Error> {
        self.call("addnode", &[json!(node), json!(command)])
    }

    pub fn get_block_count(&self) -> Result<Value, Error> {
        self.call("getblockcount", &[])
    }

    pub fn get_txout(&self, txid: &str, vout: u32, include_mempool: bool) -> Result<Value, Error> {
        self.call(
            "gettxout",
            &[json!(txid), json!(vout), json!(include_mempool)],
        )
    }
}
