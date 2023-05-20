use bitcoin::{BlockHash, Network, Txid};
use clap::{Parser, Subcommand};
use jsonrpc::{arg, simple_http::SimpleHttpTransport, Client, Request};
use serde_json::{value::RawValue, Value};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let (params, method) = get_req(&cli);

    let mut transport = SimpleHttpTransport::builder().url(&get_host(&cli))?;
    if let Some(username) = cli.rpc_user {
        transport = transport.auth(username, cli.rpc_password);
    }
    let transport = transport.build();

    let client = Client::with_transport(transport);
    let request = Request {
        id: Value::from(0),
        method: &method,
        params: &params,
        jsonrpc: Some("2.0"),
    };
    let response = client.send_request(request)?;

    let response = response.result::<Value>()?;
    println!("{}", ::serde_json::to_string_pretty(&response).unwrap());

    anyhow::Ok(())
}
fn get_host(cmd: &Cli) -> String {
    if let Some(host) = cmd.rpc_host.clone() {
        return host;
    }
    match cmd.network {
        Network::Bitcoin => "127.0.0.1:8332".into(),
        Network::Testnet => "127.0.0.1:18332".into(),
        Network::Signet => "127.0.0.1:38332".into(),
        Network::Regtest => "127.0.0.1:18443".into(),
    }
}
fn get_req(cmd: &Cli) -> (Vec<Box<RawValue>>, String) {
    let method = match cmd.methods {
        Methods::GetBlockchainInfo => "getblockchaininfo",
        Methods::GetBlockHash { .. } => "getblockhash",
        Methods::GetTxOut { .. } => "gettxout",
        Methods::GetTxProof { .. } => "gettxproof",
        Methods::GetRawTransaction { .. } => "gettransaction",
        Methods::RescanBlockchain { .. } => "rescan",
        Methods::SendRawTransaction { .. } => "sendrawtransaction",
        Methods::GetBlockHeader { .. } => "getblockheader",
        Methods::LoadDescriptor { .. } => "loaddescriptor",
        Methods::GetRoots => "getroots",
    };
    let params = match &cmd.methods {
        Methods::GetBlockchainInfo => vec![],
        Methods::GetBlockHash { height } => vec![arg(height)],
        Methods::GetTxOut { txid, vout } => vec![arg(txid), arg(vout)],
        Methods::GetTxProof { txids, blockhash } => {
            if let Some(blockhash) = blockhash {
                vec![arg(txids), arg(blockhash)]
            } else {
                vec![arg(txids)]
            }
        }
        Methods::GetRawTransaction { txid, .. } => {
            vec![arg(txid)]
        }
        Methods::GetBlockHeader { hash } => vec![arg(hash)],
        Methods::LoadDescriptor { rescan, desc } => {
            if let Some(rescan) = rescan {
                vec![arg(desc), arg(rescan)]
            } else {
                vec![arg(desc)]
            }
        }
        Methods::RescanBlockchain { start_height } => vec![arg(start_height)],
        Methods::SendRawTransaction { tx } => vec![arg(tx)],
        Methods::GetRoots => vec![],
    };

    (params, method.to_string())
}

#[derive(Debug, Parser)]
#[command(author = "Davidson Souza", version = "0.1.0", about = r#"
    A simple command line interface to the Floresta JSON RPC interface.
"#, long_about = None)]
pub struct Cli {
    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    pub config_file: Option<String>,
    /// Which network should we use
    #[arg(short, long, default_value_t=Network::Bitcoin)]
    pub network: Network,
    /// Turn debugging information on
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub debug: u8,
    /// The RPC host to connect to
    #[arg(short = 'H', long, value_name = "URL")]
    pub rpc_host: Option<String>,
    /// The RPC username to use
    #[arg(short = 'u', long, value_name = "USERNAME")]
    pub rpc_user: Option<String>,
    /// The RPC password to use
    #[arg(short = 'P', long, value_name = "PASSWORD")]
    pub rpc_password: Option<String>,
    /// An actual RPC command to run
    #[command(subcommand)]
    pub methods: Methods,
}

#[derive(Debug, Subcommand)]
pub enum Methods {
    /// Returns information about the current state of the blockchain
    #[command(name = "getblockchaininfo")]
    GetBlockchainInfo,
    /// Returns the hash of the block associated with height
    #[command(name = "getblockhash")]
    GetBlockHash { height: u32 },
    /// Returns information about a transaction output, assuming it is cached by our watch
    /// only wallet
    #[command(name = "gettxout")]
    GetTxOut { txid: Txid, vout: u32 },
    /// Returns the proof that one or more transactions were included in a block
    #[command(name = "gettxproof")]
    GetTxProof {
        txids: Txid,
        blockhash: Option<BlockHash>,
    },
    /// Returns the raw transaction, assuming it is cached by our watch only wallet
    #[command(name = "getrawtransaction")]
    GetRawTransaction { txid: Txid, verbose: Option<bool> },
    /// Ask the node to rescan the blockchain for transactions
    #[command(name = "rescan")]
    RescanBlockchain { start_height: u32 },
    /// Submits a raw transaction to the network
    #[command(name = "sendrawtransaction")]
    SendRawTransaction { tx: String },
    /// Returns the block header for the given block hash
    #[command(name = "getblockheader")]
    GetBlockHeader { hash: BlockHash },
    /// Loads a new descriptor to the watch only wallet
    #[command(name = "loaddescriptor")]
    LoadDescriptor { desc: String, rescan: Option<u32> },
    /// Returns the roots of the current utreexo forest
    #[command(name = "getroots")]
    GetRoots,
}
