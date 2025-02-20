use std::fmt::Debug;

use anyhow::Ok;
use bitcoin::BlockHash;
use bitcoin::Network;
use bitcoin::Txid;
use clap::Parser;
use clap::Subcommand;
use floresta_cli::jsonrpc_client::Client;
use floresta_cli::rpc::FlorestaRPC;
use floresta_cli::rpc_types::GetBlockRes;

// Main function that runs the CLI application
fn main() -> anyhow::Result<()> {
    // Parse command line arguments into a Cli struct
    let cli = Cli::parse();

    // Create a new JSON-RPC client using the host from the CLI arguments
    let client = Client::new(get_host(&cli));

    // Perform the requested RPC call and get the result
    let res = do_request(&cli, client)?;

    // Print the result to the console
    println!("{}", res);

    // Return Ok to indicate the program ran successfully
    anyhow::Ok(())
}

// Function to determine the RPC host based on CLI arguments and network type
fn get_host(cmd: &Cli) -> String {
    // If a specific RPC host is provided, use it
    if let Some(host) = cmd.rpc_host.clone() {
        return host;
    }

    // Otherwise, use the default host based on the network type
    match cmd.network {
        Network::Bitcoin => "http://127.0.0.1:8332".into(),
        Network::Testnet => "http://127.0.0.1:18332".into(),
        Network::Signet => "http://127.0.0.1:38332".into(),
        Network::Regtest => "http://127.0.0.1:18442".into(),
        _ => "http://127.0.0.1:8332".into(),
    }
}

// Function to perform the requested RPC call based on CLI arguments
fn do_request(cmd: &Cli, client: Client) -> anyhow::Result<String> {
    Ok(match cmd.methods.clone() {
        // Handle each possible RPC method and serialize the result to a pretty JSON string
        Methods::GetBlockchainInfo => serde_json::to_string_pretty(&client.get_blockchain_info()?)?,
        Methods::GetBlockHash { height } => {
            serde_json::to_string_pretty(&client.get_block_hash(height)?)?
        }
        Methods::GetTxOut { txid, vout } => {
            serde_json::to_string_pretty(&client.get_tx_out(txid, vout)?)?
        }
        Methods::GetTxProof { txids, blockhash } => {
            serde_json::to_string_pretty(&client.get_tx_proof(txids, blockhash)?)?
        }
        Methods::GetTransaction { txid, .. } => {
            serde_json::to_string_pretty(&client.get_transaction(txid, Some(true))?)?
        }
        Methods::RescanBlockchain { start_height } => {
            serde_json::to_string_pretty(&client.rescan(start_height)?)?
        }
        Methods::SendRawTransaction { tx } => {
            serde_json::to_string_pretty(&client.send_raw_transaction(tx)?)?
        }
        Methods::GetBlockHeader { hash } => {
            serde_json::to_string_pretty(&client.get_block_header(hash)?)?
        }
        Methods::LoadDescriptor { desc } => {
            serde_json::to_string_pretty(&client.load_descriptor(desc)?)?
        }
        Methods::GetRoots => serde_json::to_string_pretty(&client.get_roots()?)?,
        Methods::GetBlock { hash, verbosity } => {
            let block = client.get_block(hash, verbosity)?;

            match block {
                GetBlockRes::Verbose(block) => serde_json::to_string_pretty(&block)?,
                GetBlockRes::Serialized(block) => serde_json::to_string_pretty(&block)?,
            }
        }
        Methods::GetPeerInfo => serde_json::to_string_pretty(&client.get_peer_info()?)?,
        Methods::Stop => serde_json::to_string_pretty(&client.stop()?)?,
        Methods::AddNode { node } => serde_json::to_string_pretty(&client.add_node(node)?)?,
        Methods::FindTxOut {
            txid,
            vout,
            script,
            height_hint,
        } => serde_json::to_string_pretty(&client.find_tx_out(
            txid,
            vout,
            script,
            height_hint.unwrap_or(0),
        )?)?,
        Methods::GetMemoryInfo { mode } => {
            let mode = mode.unwrap_or("stats".to_string());
            serde_json::to_string_pretty(&client.get_memory_info(mode)?)?
        }
        Methods::GetRpcInfo => serde_json::to_string_pretty(&client.get_rpc_info()?)?,
        Methods::Uptime => serde_json::to_string_pretty(&client.uptime()?)?,
    })
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

#[derive(Debug, Clone, Subcommand)]
pub enum Methods {
    /// Returns information about the current state of the blockchain
    #[command(name = "getblockchaininfo")]
    GetBlockchainInfo,
    /// Returns the hash of the block associated with height
    #[command(name = "getblockhash")]
    GetBlockHash { height: u32 },
    /// Returns the proof that one or more transactions were included in a block
    #[command(name = "gettxproof")]
    GetTxProof {
        txids: Txid,
        blockhashs: Option<BlockHash>,
    },
    /// Returns the transaction, assuming it is cached by our watch only wallet
    #[command(name = "gettransaction")]
    GetTransaction { txid: Txid, verbose: Option<bool> },
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
    LoadDescriptor { desc: String },
    /// Returns the roots of the current utreexo forest
    #[command(name = "getroots")]
    GetRoots,
    /// Returns a block
    #[command(name = "getblock")]
    GetBlock {
        hash: BlockHash,
        verbosity: Option<u32>,
    },
    /// Returns information about the peers we are connected to
    #[command(name = "getpeerinfo")]
    GetPeerInfo,
    /// Returns the value associated with a UTXO, if it's still not spent.
    /// This function only works properly if we have the compact block filters
    /// feature enabled
    #[command(name = "gettxout")]
    GetTxOut { txid: Txid, vout: u32 },
    /// Stops the node
    #[command(name = "stop")]
    Stop,
    /// Connects with a peer, given its address and port
    /// Usage: addnode <ip:[port]>
    #[command(name = "addnode")]
    AddNode { node: String },
    #[command(name = "findtxout")]
    FindTxOut {
        txid: Txid,
        vout: u32,
        script: String,
        height_hint: Option<u32>,
    },
    /// Returns stats about our memory usage
    #[command(name = "getmemoryinfo")]
    GetMemoryInfo { mode: Option<String> },
    /// Returns information about the RPC server
    #[command(name = "getrpcinfo")]
    GetRpcInfo,
    /// Returns for how long the node has been running, in seconds
    #[command(name = "uptime")]
    Uptime,
}
