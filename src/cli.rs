use std::path::PathBuf;

use clap::{arg, command, Parser, Subcommand, ValueEnum};
#[derive(Clone, Debug, ValueEnum)]
pub enum Network {
    Bitcoin,
    Signet,
    Testnet,
    Regtest,
}
impl Default for Network {
    fn default() -> Self {
        Network::Bitcoin
    }
}
impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Bitcoin => write!(f, "bitcoin"),
            Network::Signet => write!(f, "signet"),
            Network::Testnet => write!(f, "testnet"),
            Network::Regtest => write!(f, "regtest"),
        }
    }
}
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,
    /// Which network should we use
    #[arg(short, long, default_value_t=Network::Bitcoin)]
    pub network: Network,
    /// Turn debugging information on
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub debug: u8,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Starts your wallet and server
    Run {
        /// Where should we store data
        data_dir: String,
        /// Your rpc user, as set in Utreexod
        #[arg(long)]
        #[arg(default_value = "")]
        rpc_user: String,
        /// Your rpc password, as set in Utreexod
        #[arg(long)]
        #[arg(default_value = "")]
        rpc_password: String,
        /// The hostname:port of Utreexod
        #[arg(short, long)]
        #[arg(default_value = "localhost")]
        rpc_host: String,

        #[arg(long)]
        #[arg(default_value_t = 8332)]
        rpc_port: u32,
        /// Whether or not we want to sync with a external provider
        #[arg(long)]
        #[arg(default_value_t = false)]
        use_external_sync: bool,
        /// If use_external_sync is set, this option provides which server we use
        #[arg(long)]
        external_sync: Option<String>,
    },
    /// Setups you wallet, creating the local database and initializing the local cache
    /// must be executed exactly once.
    Setup {
        /// Your wallet's descriptor
        wallet_xpub: String,
        /// Where should we store data
        data_dir: String,
    },
}
