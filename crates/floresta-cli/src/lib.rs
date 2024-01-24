// SPDX license specifier: MIT

//! # floresta-cli - A command line interface for florestad
//!
//! Florestad is a lightweight Bitcoin full node, built with libfloresta. It gives
//! you complete control over your Bitcoin node with a simple json-rpc interface that
//! may be used either from command line or programmatically. This crate provides a
//! ready-to-use library for interacting with florestad's json-rpc interface in your rust
//! application.

pub mod rpc_types;

#[cfg(feature = "with-reqwest")]
pub mod reqwest_client;

use std::fmt::Debug;

use bitcoin::block::Header as BlockHeader;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::Txid;
use rpc_types::*;
use serde_json::Number;
use serde_json::Value;

type Result<T> = std::result::Result<T, rpc_types::Error>;

/// A trait specifying all possible methods for floresta's json-rpc
pub trait FlorestaRPC {
    /// Get the BIP158 filter for a given block height
    ///
    /// BIP158 filters are a compact representation of the set of transactions in a block,
    /// designed for efficient light client synchronization. This method returns the filter
    /// for a given block height, encoded as a hexadecimal string.
    /// You need to have enabled block filters by setting the `blockfilters=1` option
    fn get_block_filter(&self, heigth: u32) -> Result<String>;
    /// Returns general information about the chain we are on
    ///
    /// This method returns a bunch of information about the chain we are on, including
    /// the current height, the best block hash, the difficulty, and whether we are
    /// currently in IBD (Initial Block Download) mode.
    fn get_blockchain_info(&self) -> Result<GetBlockchainInfoRes>;
    /// Returns the hash of the block at the given height
    ///
    /// This method returns the hash of the block at the given height. If the height is
    /// invalid, an error is returned.
    fn get_block_hash(&self, height: u32) -> Result<BlockHash>;
    /// Returns the block header for the given block hash
    ///
    /// This method returns the block header for the given block hash, as defined
    /// in the Bitcoin protocol specification. A header contains the block's version,
    /// the previous block hash, the merkle root, the timestamp, the difficulty target,
    /// and the nonce.
    fn get_block_header(&self, hash: BlockHash) -> Result<BlockHeader>;
    /// Gets a transaction from the blockchain
    ///
    /// This method returns a transaction that's cached in our wallet. If the verbosity flag is
    /// set to false, the transaction is returned as a hexadecimal string. If the verbosity
    /// flag is set to true, the transaction is returned as a json object.
    fn get_transaction(&self, tx_id: Txid, verbosity: Option<bool>) -> Result<Value>;
    /// Returns the proof that one or more transactions were included in a block
    ///
    /// This method returns the Merkle proof, showing that a transaction was included in a block.
    /// The pooof is returned as a vector hexadecimal string.
    fn get_tx_proof(&self, tx_id: Txid) -> Result<Vec<String>>;
    /// Loads up a descriptor into the wallet
    ///
    /// This method loads up a descriptor into the wallet. If the rescan option is not None,
    /// the wallet will be rescanned for transactions matching the descriptor. If you have
    /// compact block filters enabled, this process will be much faster and use less bandwidth.
    /// The rescan parameter is the height at which to start the rescan, and should be at least
    /// as old as the oldest transaction this descriptor could have been used in.
    fn load_descriptor(&self, descriptor: String, rescan: Option<u32>) -> Result<bool>;
    /// Trigger a rescan of the wallet
    ///
    /// This method triggers a rescan of the wallet. If you have compact block filters enabled,
    /// this process will be much faster and use less bandwidth. If you don't have compact block
    /// filters, we'll need to download the entire blockchain again, which will take a while.
    /// The rescan parameter is the height at which to start the rescan, and should be at least
    /// as old as the oldest transaction this descriptor could have been used in.
    fn rescan(&self, rescan: u32) -> Result<bool>;
    /// Returns the current height of the blockchain
    fn get_height(&self) -> Result<u32>;
    /// Sends a hex-encoded transaction to the network
    ///
    /// This method sends a transaction to the network. The transaction should be encoded as a
    /// hexadecimal string. If the transaction is valid, it will be broadcast to the network, and
    /// return the transaction id. If the transaction is invalid, an error will be returned.
    fn send_raw_transaction(&self, tx: String) -> Result<Txid>;
    /// Gets the current accumulator for the chain we're on
    ///
    /// This method returns the current accumulator for the chain we're on. The accumulator is
    /// a set of roots, that let's us prove that a UTXO exists in the chain. This method returns
    /// a vector of hexadecimal strings, each of which is a root in the accumulator.
    fn get_roots(&self) -> Result<Vec<String>>;
    /// Gets information about the peers we're connected with
    ///
    /// This method returns information about the peers we're connected with. This includes
    /// the peer's IP address, the peer's version, the peer's user agent, and the peer's
    /// current height.
    fn get_peer_info(&self) -> Result<Vec<PeerInfo>>;
    /// Returns a block, given a block hash
    ///
    /// This method returns a block, given a block hash. If the verbosity flag is 0, the block
    /// is returned as a hexadecimal string. If the verbosity flag is 1, the block is returned
    /// as a json object.
    fn get_block(&self, hash: BlockHash) -> Result<GetBlockRes>;
    /// Finds an specific utxo in the chain
    ///
    /// You can use this to look for a utxo. If it exists, it will return the amount and
    /// scriptPubKey of this utxo. It returns an empty object if the utxo doesn't exist.
    /// You must have enabled block filters by setting the `blockfilters=1` option.
    fn get_tx_out(&self, tx_id: Txid, outpoint: u32) -> Result<Value>;
    /// Stops the florestad process
    ///
    /// This can be used to gracefully stop the florestad process.
    fn stop(&self) -> Result<bool>;
    /// Tells florestad to connect with a peer
    ///
    /// You can use this to connect with a given node, providing it's IP address and port.
    fn add_node(&self, node: String) -> Result<bool>;
}

/// Since the workflow for jsonrpc is the same for all methods, we can implement a trait
/// that will let us call any method on the client, and then implement the methods on any
/// client that implements this trait.
pub trait JsonRPCClient: Sized {
    /// Calls a method on the client
    ///
    /// This should call the appropriated rpc method and return a parsed response or error.
    fn call<T: serde::de::DeserializeOwned>(&self, method: &str, params: &[Value]) -> Result<T>
    where
        T: for<'a> serde::de::Deserialize<'a> + Debug;
}

impl<T: JsonRPCClient> FlorestaRPC for T {
    fn add_node(&self, node: String) -> Result<bool> {
        self.call("addnode", &[Value::String(node)])
    }

    fn stop(&self) -> Result<bool> {
        self.call("stop", &[])
    }

    fn rescan(&self, rescan: u32) -> Result<bool> {
        self.call("rescan", &[Value::Number(Number::from(rescan))])
    }

    fn get_roots(&self) -> Result<Vec<String>> {
        self.call("getroots", &[])
    }

    fn get_block(&self, hash: BlockHash) -> Result<GetBlockRes> {
        let verbosity = 1; // Return the block in json format
        self.call(
            "getblock",
            &[
                Value::String(hash.to_string()),
                Value::Number(Number::from(verbosity)),
            ],
        )
    }

    fn get_height(&self) -> Result<u32> {
        self.call("getheight", &[])
    }

    fn get_tx_out(&self, tx_id: Txid, outpoint: u32) -> Result<Value> {
        self.call(
            "gettxout",
            &[
                Value::String(tx_id.to_string()),
                Value::Number(Number::from(outpoint)),
            ],
        )
    }

    fn get_tx_proof(&self, tx_id: Txid) -> Result<Vec<String>> {
        self.call("gettxoutproof", &[Value::String(tx_id.to_string())])
    }

    fn get_peer_info(&self) -> Result<Vec<PeerInfo>> {
        self.call("getpeerinfo", &[])
    }

    fn get_block_hash(&self, height: u32) -> Result<BlockHash> {
        self.call("getblockhash", &[Value::Number(Number::from(height))])
    }

    fn get_transaction(&self, tx_id: Txid, verbosity: Option<bool>) -> Result<Value> {
        let verbosity = verbosity.unwrap_or(false);
        self.call(
            "getrawtransaction",
            &[Value::String(tx_id.to_string()), Value::Bool(verbosity)],
        )
    }

    fn load_descriptor(&self, descriptor: String, rescan: Option<u32>) -> Result<bool> {
        let rescan = rescan.unwrap_or(0);
        self.call(
            "loaddescriptor",
            &[
                Value::String(descriptor),
                Value::Number(Number::from(rescan)),
            ],
        )
    }

    fn get_block_filter(&self, heigth: u32) -> Result<String> {
        self.call("getblockfilter", &[Value::Number(Number::from(heigth))])
    }

    fn get_block_header(&self, hash: BlockHash) -> Result<BlockHeader> {
        self.call("getblockheader", &[Value::String(hash.to_string())])
    }

    fn get_blockchain_info(&self) -> Result<GetBlockchainInfoRes> {
        self.call("getblockchaininfo", &[])
    }

    fn send_raw_transaction(&self, tx: String) -> Result<Txid> {
        self.call("sendrawtransaction", &[Value::String(tx)])
    }
}

// Those tests doesn't work on windowns
// TODO (Davidson): work on windows?
#[cfg(all(test, not(target_os = "windows")))]
mod tests {
    use std::fs;
    use std::process::Child;
    use std::process::Command;
    use std::process::Stdio;
    use std::str::FromStr;
    use std::thread::sleep;
    use std::time::Duration;

    use bitcoin::BlockHash;
    use bitcoin::Txid;

    use crate::reqwest_client::ReqwestClient;
    use crate::FlorestaRPC;

    struct Florestad {
        proc: Child,
    }

    impl Drop for Florestad {
        fn drop(&mut self) {
            self.proc.kill().unwrap();
        }
    }

    /// A helper function for tests.
    ///
    /// This function will start a florestad process and return a client that can be used to
    /// interact with it through RPC. It also returns a handle to the process itself, so that
    /// you can poke at the stdin and out for this process. You don't have to kill it though,
    /// once the handle goes out of scope, the process will be killed.
    ///
    /// The process created by this method will run in a random datadir and use random ports
    /// for both RPC and Electrum. The datadir will be in the current dir, under a `tmp` subdir.
    /// If you're at $HOME/floresta it will run on $HOME/floresta/tmp/<random_name>/
    fn start_florestad() -> (Florestad, ReqwestClient) {
        let here = env!("PWD");
        let port = rand::random::<u16>() % 1000 + 18443;

        // makes a temporary directory
        let test_code = rand::random::<u64>();
        let dirname = format!("{here}/tmp/floresta.{test_code}");
        fs::DirBuilder::new()
            .recursive(true)
            .create(dirname.clone())
            .unwrap();

        let fld = Command::new(format!("{here}/target/debug/florestad"))
            .args(["-n", "regtest"])
            .args(["run"])
            .args(["--data-dir", &dirname])
            .args(["--rpc-address", &format!("127.0.0.1:{}", port)])
            .args(["--electrum-address", &format!("127.0.0.1:{}", port + 1)])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        let client = ReqwestClient::new(format!("http://127.0.0.1:{port}"));

        let mut retries = 10;

        loop {
            sleep(Duration::from_secs(1));
            retries -= 1;
            if retries == 0 {
                panic!("florestad didn't start {:?}", fld.stdout);
            }
            match client.get_blockchain_info() {
                Ok(_) => break,
                Err(_) => continue,
            }
        }

        (Florestad { proc: fld }, client)
    }

    #[test]
    fn test_rescan() {
        let (_proc, client) = start_florestad();

        let rescan = client.rescan(0).expect("rpc not working");
        assert!(rescan);
    }

    #[test]
    fn test_stop() {
        let (mut _proc, client) = start_florestad();

        let stop = client.stop().expect("rpc not working");
        assert!(stop);
    }

    #[test]
    fn test_get_blockchaininfo() {
        let (_proc, client) = start_florestad();

        let gbi = client.get_blockchain_info().expect("rpc not working");

        assert_eq!(gbi.height, 0);
        assert_eq!(gbi.chain, "regtest".to_owned());
        assert!(gbi.ibd);
        assert_eq!(gbi.leaf_count, 0);
        assert_eq!(gbi.root_hashes, Vec::<String>::new());
    }

    #[test]
    fn test_get_roots() {
        let (_proc, client) = start_florestad();

        let gbi = client.get_blockchain_info().expect("rpc not working");

        assert_eq!(gbi.root_hashes, Vec::<String>::new());
    }

    #[test]
    fn test_get_block() {
        let (_proc, client) = start_florestad();

        let block_hash: BlockHash =
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
                .parse()
                .unwrap();
        let block = client.get_block(block_hash).unwrap();

        assert_eq!(
            block.hash,
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206".to_owned()
        );
    }

    #[test]
    fn test_get_block_hash() {
        let (_proc, client) = start_florestad();

        let blockhash = client.get_block_hash(0).expect("rpc not working");

        assert_eq!(
            blockhash,
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
                .parse()
                .unwrap()
        );
    }

    #[test]
    fn test_get_block_header() {
        let (_proc, client) = start_florestad();

        let blockhash = client.get_block_hash(0).expect("rpc not working");
        let block_header = client.get_block_header(blockhash).expect("rpc not working");

        assert_eq!(block_header.block_hash(), blockhash);
    }

    #[test]
    fn test_get_block_filter() {
        let (_proc, client) = start_florestad();

        let block_filter = client.get_block_filter(0);

        // this should err, because there is no filter for genesis block
        assert!(block_filter.is_err());
    }

    #[test]
    fn test_load_descriptor() {
        let (_proc, client) = start_florestad();

        let desc = "
            wsh(sortedmulti(1,[54ff5a12/48h/1h/0h/2h]tpubDDw6pwZA3hYxcSN32q7a5ynsKmWr4BbkBNHydHPKkM4BZwUfiK7tQ26h7USm8kA1E2FvCy7f7Er7QXKF8RNptATywydARtzgrxuPDwyYv4x/<0;1>/*,[bcf969c0/48h/1h/0h/2h]tpubDEFdgZdCPgQBTNtGj4h6AehK79Jm4LH54JrYBJjAtHMLEAth7LuY87awx9ZMiCURFzFWhxToRJK6xp39aqeJWrG5nuW3eBnXeMJcvDeDxfp/<0;1>/*))#fuw35j0q";

        let res = client.load_descriptor(desc.to_string(), Some(0)).unwrap();

        assert!(res)
    }

    #[test]
    fn test_get_height() {
        let (_proc, client) = start_florestad();

        let height = client.get_height().unwrap();
        assert_eq!(height, 0);
    }

    #[test]
    fn test_send_raw_transaction() {
        let (_proc, client) = start_florestad();

        let tx = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000".to_string();

        let res = client.send_raw_transaction(tx).unwrap();
        assert_eq!(
            res,
            Txid::from_str("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
                .unwrap()
        );
    }
}
