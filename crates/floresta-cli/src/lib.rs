// SPDX license specifier: MIT

//! # floresta-cli - A command line interface for florestad
//!
//! Florestad is a lightweight Bitcoin full node, built with libfloresta. It gives
//! you complete control over your Bitcoin node with a simple json-rpc interface that
//! may be used either from command line or programmatically. This crate provides a
//! ready-to-use library for interacting with florestad's json-rpc interface in your rust
//! application.

#[cfg(feature = "with-jsonrpc")]
pub mod jsonrpc_client;

pub mod rpc;
pub mod rpc_types;

// Those tests doesn't work on windowns
// TODO (Davidson): work on windows?

#[cfg(all(test, feature = "with-jsonrpc", not(target_os = "windows")))]
mod tests {
    use std::fs;
    use std::net::TcpListener;
    use std::path::Path;
    use std::process::Child;
    use std::process::Command;
    use std::process::Stdio;
    use std::str::FromStr;
    use std::thread::sleep;
    use std::time::Duration;

    use bitcoin::BlockHash;
    use bitcoin::Txid;
    use rcgen::generate_simple_self_signed;
    use rcgen::CertifiedKey;

    use crate::jsonrpc_client::Client;
    use crate::rpc::FlorestaRPC;
    use crate::rpc_types::GetBlockRes;

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
    fn start_florestad() -> (Florestad, Client) {
        // CARGO_MANIFEST_DIR is always floresta-cli's directory; PWD changes based on where the
        // command is executed.
        let root = format!("{}/../..", env!("CARGO_MANIFEST_DIR"));
        let release_path = format!("{root}/target/release/florestad");
        let debug_path = format!("{root}/target/debug/florestad");

        let release_found = Path::new(&release_path).try_exists().unwrap();
        // If release target not found, default to the debug path
        let florestad_path = match release_found {
            true => release_path,
            false => debug_path,
        };

        // Makes a temporary directory to store the chain db, SSL certificates, logs, etc.
        let test_code = rand::random::<u64>();
        let dirname = format!("{root}/tmp/floresta.{test_code}");
        fs::DirBuilder::new()
            .recursive(true)
            .create(&dirname)
            .unwrap();

        // Generate SSL certificate and key using rcgen
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        fs::create_dir_all(format!("{dirname}/regtest/ssl")).unwrap();
        fs::write(format!("{dirname}/regtest/ssl/cert.pem"), cert_pem).unwrap();
        fs::write(format!("{dirname}/regtest/ssl/key.pem"), key_pem).unwrap();

        let port = get_available_port();
        let fld = Command::new(&florestad_path)
            .args(["-n", "regtest"])
            .args(["--data-dir", &dirname])
            .args(["--rpc-address", &format!("127.0.0.1:{}", port)])
            .args(["--electrum-address", "127.0.0.1:0"])
            .args(["--ssl-electrum-address", "127.0.0.1:0"])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap_or_else(|e| panic!("Couldn't launch florestad at {}: {}", florestad_path, e));

        let client = Client::new(format!("http://127.0.0.1:{port}"));

        let mut retries = 10;
        loop {
            // Wait some time for florestad to start
            sleep(Duration::from_secs(1));

            if retries == 0 {
                panic!("florestad didn't start");
            }
            retries -= 1;
            match client.get_blockchain_info() {
                Ok(_) => break,
                Err(_) => continue,
            }
        }

        (Florestad { proc: fld }, client)
    }

    fn get_available_port() -> u16 {
        // Limit `listener` scope to release port
        let port = {
            let listener =
                TcpListener::bind("127.0.0.1:0").expect("Failed to bind to an available port");
            listener.local_addr().unwrap().port()
        };

        // Delay to ensure port is fully released by OS
        sleep(Duration::from_millis(100));

        port
    }

    #[test]
    fn test_stop() {
        let (mut _proc, client) = start_florestad();

        let stop = client.stop().expect("rpc not working");
        assert_eq!(stop.as_str(), "florestad stopping");
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

        let block = client.get_block(block_hash, Some(1)).unwrap();
        let GetBlockRes::Verbose(block) = block else {
            panic!("Expected verbose block");
        };

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
    fn test_get_height() {
        let (_proc, client) = start_florestad();

        let height = client.get_block_count().unwrap();
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
