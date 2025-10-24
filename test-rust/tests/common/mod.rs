#![allow(dead_code)]

pub(crate) mod bitcoind;
pub(crate) mod florestad;
pub(crate) mod utreexod;

use std::process::Command;
use std::process::Stdio;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use bitcoind::setup_bitcoind;
use electrsd::corepc_node;
use electrsd::corepc_node::Client as BitcoindClient;
use electrsd::corepc_node::Node as BitcoinD;
use floresta_rpc::rpc::FlorestaRPC;
use florestad::setup_florestad;
use florestad::Florestad;
use once_cell::sync::Lazy;
use rand::Rng;
use utreexod::Utreexod;

const MAX_RETRY_DURATION_SECONDS_NODE_START: u64 = 500;
const MAX_RETRY_DURATION_SECONDS: u64 = 40;
const DELAYED_RETRY_SECONDS: u64 = 20;
const SLEEP_SECONDS: u64 = 3;

//menemonicos = useless ritual arm slow mention dog force almost sudden pulp rude eager
pub(crate)  const DESCRIPTOR_INTERNAL: &str = "wpkh(tprv8hCwaWbnCTeqSXMmEgtYqC3tjCHQTKphfXBG5MfWgcA6pif3fAUqCuqwphSyXmVFhd8b5ep5krkRxF6YkuQfxSAhHMTGeRA8rKPzQd9BMre/1/*)#v08p3aj4";
pub(crate) const DESCRIPTOR_EXTERNAL: &str = "wpkh(tprv8hCwaWbnCTeqSXMmEgtYqC3tjCHQTKphfXBG5MfWgcA6pif3fAUqCuqwphSyXmVFhd8b5ep5krkRxF6YkuQfxSAhHMTGeRA8rKPzQd9BMre/0/*)#amzqvgzd";
pub(crate) const XPUB_STR: &str = "vpub5ZrpbMUWLCJ6MbpU1RzocWBddAQnk2XYry9JSXrtzxSqoicei28CzqUhiN2HJ8z2VjY6rsUNf4qxjym43ydhAFQJ7BDDcC2bK6et6x9hc4D";
pub(crate) const ADDRESS_STR: &str = "bcrt1q427ze5mrzqupzyfmqsx9gxh7xav538yk2j4cft";

// Shared instance of Florestad, BitcoinD, Utreexod, and generated blocks height, initialized once.
// Purpose: Optimize tests needing a chain with blocks by avoiding repeated setup and generation.
static SHARED_FLORESTAD_BITCOIND_UTREEXOD_WITH_BLOCKS: Lazy<Arc<(Florestad, BitcoinD, Utreexod)>> =
    Lazy::new(|| {
        let (florestad, bitcoind, utreexod) = setup_florestad_bitcoind_utreexod(true);
        let _height = generate_random_blocks_by_utreexod(&florestad, &bitcoind, &utreexod);
        Arc::new((florestad, bitcoind, utreexod))
    });

// Returns a shared reference to Florestad, BitcoinD, and Utreexod.
// Purpose: Provide access to the shared setup for tests that don't modify the chain.
pub(crate) fn get_shared_florestad_bitcoind_utreexod_with_blocks(
) -> &'static (Florestad, BitcoinD, Utreexod) {
    &*SHARED_FLORESTAD_BITCOIND_UTREEXOD_WITH_BLOCKS
}

// Returns a shared reference to Florestad and BitcoinD.
// Purpose: Provide access to the shared setup for tests that don't modify the chain.
pub(crate) fn get_shared_florestad_bitcoind_with_blocks() -> (&'static Florestad, &'static BitcoinD)
{
    let (florestad, bitcoind, _utreexod) = get_shared_florestad_bitcoind_utreexod_with_blocks();
    (florestad, bitcoind)
}

pub(crate) fn setup_florestad_bitcoind_utreexod(
    v2_transport: bool,
) -> (Florestad, BitcoinD, Utreexod) {
    let florestad = setup_florestad();
    let bitcoind = setup_bitcoind(v2_transport);
    let utreexod = Utreexod::setup();

    // It is necessary to generate some blocks so that utreexod and bitcoind can sync
    let initial_height = 10;
    utreexod.client.generate(initial_height).unwrap();

    // florestad_connected_to_bitcoind(&florestad, &bitcoind, v2_transport);
    florestad_connected_to_utreexod(&florestad, &utreexod);
    assert!(florestad.client.get_peer_info().unwrap().len() == 1);

    // Add utreexod as peer to bitcoind
    bitcoind
        .client
        .add_node(
            &utreexod.p2p.to_string(),
            electrsd::corepc_node::AddNodeCommand::Add,
        )
        .unwrap();

    // Check if bitcoind connected to utreexod
    wait_for_condition(|| {
        let info = bitcoind.client.get_peer_info().unwrap().0;
        if info.iter().any(|p| p.address == utreexod.p2p.to_string()) {
            assert!(info.len() == 1);
            return true;
        }
        false
    })
    .unwrap();

    // check if utreexod connected to bitcoind
    wait_for_condition(|| {
        let resp = utreexod.client.get_peer_info().unwrap();
        let peers = resp.as_array().unwrap();
        if peers
            .iter()
            .any(|p| p["subver"].as_str().unwrap().contains("Satoshi"))
        {
            assert!(peers.len() == 2);
            return true;
        }
        false
    })
    .unwrap();

    // Wait for all nodes to reach the same block height
    wait_for_condition(|| florestad.client.get_block_count().unwrap() == initial_height).unwrap();
    wait_for_condition(|| bitcoind.client.get_block_count().unwrap().0 as u32 == initial_height)
        .unwrap();

    (florestad, bitcoind, utreexod)
}

pub(crate) fn setup_florestad_bitcoind(v2_transport: bool) -> (Florestad, BitcoinD) {
    let florestad = setup_florestad();
    let bitcoind = setup_bitcoind(v2_transport);

    florestad_connected_to_bitcoind(&florestad, &bitcoind, v2_transport);

    (florestad, bitcoind)
}

pub(crate) fn setup_florestad_utreexod() -> (Florestad, Utreexod) {
    let florestad = setup_florestad();
    let utreexod = Utreexod::setup();

    florestad_connected_to_utreexod(&florestad, &utreexod);

    (florestad, utreexod)
}

pub(crate) fn florestad_connected_to_bitcoind(
    florestad: &Florestad,
    bitcoind: &BitcoinD,
    v2_transport: bool,
) {
    florestad
        .client
        .add_node(
            bitcoind.params.p2p_socket.as_ref().unwrap().to_string(),
            floresta_rpc::rpc_types::AddNodeCommand::Add,
            v2_transport,
        )
        .unwrap();

    // Wait for florestad to connect to bitcoind
    wait_for_condition(|| {
        let peers = florestad.client.get_peer_info().unwrap();
        peers.iter().any(|p| {
            Some(p.address.clone()) == bitcoind.params.p2p_socket.as_ref().map(|s| s.to_string())
        })
    })
    .unwrap();

    // Wait for bitcoind to connect to florestad
    wait_for_condition(|| {
        let peers = bitcoind.client.get_peer_info().unwrap().0;
        peers.iter().any(|p| p.subversion.contains("Floresta"))
    })
    .unwrap();
}

pub(crate) fn florestad_connected_to_utreexod(florestad: &Florestad, utreexod: &Utreexod) {
    florestad
        .client
        .add_node(
            utreexod.p2p.to_string(),
            floresta_rpc::rpc_types::AddNodeCommand::Add,
            false,
        )
        .unwrap();

    // Wait for florestad to connect to utreexod
    wait_for_condition(|| {
        if let Ok(peers) = florestad.client.get_peer_info() {
            return peers.iter().any(|p| p.address == utreexod.p2p.to_string());
        }
        false
    })
    .unwrap();

    // Wait for utreexod to connect to florestad
    wait_for_condition(|| {
        let resp = utreexod.client.get_peer_info().unwrap();
        let peers = resp.as_array().unwrap();
        if peers
            .iter()
            .any(|p| p["subver"].as_str().unwrap().contains("Floresta"))
        {
            return true;
        }
        false
    })
    .unwrap();
}

pub(crate) fn wait_for_condition_node_started<F>(condition: F) -> Result<(), String>
where
    F: Fn() -> bool,
{
    wait_for_condition_inner(condition, MAX_RETRY_DURATION_SECONDS_NODE_START)
}

// Helper function to wait for a condition with timeout
pub(crate) fn wait_for_condition<F>(condition: F) -> Result<(), String>
where
    F: Fn() -> bool,
{
    wait_for_condition_inner(condition, MAX_RETRY_DURATION_SECONDS)
}

fn wait_for_condition_inner<F>(condition: F, max_retries: u64) -> Result<(), String>
where
    F: Fn() -> bool,
{
    let start = Instant::now();
    loop {
        if condition() {
            return Ok(());
        }
        if start.elapsed() > Duration::from_secs(max_retries) {
            return Err("Timeout waiting for condition".into());
        }
        if start.elapsed() > Duration::from_secs(DELAYED_RETRY_SECONDS) {
            std::thread::sleep(Duration::from_secs(SLEEP_SECONDS));
        }
    }
}

/// Asserts that a u32 value equals an i64 value, allowing the i64 to be 1 more due to conversion errors.
/// Panics if the values do not match (with or without the +1 offset).
pub(crate) fn assert_u32_i64_equal_with_offset(u32_val: u32, i64_val: i64) -> Result<(), String> {
    let converted = u32_val as i64;
    if !(converted == i64_val || converted + 1 == i64_val || converted == i64_val + 1) {
        return Err(format!(
            "Time comparison failed: {} does not match {} (allowing +1 offset)",
            u32_val, i64_val
        ));
    }
    Ok(())
}

pub(crate) fn check_peers_florestad_bitcoind(
    florestad: &Florestad,
    bitcoind: &BitcoinD,
    v2_transport: bool,
    peer_len: usize,
) {
    assert!(florestad.client.ping().is_ok());
    assert!(bitcoind.client.ping().is_ok());
    let peers = florestad.client.get_peer_info().unwrap();
    assert!(peers.len() == peer_len);

    let peer = peers
        .iter()
        .find(|p| {
            Some(p.address.clone()) == bitcoind.params.p2p_socket.as_ref().map(|s| s.to_string())
        })
        .unwrap();
    assert!(peer.state == "Ready");
    assert!(peer.address == bitcoind.params.p2p_socket.unwrap().to_string());
    assert!(peer.kind == "regular");
    assert!(peer.initial_height == 0);
    let transporte_protocol = if v2_transport { "V2" } else { "V1" };
    assert!(peer.transport_protocol == transporte_protocol);

    let bitcoind_network = bitcoind.client.get_network_info().unwrap();
    assert!(peer.user_agent == bitcoind_network.subversion);
    let service = bitcoind_network.local_services_names.join("|");
    assert!(peer.services.contains(&service));

    let bitcoind_peers = bitcoind.client.get_peer_info().unwrap();
    assert!(bitcoind_peers.0.len() == 1);
    let bitcoind_peer = &bitcoind_peers.0[0];
    assert!(bitcoind_peer.starting_height.unwrap() == 0);
    assert!(bitcoind_peer.services == "0000000001000009");
    assert!(bitcoind_peer.subversion.contains("Floresta"));
    assert!(bitcoind_peer.transport_protocol_type == transporte_protocol.to_lowercase());
}

pub(crate) fn generate_random_blocks_by_utreexod(
    florestad: &Florestad,
    bitcoind: &BitcoinD,
    utreexod: &Utreexod,
) -> usize {
    let height_florestad = florestad.client.get_block_count().unwrap() as usize;

    let number_blocks = rand::thread_rng().gen_range(21..50);
    utreexod.client.generate(number_blocks as u32).unwrap();
    let expect_height_blocks = height_florestad + number_blocks;
    println!(
        "Generated {} blocks via utreexod, new height: {}",
        number_blocks, expect_height_blocks
    );

    wait_for_condition(|| {
        florestad.client.get_block_count().unwrap() == expect_height_blocks as u32
    })
    .unwrap();

    wait_for_condition(|| {
        bitcoind.client.get_block_count().unwrap().0 == expect_height_blocks as u64
    })
    .unwrap();

    wait_for_condition(|| !florestad.client.get_blockchain_info().unwrap().ibd).unwrap();

    expect_height_blocks
}

pub(crate) fn generate_random_blocks(florestad: &Florestad, bitcoind: &BitcoinD) -> usize {
    let number_blocks = rand::thread_rng().gen_range(21..50);
    let height_bitcoind = bitcoind.client.get_block_count().unwrap().0 as usize;
    let height_florestad = florestad.client.get_block_count().unwrap() as usize;
    assert!(height_bitcoind == height_florestad);

    generate_blocks_bitcoind(&bitcoind.client, number_blocks);
    let expect_height_blocks = height_bitcoind + number_blocks;

    wait_for_condition(|| {
        florestad.client.get_block_count().unwrap() == expect_height_blocks as u32
    })
    .unwrap();

    wait_for_condition(|| {
        bitcoind.client.get_block_count().unwrap().0 == expect_height_blocks as u64
    })
    .unwrap();

    expect_height_blocks
}

pub(crate) fn generate_blocks_bitcoind(bitcoind: &BitcoindClient, num: usize) {
    let address_unchecked = bitcoin::Address::from_str(&ADDRESS_STR).expect("invalid address");
    let address = address_unchecked.assume_checked();

    print!("Generating {} blocks...", num);
    bitcoind.generate_to_address(num, &address).unwrap();

    print!(" Done!");
    println!("\n");
}

pub(crate) fn run_node(path: String, args: Vec<&str>, view_log: bool) -> std::process::Child {
    let view_stdout = if view_log {
        Stdio::inherit()
    } else {
        Stdio::null()
    };
    let view_stderr = if view_log {
        Stdio::inherit()
    } else {
        Stdio::null()
    };

    let mut process = corepc_node::anyhow::Context::with_context(
        Command::new(&path)
            .args(&args)
            .stdout(view_stdout)
            .stderr(view_stderr)
            .spawn(),
        || format!("Error while executing {:?}", path),
    )
    .unwrap();

    match process.try_wait() {
        Ok(Some(_)) | Err(_) => {
            let _ = process.kill();
            panic!("process exited prematurely or failed to start");
        }
        Ok(None) => {
            // Process is still running, proceed
        }
    };

    process
}
