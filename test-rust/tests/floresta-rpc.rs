#![allow(dead_code)]
#![cfg(feature = "functional-tests")]

use bitcoin::BlockHash;
use common::bitcoind::setup_bitcoind_by_bitcoind;
use common::check_peers_florestad_bitcoind;
use common::florestad::Florestad;
use common::generate_random_blocks;
use common::setup_florestad_bitcoind;
use common::wait_for_condition;
use electrsd::corepc_node::Node as BitcoinD;
use floresta_rpc::rpc::FlorestaRPC;
use floresta_rpc::rpc_types::AddNodeCommand;
use floresta_rpc::rpc_types::GetBlockRes;
use floresta_rpc::rpc_types::GetMemInfoRes;

use crate::common::assert_u32_i64_equal_with_offset;
use crate::common::florestad::setup_florestad;
use crate::common::get_shared_florestad_bitcoind_utreexod_with_blocks;
use crate::common::get_shared_florestad_bitcoind_with_blocks;

mod common;

#[test]
fn test_add_node_v1() {
    do_test_add_node(false);
}
#[test]
fn test_add_node_v2() {
    do_test_add_node(true);
}

fn do_test_add_node(v2_transport: bool) {
    //Helper function to restart bitcoind
    fn restart_bitcoind(bitcoind: &mut BitcoinD, v2_transport: bool) {
        bitcoind.client.stop().unwrap();
        wait_for_condition(|| bitcoind.client.ping().is_err()).unwrap();
        setup_bitcoind_by_bitcoind(bitcoind, v2_transport);
    }

    println!("=== Setting up florestad and bitcoind ===");
    let (florestad, mut bitcoind) = setup_florestad_bitcoind(v2_transport);
    check_peers_florestad_bitcoind(&florestad, &bitcoind, v2_transport, 1);

    println!("=== Stopping bitcoind and waiting for disconnection ===");
    bitcoind.client.stop().unwrap();
    wait_for_condition(|| bitcoind.client.ping().is_err()).unwrap();
    wait_for_condition(|| florestad.client.get_peer_info().unwrap().is_empty()).unwrap();

    println!("=== Restarting bitcoind and waiting for reconnection ===");
    setup_bitcoind_by_bitcoind(&mut bitcoind, v2_transport);
    wait_for_condition(|| {
        florestad.client.get_peer_info().unwrap().len() == 1 && florestad.client.ping().is_ok()
    })
    .unwrap();
    check_peers_florestad_bitcoind(&florestad, &bitcoind, v2_transport, 1);

    let node = bitcoind.params.p2p_socket.unwrap().to_string();

    println!("=== Not adding peer again ===");
    florestad
        .client
        .add_node(node.clone(), AddNodeCommand::Add, v2_transport)
        .unwrap();
    check_peers_florestad_bitcoind(&florestad, &bitcoind, v2_transport, 1); // Should still be only one peer
    florestad
        .client
        .add_node(node.clone(), AddNodeCommand::Add, !v2_transport)
        .unwrap();
    check_peers_florestad_bitcoind(&florestad, &bitcoind, v2_transport, 1); // Should still be only one peer
    florestad
        .client
        .add_node(node.clone(), AddNodeCommand::Onetry, v2_transport)
        .unwrap();
    check_peers_florestad_bitcoind(&florestad, &bitcoind, v2_transport, 1); // Should still be only one peer

    println!("=== Removing node from florestad ===");
    florestad
        .client
        .add_node(node.clone(), AddNodeCommand::Remove, v2_transport)
        .unwrap();
    check_peers_florestad_bitcoind(&florestad, &bitcoind, v2_transport, 1);

    println!("=== Waiting for florestad to disconnect from bitcoind ===");
    restart_bitcoind(&mut bitcoind, v2_transport);
    wait_for_condition(|| {
        florestad.client.get_peer_info().unwrap().is_empty() && florestad.client.ping().is_ok()
    })
    .unwrap();

    println!("=== Adding node with Onetry command ===");
    florestad
        .client
        .add_node(node.clone(), AddNodeCommand::Onetry, v2_transport)
        .unwrap();
    wait_for_condition(|| florestad.client.get_peer_info().unwrap().len() == 1).unwrap();
    check_peers_florestad_bitcoind(&florestad, &bitcoind, v2_transport, 1);

    println!("=== Final checks for florestad and bitcoind ===");
    restart_bitcoind(&mut bitcoind, v2_transport);
    wait_for_condition(|| florestad.client.ping().is_ok()).unwrap();
    wait_for_condition(|| florestad.client.get_peer_info().unwrap().is_empty()).unwrap();
}

#[test]
fn test_get_best_block_hash() {
    let (florestad, bitcoind) = setup_florestad_bitcoind(true);
    let floresta_best = florestad.client.get_best_block_hash().unwrap();
    let bitcoind_best = bitcoind.client.get_best_block_hash().unwrap();
    assert_eq!(floresta_best.to_string(), bitcoind_best.0);

    generate_random_blocks(&florestad, &bitcoind);

    let floresta_best = florestad.client.get_best_block_hash().unwrap();
    let bitcoind_best = bitcoind.client.get_best_block_hash().unwrap();
    assert_eq!(floresta_best.to_string(), bitcoind_best.0);
}

#[test]
fn test_get_block() {
    fn check_block(
        florestad: &Florestad,
        bitcoind: &BitcoinD,
        block_hash: BlockHash,
        verbosity: Option<u32>,
    ) {
        let floresta_block = florestad.client.get_block(block_hash, verbosity).unwrap();
        match floresta_block {
            GetBlockRes::Serialized(floresta_block_hex) => {
                assert!(verbosity.is_none());
                let bitcoin_block = bitcoind.client.get_block_verbose_zero(block_hash).unwrap();
                assert_eq!(floresta_block_hex, bitcoin_block.0);
            }
            GetBlockRes::Verbose(floresta_res) => {
                assert!(verbosity == Some(1));
                let bitcoin_res = bitcoind.client.get_block_verbose_one(block_hash).unwrap();
                assert_eq!(floresta_res.hash, bitcoin_res.hash);
                assert_u32_i64_equal_with_offset(
                    floresta_res.confirmations,
                    bitcoin_res.confirmations,
                )
                .unwrap();
                assert_eq!(
                    floresta_res.strippedsize,
                    bitcoin_res.stripped_size.unwrap() as usize
                );
                assert_eq!(floresta_res.size, bitcoin_res.size as usize);
                assert_eq!(floresta_res.weight, bitcoin_res.weight as usize);
                assert_u32_i64_equal_with_offset(floresta_res.height, bitcoin_res.height).unwrap();
                assert_eq!(floresta_res.version, bitcoin_res.version);
                assert_eq!(floresta_res.version_hex, bitcoin_res.version_hex);
                assert_eq!(floresta_res.merkleroot, bitcoin_res.merkle_root);
                assert_eq!(floresta_res.tx, bitcoin_res.tx);
                assert_u32_i64_equal_with_offset(floresta_res.time, bitcoin_res.time).unwrap();
                assert_u32_i64_equal_with_offset(
                    floresta_res.mediantime,
                    bitcoin_res.median_time.unwrap(),
                )
                .unwrap();
                assert_u32_i64_equal_with_offset(floresta_res.nonce, bitcoin_res.nonce).unwrap();
                assert_eq!(floresta_res.bits, bitcoin_res.bits);
                assert_eq!(floresta_res.difficulty, bitcoin_res.difficulty);
                // Not comparing chainwork, because the floresta no accumula chainwork yet.
                // assert_eq!(floresta_res.chainwork, bitcoin_res.chain_work);
                assert_eq!(floresta_res.n_tx, bitcoin_res.n_tx as usize);
                assert_eq!(
                    floresta_res.previousblockhash,
                    bitcoin_res.previous_block_hash.unwrap_or(
                        "0000000000000000000000000000000000000000000000000000000000000000"
                            .to_string()
                    )
                );
                assert_eq!(floresta_res.nextblockhash, bitcoin_res.next_block_hash);
                assert_eq!(floresta_res.target, bitcoin_res.target);
            }
        }
    }

    fn get_blocks_and_check(florestad: &Florestad, bitcoind: &BitcoinD, block_hash: BlockHash) {
        let mut verbosity = None;
        check_block(florestad, bitcoind, block_hash, verbosity);

        verbosity = Some(1);
        check_block(florestad, bitcoind, block_hash, verbosity);
    }

    // Initial block (genesis)
    let (florestad, bitcoind) = get_shared_florestad_bitcoind_with_blocks();
    let block_hash = florestad.client.get_block_hash(0).unwrap();
    get_blocks_and_check(&florestad, &bitcoind, block_hash);

    // Check last block
    let block_hash = florestad.client.get_best_block_hash().unwrap();
    get_blocks_and_check(&florestad, &bitcoind, block_hash);

    // Check a random block floresta
    let height = florestad.client.get_block_count().unwrap() as usize;
    use rand::Rng;
    let random_height = rand::thread_rng().gen_range(0..height);
    let block_hash = florestad
        .client
        .get_block_hash(random_height as u32)
        .unwrap();
    get_blocks_and_check(&florestad, &bitcoind, block_hash);

    // Check a random block bitcoind
    let random_height = rand::thread_rng().gen_range(0..height);
    let block_hash = bitcoind
        .client
        .get_block_hash(random_height as u64)
        .unwrap()
        .block_hash()
        .unwrap();
    get_blocks_and_check(&florestad, &bitcoind, block_hash);
}

#[test]
fn test_block_chain_info() {
    fn check(florestad: &Florestad, bitcoind: &BitcoinD) {
        let floresta_info = florestad.client.get_blockchain_info().unwrap();
        let bitcoind_info = bitcoind.client.get_blockchain_info().unwrap();

        assert_eq!(floresta_info.chain, bitcoind_info.chain);
        assert_eq!(floresta_info.height, bitcoind_info.blocks as u32);
        assert_eq!(floresta_info.best_block, bitcoind_info.best_block_hash);
        assert_eq!(floresta_info.difficulty, bitcoind_info.difficulty);
        assert_eq!(floresta_info.latest_block_time, bitcoind_info.time as u32);
    }

    // Initial block (genesis)
    let (florestad, bitcoind) = setup_florestad_bitcoind(true);
    check(&florestad, &bitcoind);

    // Generate more blocks
    generate_random_blocks(&florestad, &bitcoind);

    // Check last block
    check(&florestad, &bitcoind);
}

#[test]
fn test_get_block_count() {
    let (florestad, bitcoind) = setup_florestad_bitcoind(true);

    // Check genesis block height
    let floresta_height = florestad.client.get_block_count().unwrap();
    let bitcoind_height = bitcoind.client.get_block_count().unwrap().0;
    assert_eq!(floresta_height as u64, bitcoind_height);

    // Generate more blocks
    let new_height = generate_random_blocks(&florestad, &bitcoind);

    // Check latest block height
    let floresta_height = florestad.client.get_block_count().unwrap();
    let bitcoind_height = bitcoind.client.get_block_count().unwrap().0;
    assert_eq!(floresta_height as u64, bitcoind_height);
    assert_eq!(floresta_height as usize, new_height);
}

#[test]
fn test_get_block_hash() {
    let (florestad, bitcoind) = get_shared_florestad_bitcoind_with_blocks();

    // Check genesis block hash
    let floresta_hash = florestad.client.get_block_hash(0).unwrap();
    let bitcoind_hash = bitcoind
        .client
        .get_block_hash(0)
        .unwrap()
        .block_hash()
        .unwrap();
    assert_eq!(floresta_hash, bitcoind_hash);

    // Check latest block hash
    let floresta_hash = florestad.client.get_best_block_hash().unwrap();
    let bitcoind_hash = bitcoind
        .client
        .get_best_block_hash()
        .unwrap()
        .block_hash()
        .unwrap();

    assert_eq!(floresta_hash, bitcoind_hash);

    // Check a random block hash
    let height = florestad.client.get_block_count().unwrap() as usize;
    use rand::Rng;
    let random_height = rand::thread_rng().gen_range(0..height);
    let floresta_hash = florestad
        .client
        .get_block_hash(random_height as u32)
        .unwrap();
    let bitcoind_hash = bitcoind
        .client
        .get_block_hash(random_height as u64)
        .unwrap()
        .block_hash()
        .unwrap();
    assert_eq!(floresta_hash, bitcoind_hash);
}

#[test]
fn test_get_block_header() {
    let (florestad, bitcoind) = get_shared_florestad_bitcoind_with_blocks();

    // Check genesis block header
    let floresta_hash = florestad.client.get_block_hash(0).unwrap();
    let floresta_header = florestad.client.get_block_header(floresta_hash).unwrap();
    let bitcoind_header = bitcoind
        .client
        .get_block_header(&floresta_hash)
        .unwrap()
        .block_header()
        .unwrap();
    assert_eq!(floresta_header, bitcoind_header);

    // Check latest block header
    let floresta_hash = florestad.client.get_best_block_hash().unwrap();
    let floresta_header = florestad.client.get_block_header(floresta_hash).unwrap();
    let bitcoind_header = bitcoind
        .client
        .get_block_header(&floresta_hash)
        .unwrap()
        .block_header()
        .unwrap();
    assert_eq!(floresta_header, bitcoind_header);

    // Check a random block header
    let height = florestad.client.get_block_count().unwrap() as usize;
    use rand::Rng;
    let random_height = rand::thread_rng().gen_range(0..height);
    let floresta_hash = florestad
        .client
        .get_block_hash(random_height as u32)
        .unwrap();
    let floresta_header = florestad.client.get_block_header(floresta_hash).unwrap();
    let bitcoind_header = bitcoind
        .client
        .get_block_header(&floresta_hash)
        .unwrap()
        .block_header()
        .unwrap();
    assert_eq!(floresta_header, bitcoind_header);
}

#[test]
fn test_get_memory_info() {
    let (florestad, _bitcoind) = get_shared_florestad_bitcoind_with_blocks();

    // Test mode "stats" (only on Linux)
    #[cfg(target_os = "linux")]
    {
        let result = florestad
            .client
            .get_memory_info("stats".to_string())
            .unwrap();
        match result {
            GetMemInfoRes::Stats(res) => {
                // Check basic invariants: total should be at least the used/free parts,
                assert!(res.locked.total >= res.locked.used);
                assert!(res.locked.total >= res.locked.free);
                assert!(res.locked.locked > 0);

                assert!(res.locked.chunks_used > 0);
                assert!(res.locked.chunks_free > 0);
            }
            _ => panic!("Expected GetMemInfoRes::Stats"),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Skip on non-Linux
        println!("Skipping 'getmemoryinfo stats': not implemented for this OS");
    }

    // Test mode "mallocinfo" (only on Linux)
    #[cfg(target_os = "linux")]
    {
        let result = florestad
            .client
            .get_memory_info("mallocinfo".to_string())
            .unwrap();
        match result {
            GetMemInfoRes::MallocInfo(xml) => {
                // Just checking if we got some XML content
                assert!(xml.contains("<malloc"));
                assert!(xml.contains("<heap"));
                assert!(xml.contains("<allocated>"));
                assert!(xml.contains("<free>"));
                assert!(xml.contains("<total>"));
                assert!(xml.contains("<locked>"));
                assert!(xml.contains("<chunks"));
                assert!(xml.contains("<used>"));
                assert!(xml.contains("</chunks>"));
                assert!(xml.contains("</heap>"));
                assert!(xml.contains("</malloc>"));
            }
            _ => panic!("Expected GetMemInfoRes::MallocInfo"),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Skip on non-Linux
        println!("Skipping 'getmemoryinfo mallocinfo': not implemented for this OS");
    }
}

#[test]
fn test_get_peer_info() {
    let v2_transport = true;
    let (florestad, bitcoind) = setup_florestad_bitcoind(v2_transport);

    check_peers_florestad_bitcoind(&florestad, &bitcoind, v2_transport, 1);
}

#[test]
fn test_get_roots() {
    let (florestad, _bitcoind, _utreexod) = get_shared_florestad_bitcoind_utreexod_with_blocks();

    let floresta_roots = florestad.client.get_roots().unwrap();

    assert!(!floresta_roots.is_empty());
}

#[test]
fn test_get_rpc_info() {
    let florestad = setup_florestad();
    let rpc_info = florestad.client.get_rpc_info().unwrap();
    assert_eq!(rpc_info.active_commands.len(), 1);
    assert_eq!(rpc_info.active_commands[0].method, "getrpcinfo");
    assert!(rpc_info.active_commands[0].duration > 0);
    assert_eq!(rpc_info.logpath, florestad.directory + "/regtest/debug.log");
}

#[test]
fn test_get_tx_out() {
    let (florestad, bitcoind, _utreexod) = get_shared_florestad_bitcoind_utreexod_with_blocks();

    let height = florestad.client.get_block_count().unwrap() as usize;

    use rand::Rng;
    let random_height = rand::thread_rng().gen_range(1..height);
    let block_hash = florestad
        .client
        .get_block_hash(random_height as u32)
        .unwrap();
    let block = bitcoind.client.get_block(block_hash).unwrap();
    let txid = block.txdata[0].compute_txid();
    let vout = 0;

    let txout_floresta = florestad.client.get_tx_out(txid, vout).unwrap();
    let txout_bitcoind = bitcoind.client.get_tx_out(txid, vout.into()).unwrap();
    assert_eq!(
        txout_floresta.bestblock.to_string(),
        txout_bitcoind.best_block
    );
    assert_eq!(txout_floresta.confirmations, txout_bitcoind.confirmations);
    assert_eq!(txout_floresta.value, txout_bitcoind.value);
    assert_eq!(txout_floresta.coinbase, txout_bitcoind.coinbase);
    assert_eq!(
        txout_floresta.script_pubkey.hex,
        txout_bitcoind.script_pubkey.hex
    );
    assert_eq!(
        txout_floresta.script_pubkey.type_field,
        txout_bitcoind.script_pubkey.type_
    );
    assert_eq!(
        txout_floresta.script_pubkey.asm,
        txout_bitcoind.script_pubkey.asm
    );
    assert_eq!(
        txout_floresta.script_pubkey.desc,
        txout_bitcoind
            .script_pubkey
            .descriptor
            .unwrap_or("".to_string())
    );
    assert_eq!(
        txout_floresta.script_pubkey.address,
        txout_bitcoind.script_pubkey.address
    );
}

#[test]
fn test_ping() {
    let (florestad, bitcoind) = setup_florestad_bitcoind(true);

    // Check initial state (no ping_time)
    let bitcoin_res = bitcoind.client.get_peer_info().unwrap();
    let peer_bitcoin = bitcoin_res.0.first().unwrap();
    assert!(peer_bitcoin.ping_time.is_none());

    // Send ping from florestad
    florestad.client.ping().unwrap();

    // Wait for ping_time to be set in bitcoind
    wait_for_condition(|| {
        let bitcoin_res = bitcoind.client.get_peer_info().unwrap();
        let peer_bitcoin = bitcoin_res.0.first().unwrap();
        peer_bitcoin.ping_time.is_some()
    })
    .unwrap();
}

#[test]
fn test_stop() {
    let (florestad, bitcoind) = setup_florestad_bitcoind(true);

    let stop_res = florestad.client.stop().unwrap();
    assert_eq!(stop_res.as_str(), "Floresta stopping");
    wait_for_condition(|| florestad.client.ping().is_err()).unwrap();

    wait_for_condition(|| bitcoind.client.ping().is_ok()).unwrap();
    assert!(bitcoind.client.get_peer_info().unwrap().0.is_empty())
}

#[test]
fn test_uptime() {
    let (florestad, bitcoind) = get_shared_florestad_bitcoind_with_blocks();
    std::thread::sleep(std::time::Duration::from_secs(2));

    let floresta_uptime = florestad.client.uptime().unwrap();
    let bitcoin_uptime = bitcoind.client.uptime().unwrap();

    assert!(floresta_uptime > 0);
    assert!(bitcoin_uptime > 0);

    use rand::Rng;
    let random_sleep = rand::thread_rng().gen_range(1..15);
    std::thread::sleep(std::time::Duration::from_secs(random_sleep));

    let floresta_new_uptime = florestad.client.uptime().unwrap();
    assert!(floresta_new_uptime >= floresta_uptime + random_sleep as u32);
    let bitcoin_new_uptime = bitcoind.client.uptime().unwrap();
    assert!(bitcoin_new_uptime >= bitcoin_uptime + random_sleep as u32);
}
