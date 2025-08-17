#![no_main]

use std::fs;
use std::path::PathBuf;

use bitcoin::block::Header as BlockHeader;
use bitcoin::block::Version;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use bitcoin::CompactTarget;
use bitcoin::TxMerkleNode;
use floresta_chain::pruned_utreexo::flat_chain_store::FlatChainStore;
use floresta_chain::pruned_utreexo::flat_chain_store::FlatChainStoreConfig;
use floresta_chain::pruned_utreexo::ChainStore;
use floresta_chain::BestChain;
use floresta_chain::DiskBlockHeader;
use libfuzzer_sys::fuzz_target;

// Create a unique temporary directory for each fuzzing run
fn create_temp_dir(test_id: u32) -> PathBuf {
    let temp_dir: PathBuf = format!("./tmp/fuzz-{}", test_id).into();
    fs::create_dir_all(&temp_dir).expect("Failed to create temp directory");
    temp_dir
}

// Construct headers with given prev_hash
fn create_header_with_prev(prev_hash: BlockHash, nonce: u32) -> BlockHeader {
    BlockHeader {
        version: Version::from_consensus(1),
        prev_blockhash: prev_hash,
        merkle_root: TxMerkleNode::all_zeros(), // all zeros for simplicity
        time: 1231006505,                       // Genesis block timestamp
        bits: CompactTarget::from_consensus(0x1d00ffff), // Genesis difficulty
        nonce,
    }
}

fuzz_target!(|data: &[u8]| {
    // Need enough data for simulating a chain and reorgs
    if data.len() < 32 {
        return;
    }

    let mut id: [u8; 4] = [0; 4];
    id.copy_from_slice(&data[0..4]);
    let id = u32::from_be_bytes(id);

    let temp_dir = create_temp_dir(id);
    let config = FlatChainStoreConfig {
        block_index_size: Some(256),
        headers_file_size: Some(256),
        fork_file_size: Some(128),
        cache_size: Some(32),
        file_permission: Some(0o666),
        path: temp_dir.to_str().unwrap().to_string(),
    };

    // Initialize the chainstore
    let mut store = match FlatChainStore::new(config) {
        Ok(store) => store,
        Err(_) => return, // If we can't create store, skip
    };

    // Create a chain of headers where each one points to the previous
    let mut headers = Vec::new();
    let mut fork_headers: Vec<BlockHeader> = Vec::new();

    // Genesis header
    let genesis = BlockHeader {
        version: Version::from_consensus(1),
        prev_blockhash: BlockHash::all_zeros(), // Genesis block has no previous hash
        merkle_root: TxMerkleNode::all_zeros(), // all zeros for simplicity
        time: 1231006505,                       // Genesis block timestamp
        bits: CompactTarget::from_consensus(0x1d00ffff), // Genesis difficulty
        nonce: data[0] as u32,                  // Use first byte of data as nonce
    };

    headers.push(genesis);

    // Create a chain of headers (height 0 to 9)
    let chain_length = 10.min(data.len() / 3);
    for i in 1..chain_length {
        let prev_hash = headers[i - 1].block_hash();
        let header = create_header_with_prev(prev_hash, data[i] as u32);
        headers.push(header);
    }

    // Create a fork starting from height 3 (if we have enough headers)
    if headers.len() > 3 {
        let fork_point = 3;
        let prev_hash = headers[fork_point].block_hash();

        // Create a fork chain
        let fork_length = 5.min(data.len() / 4);
        for i in 0..fork_length {
            let prev = if i == 0 {
                prev_hash
            } else {
                fork_headers[i - 1].block_hash()
            };

            let nonce = data[i + chain_length] as u32;
            let header = create_header_with_prev(prev, nonce);
            fork_headers.push(header);
        }
    }

    // First save all main chain headers
    for (i, header) in headers.iter().enumerate() {
        let height = i as u32;
        let variant = DiskBlockHeader::FullyValid(*header, height);

        // Save header and update index
        if store.save_header(&variant).is_err() {
            continue;
        }

        if store
            .update_block_index(height, header.block_hash())
            .is_err()
        {
            continue;
        }

        // Create some accumulator data
        let acc_data = vec![i as u8; 32]; // Simple mock data
        let _ = store.save_roots_for_block(acc_data, height);
    }

    // Set the best chain
    if !headers.is_empty() {
        let last_header = headers.last().unwrap();
        let best_chain = BestChain {
            best_block: last_header.block_hash(),
            depth: (headers.len() - 1) as u32,
            validation_index: last_header.block_hash(),
            alternative_tips: vec![],
            assume_valid_index: 0,
        };

        let _ = store.save_height(&best_chain);
        let _ = store.flush();
    }

    // Now save fork headers
    for (i, header) in fork_headers.iter().enumerate() {
        let height = (i + 3) as u32; // Fork starts at height 3

        // First save as a fork
        let variant = DiskBlockHeader::InFork(*header, height);
        let _ = store.save_header(&variant);

        // Then try to switch to this chain by saving as fully valid and updating the index
        let variant2 = DiskBlockHeader::FullyValid(*header, height);
        let _ = store.save_header(&variant2);
        let _ = store.update_block_index(height, header.block_hash());

        // Create some accumulator data for the fork
        let acc_data = vec![(i + 100) as u8; 32]; // Different mock data
        let _ = store.save_roots_for_block(acc_data, height);
    }

    // If we have fork headers, try to make it the best chain
    if !fork_headers.is_empty() {
        let last_fork_header = fork_headers.last().unwrap();
        let best_chain = BestChain {
            best_block: last_fork_header.block_hash(),
            depth: (fork_headers.len() + 2) as u32, // +2 for the shared history
            validation_index: last_fork_header.block_hash(),
            alternative_tips: if !headers.is_empty() {
                vec![headers.last().unwrap().block_hash()]
            } else {
                vec![]
            },
            assume_valid_index: 0,
        };

        let _ = store.save_height(&best_chain);
    }

    // Final flush
    let _ = store.flush();

    // Now do some random queries to test memory safety
    if !headers.is_empty() {
        for header in headers {
            let _ = store.get_header(&header.block_hash());
        }
    }

    if !fork_headers.is_empty() {
        for header in fork_headers {
            let _ = store.get_header(&header.block_hash());
        }
    }

    // Query some random heights
    if !data.is_empty() {
        for i in 0..data.len().min(20) {
            let height = data[i] as u32 % 20;
            let _ = store.get_block_hash(height);
            let _ = store.load_roots_for_block(height);
        }
    }

    // Final integrity check
    let _ = store.check_integrity();

    // Clean up
    let _ = fs::remove_dir_all(temp_dir);
});
