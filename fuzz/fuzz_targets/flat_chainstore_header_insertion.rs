#![no_main]

use std::fs;
use std::path::PathBuf;

use bitcoin::block::Header as BlockHeader;
use bitcoin::consensus::deserialize;
use floresta_chain::pruned_utreexo::flat_chain_store::FlatChainStore;
use floresta_chain::pruned_utreexo::flat_chain_store::FlatChainStoreConfig;
use floresta_chain::pruned_utreexo::ChainStore;
use floresta_chain::DiskBlockHeader;
use libfuzzer_sys::fuzz_target;

// Create a unique temporary directory for each fuzzing run
fn create_temp_dir(test_id: u32) -> PathBuf {
    let temp_dir: PathBuf = format!("./tmp/fuzz-{}", test_id).into();
    fs::create_dir_all(&temp_dir).expect("Failed to create temp directory");

    temp_dir
}

fuzz_target!(|data: &[u8]| {
    // Don't process too small inputs
    if data.len() < 80 {
        return;
    }

    // Try to deserialize header data
    let header = match deserialize::<BlockHeader>(data) {
        Ok(header) => header,
        Err(_) => return, // Invalid header data, skip
    };

    // Create a temporary directory for our chainstore
    let mut id: [u8; 4] = [0; 4];
    id.copy_from_slice(&data[0..4]);
    let id = u32::from_be_bytes(id);

    let temp_dir = create_temp_dir(id);
    let config = FlatChainStoreConfig {
        block_index_size: Some(128), // Use small values for fuzzing
        headers_file_size: Some(128),
        fork_file_size: Some(64),
        cache_size: Some(10),
        file_permission: Some(0o666),
        path: temp_dir.to_str().unwrap().to_string(),
    };

    // Initialize the chainstore
    let mut store = match FlatChainStore::new(config) {
        Ok(store) => store,
        Err(_) => return, // If we can't create store, skip
    };

    // Create random block heights to test
    let heights = [
        0,                   // Genesis
        1,                   // Next block
        data[0] as u32 % 64, // Random height based on data
        127,                 // Near file size limit
    ];

    // Try saving the header at different heights
    for height in heights {
        // Try to save the header with different status
        let variants = [
            DiskBlockHeader::FullyValid(header, height),
            DiskBlockHeader::HeadersOnly(header, height),
            DiskBlockHeader::AssumedValid(header, height),
            DiskBlockHeader::InFork(header, height),
            DiskBlockHeader::Orphan(header),
            DiskBlockHeader::InvalidChain(header),
        ];

        for variant in variants {
            // Save header
            let _ = store.save_header(&variant);

            // If it's a header with height, update the block index
            if let Some(height) = variant.height() {
                let _ = store.update_block_index(height, header.block_hash());
            }

            // Try to retrieve the header
            let _ = store.get_header(&header.block_hash());

            // Try to get block hash by height
            if let Some(height) = variant.height() {
                let _ = store.get_block_hash(height);
            }

            // Flush to disk
            let _ = store.flush();

            // Check integrity
            let _ = store.check_integrity();
        }
    }

    // Clean up
    let _ = fs::remove_dir_all(temp_dir);
});
