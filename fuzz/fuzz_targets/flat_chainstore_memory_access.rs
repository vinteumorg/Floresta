#![no_main]
//! # FlatChainStore Memory Access Pattern Fuzzer
//!
//! This fuzzer is specifically designed to test the memory safety of the FlatChainStore
//! implementation, with a focus on the memory-mapped file operations.
//!
//! ## Testing Strategy
//!
//! 1. **Small allocation sizes**: Uses especially small sizes for the memory-mapped files to
//!    increase the likelihood of hitting boundary conditions.
//!
//! 2. **Data filling**: Fills the store up to capacity to test behavior when nearing limits.
//!
//! 3. **Random access patterns**: After filling the store, performs random access operations
//!    to test memory safety when accessing previously written data.
//!
//! 4. **Concurrent access simulation**: Opens a second handle to the same store to simulate
//!    potential concurrent access issues.
//!
//! 5. **Stress I/O operations**: Performs periodic flushes to stress the interaction between
//!    in-memory operations and disk persistence.
//!
//! ## Memory Safety Concerns
//!
//! The FlatChainStore uses memory-mapped files for:
//! - Headers file: Stores block headers sequentially
//! - Index map: Maps block hashes to heights using open addressing
//! - Fork headers file: Stores headers that aren't in the main chain
//! - Accumulator file: Stores the utreexo accumulator state
//!
//! Unsafe operations in FlatChainStore that this fuzzer targets:
//! - Pointer arithmetic in the header files
//! - Hash map lookups in the index file
//! - Memory access patterns in the flat files
//! - Boundary checking for file limits

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
    // Need enough data for header
    if data.len() < 80 {
        return;
    }

    // Try to deserialize header data
    let header = match deserialize::<BlockHeader>(&data[..80]) {
        Ok(header) => header,
        Err(_) => return, // Invalid header data, skip
    };

    // Derive some parameters from the input data
    let seed = if data.len() > 81 {
        data[81] as usize
    } else {
        0
    };

    let mut id: [u8; 4] = [0; 4];
    id.copy_from_slice(&data[0..4]);
    let id = u32::from_be_bytes(id);

    let temp_dir = create_temp_dir(id);
    let config = FlatChainStoreConfig {
        // Use especially small sizes to create boundary conditions
        block_index_size: Some(16 + (seed % 16)),
        headers_file_size: Some(16 + (seed % 16)),
        fork_file_size: Some(8 + (seed % 8)),
        cache_size: Some(4 + (seed % 4)),
        file_permission: Some(0o666),
        path: temp_dir.to_str().unwrap().to_string(),
    };

    // Initialize the chainstore
    let mut store = match FlatChainStore::new(config) {
        Ok(store) => store,
        Err(_) => return, // If we can't create store, skip
    };

    // Fill the store with headers up to capacity
    let max_headers = 16 + (seed % 16);

    for i in 0..max_headers {
        // Create a variant of the header
        let height = i as u32;
        let mut header_var = header;

        // Modify the header slightly to make it unique
        // Use a simple modification of the nonce
        header_var.nonce = header.nonce.wrapping_add(i as u32);

        // Save with different variants
        let disk_header = if i % 3 == 0 {
            DiskBlockHeader::FullyValid(header_var, height)
        } else if i % 3 == 1 {
            DiskBlockHeader::HeadersOnly(header_var, height)
        } else {
            DiskBlockHeader::InFork(header_var, height)
        };

        let _ = store.save_header(&disk_header);

        // If it's a main chain header, update the index
        if i % 3 != 2 {
            // Not a fork
            let _ = store.update_block_index(height, header_var.block_hash());
        }

        // Store some small accumulator data
        if i % 2 == 0 {
            let acc_size = (i % 33) as usize; // Create different sizes
            let acc_data = vec![i as u8; acc_size];
            let _ = store.save_roots_for_block(acc_data, height);
        }

        // Periodically flush to stress disk I/O and mmap
        if i % 4 == 0 {
            let _ = store.flush();
        }
    }

    // Now perform a series of random access patterns to stress memory access
    if data.len() > 100 {
        // Use the extra data as indices to access
        for i in 80..data.len().min(80 + max_headers) {
            let index = data[i] as u32 % (max_headers as u32);

            // Try to get a header by a reconstructed hash
            let mut modified_header = header;
            modified_header.nonce = header.nonce.wrapping_add(index);
            let hash = modified_header.block_hash();

            // Perform several access patterns
            let _ = store.get_header(&hash);
            let _ = store.get_block_hash(index);
            let _ = store.load_roots_for_block(index);
        }
    }

    // Test concurrent access to the same store (simulate multi-threading)
    // by creating another handle to the same store
    let config2 = FlatChainStoreConfig {
        block_index_size: None, // Use defaults
        headers_file_size: None,
        fork_file_size: None,
        cache_size: None,
        file_permission: None,
        path: temp_dir.to_str().unwrap().to_string(),
    };

    // Try to open the existing store
    if let Ok(store2) = FlatChainStore::new(config2) {
        // Perform some operations with the second handle
        for i in 0..max_headers {
            let height = i as u32;
            let _ = store2.get_block_hash(height);

            // Modify header nonce to get its hash
            let mut modified_header = header;
            modified_header.nonce = header.nonce.wrapping_add(i as u32);
            let hash = modified_header.block_hash();

            let _ = store2.get_header(&hash);
        }

        // Final integrity check
        let _ = store2.check_integrity();
    }

    // Final flush and integrity check on the original store
    let _ = store.flush();
    let _ = store.check_integrity();

    // Clean up
    let _ = fs::remove_dir_all(temp_dir);
});
