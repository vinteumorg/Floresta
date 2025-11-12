//! Block Parsing Differential Fuzzer
//!
//! Tests block parsing between Bitcoin Core and Floresta.


#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

#[path = "helpers/mod.rs"]
mod helpers;

use helpers::rpc_helper::RpcClient;
use helpers::logging::{init_logger, log, log_differential_bug, LogLevel};
use serde_json::json;

static BITCOIN_CORE_CLIENT: OnceLock<RpcClient> = OnceLock::new();
static FLORESTA_CLIENT: OnceLock<RpcClient> = OnceLock::new();

fn init_fuzzer() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    
    INIT.call_once(|| {
        init_logger(None, true, LogLevel::Info);
        log(LogLevel::Info, "BLOCK_FUZZER", "Initializing block parsing differential fuzzer");
        
        let _ = BITCOIN_CORE_CLIENT.get_or_init(|| {
            let client = RpcClient::new_bitcoind();
            log(LogLevel::Info, "BLOCK_FUZZER", &format!("Connected to Bitcoin Core on port"));
            client
        });
        
        let _ = FLORESTA_CLIENT.get_or_init(|| {
            let client = RpcClient::new_floresta();
            log(LogLevel::Info, "BLOCK_FUZZER", &format!("Connected to Floresta on port"));
            client
        });
        
        log(LogLevel::Info, "BLOCK_FUZZER", "Fuzzer initialization complete");
    });
}

// Get current block count from Bitcoin Core
fn get_block_count() -> i64 {
    BITCOIN_CORE_CLIENT
        .get()
        .unwrap()
        .call("getblockcount", &[])
        .ok()
        .and_then(|v| v.as_i64())
        .unwrap_or(10) // Default to 10 if query fails
}

// Test getblock RPC with fuzzy block hash
fn test_getblock(block_hash: &str, verbosity: u8) {
    // Floresta supports verbodity levels 0 and 1
    let valid_verbosity = match verbosity % 2 {
        0 => 0,
        _ => 1,
    };
    let core_result = BITCOIN_CORE_CLIENT
        .get()
        .unwrap()
        .call("getblock", &[json!(block_hash), json!(valid_verbosity)]);
    
    let floresta_result = FLORESTA_CLIENT
        .get()
        .unwrap()
        .call("getblock", &[json!(block_hash), json!(valid_verbosity)]);
    
    match (core_result, floresta_result) {
        (Ok(core), Ok(floresta)) => {
            // Both commands succeeded - compare results
            if core != floresta {
                log_differential_bug(
                    block_hash,
                    &format!("getblock mismatch: Core={}, Floresta={}", core, floresta),
                    true,
                    false
                );
                
            }
        }
        (Err(_), Err(_)) => {
            // Both commands failed 
            log(LogLevel::Error, "BLOCK_FUZZER", "Both rejected invalid block hash");
        }
        (Ok(_), Err(e)) => {
            log_differential_bug(
                block_hash,
                &format!("Core succeeded, Floresta failed: {}", e),
                true,
                false
            );
        }
        (Err(e), Ok(_)) => {
            log_differential_bug(
                block_hash,
                &format!("Floresta succeeded, Core failed: {}", e),
                false,
                true
            );
        }
    }
}

// Test getblockhash with fuzzy block height
fn test_getblockhash(height: i64) {
    let core_result = BITCOIN_CORE_CLIENT
        .get()
        .unwrap()
        .call("getblockhash", &[json!(height)]);
    
    let floresta_result = FLORESTA_CLIENT
        .get()
        .unwrap()
        .call("getblockhash", &[json!(height)]);
    
    match (core_result, floresta_result) {
        (Ok(core_hash), Ok(floresta_hash)) => {
            // Both comands succeeded 
            if core_hash != floresta_hash {
                log_differential_bug(
                    &height.to_string(),
                    &format!("Hash mismatch: Core={}, Floresta={}", core_hash, floresta_hash),
                    true,
                    false
                );
            }
            log(LogLevel::Info, "BLOCK_FUZZER", 
                &format!("Hash of block at height {} matches", height));
        }
        (Err(core_err), Err(floresta_err)) => {
            // Both commands failed 
            log(LogLevel::Error, "BLOCK_FUZZER", 
                &format!("Hash of block at height {} not found: Core='{}', Floresta='{}'", 
                         height, core_err, floresta_err));
        }
        (Ok(core_hash), Err(floresta_err)) => {
            // Core accepted, Floresta rejected
            log_differential_bug(
                &height.to_string(),
                &format!("Core accepted ({}), Floresta rejected: {}", 
                         core_hash, floresta_err),
                true,
                false
            );
        }
        (Err(core_err), Ok(floresta_hash)) => {
            // Floresta accepted, Core rejected
            log_differential_bug(
                &height.to_string(),
                &format!("Floresta accepted ({}), Core rejected: {}", 
                         floresta_hash, core_err),
                false,
                true
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    init_fuzzer();
    
    if data.len() < 1 {
        return;
    }
    
    let block_count = get_block_count();
    
    // Choose fuzzing mode based on first byte
    match data[0] % 3 {
        0 => {
            // Fuzz getblock with malformed block hash
            if data.len() < 33 {
                return;
            }
            let block_hash = hex::encode(&data[1..33]);
            let verbosity = if data.len() > 33 { data[33] } else { 0 };
            test_getblock(&block_hash, verbosity);
        }
        1 => {
            // Fuzz getblockhash with various heights
            if data.len() < 5 { 
                return;
            }
            let raw_height = i32::from_le_bytes([data[1], data[2], data[3], data[4]]) as i64;
            
            // Generate heights: valid range, edge cases, and just beyond
            let height = match raw_height % 10 {
                // 70% of tests: valid heights (0 to block_count-1)
                0..=6 => (raw_height.abs() % block_count).max(0),
                
                // 20% of tests: edge case - at the tip (block_count-1)
                7..=8 => block_count - 1,
                
                // 10% of tests: just beyond tip (should fail gracefully)
                _ => block_count,  // One past the last valid block
            };
            
            test_getblockhash(height);
        }
        2 => {
            // Fuzz gettxout - query from actual blocks
            if data.len() < 3 {  // Need mode + 1 byte height + 1 byte verbosity
                return;
            }
            // Get block hash at this height
            if block_count > 0 {
                let block_height = (data[1] as i64) % block_count;
                
                // Get block hash at this height
                if let Ok(hash) = BITCOIN_CORE_CLIENT
                    .get()
                    .unwrap()
                    .call("getblockhash", &[json!(block_height)])
                {
                    if let Some(block_hash) = hash.as_str() {
                        test_getblock(block_hash, data[2] % 3);
                    }
                }
            }
        }
        _ => unreachable!(),
    }
});
