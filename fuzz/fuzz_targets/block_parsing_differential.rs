//! Block Parsing Differential Fuzzer
//!
//! Tests block parsing between Bitcoin Core and Floresta.
//! # Corpus Format & Mode Selection
//!
//! The fuzzer uses a 3-mode system to test different RPC call patterns:
//!
//! **Byte 0 determines the test mode (data[0] % 3):**
//!
//! - **Mode 0: getblock(hash) - Random Block Hash Testing**
//!   - Input: [0x00][32-byte hash]
//!   - Seeds: Mainnet genesis, block 1, and variations
//!
//! - **Mode 1: getblockhash(height) - Height-Based Testing**
//!   - Input: [0x01][4-byte little-endian i32 height]
//!   - Uses weighted distribution:
//!     - 70% valid heights (0 to block_count-1): Tests normal operation
//!     - 20% at chain tip (block_count-1): Tests boundary conditions
//!     - 10% beyond tip (block_count): Tests error handling consistency
//!
//! - **Mode 2: getblockhash(height) + getblock(hash, verbosity) - Format Testing**
//!   - Input: [0x02][1-byte height_idx][1-byte verbosity]
//!   - Height is mapped to pre-defined test heights (genesis, blocks 1, 10, 100, 1000, 10000)
//!   - Verbosity tests different output formats (compact vs. JSON)

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

#[path = "helpers/mod.rs"]
mod helpers;

use helpers::logging::init_logger;
use helpers::logging::log;
use helpers::logging::log_differential_bug;
use helpers::logging::LogLevel;
use helpers::rpc_helper::RpcClient;
use serde_json::json;

static BITCOIN_CORE_CLIENT: OnceLock<RpcClient> = OnceLock::new();

static FLORESTA_CLIENT: OnceLock<RpcClient> = OnceLock::new();

/// Initializes the fuzzer by setting up RPC clients for Bitcoin Core and Floresta.
///
/// This function ensures that initialization happens exactly once using `Once`.
/// Logs initialization progress for debugging.
fn init_fuzzer() {
    use std::sync::Once;
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        init_logger(None, true, LogLevel::Info);
        log(
            LogLevel::Info,
            "BLOCK_FUZZER",
            "Initializing block parsing differential fuzzer",
        );

        let _ = BITCOIN_CORE_CLIENT.get_or_init(|| {
            let client = RpcClient::new_bitcoind();
            log(
                LogLevel::Info,
                "BLOCK_FUZZER",
                "Connected to Bitcoin Core on port",
            );
            client
        });

        let _ = FLORESTA_CLIENT.get_or_init(|| {
            let client = RpcClient::new_floresta();
            log(
                LogLevel::Info,
                "BLOCK_FUZZER",
                "Connected to Floresta on port",
            );
            client
        });

        log(
            LogLevel::Info,
            "BLOCK_FUZZER",
            "Fuzzer initialization complete",
        );
    });
}

/// Retrieves the current block count from Bitcoin Core.
///
/// # Returns
/// The number of blocks in the blockchain, or 10 as a fallback if the query fails.
fn get_block_count() -> i64 {
    BITCOIN_CORE_CLIENT
        .get()
        .unwrap()
        .call("getblockcount", &[])
        .ok()
        .and_then(|v| v.as_i64())
        .unwrap_or(10)
}

/// Tests the `getblock` RPC call for consistency between Bitcoin Core and Floresta.
///
/// # Arguments
/// * `block_hash` - Hex-encoded block hash to query
/// * `verbosity` - Output verbosity level (0 or 1 for Floresta compatibility)
///
/// Logs differential bugs if responses differ between implementations.
fn test_getblock(block_hash: &str, verbosity: u8) {
    // Floresta supports verbosity levels 0 and 1
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
                    false,
                );
            }
        }
        (Err(core_error), Err(floresta_error)) => {
            // Both commands failed
            log(
                LogLevel::Error,
                "BLOCK_FUZZER",
                &format!(
                    "Both implementations rejected block {}: Core='{}', Floresta='{}'",
                    block_hash, core_error, floresta_error
                ),
            );
        }
        (Ok(_), Err(e)) => {
            log_differential_bug(
                block_hash,
                &format!("Core succeeded, Floresta failed: {}", e),
                true,
                false,
            );
        }
        (Err(e), Ok(_)) => {
            log_differential_bug(
                block_hash,
                &format!("Floresta succeeded, Core failed: {}", e),
                false,
                true,
            );
        }
    }
}

/// Tests the `getblockhash` RPC call for consistency between implementations.
///
/// # Arguments
/// * `height` - Block height to query
///
/// Compares block hashes returned by Bitcoin Core and Floresta at the given height.
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
            // Both commands succeeded
            if core_hash != floresta_hash {
                log_differential_bug(
                    &height.to_string(),
                    &format!(
                        "Hash mismatch: Core={}, Floresta={}",
                        core_hash, floresta_hash
                    ),
                    true,
                    false,
                );
            }
            log(
                LogLevel::Info,
                "BLOCK_FUZZER",
                &format!("Hash of block at height {} matches", height),
            );
        }
        (Err(core_err), Err(floresta_err)) => {
            // Both commands failed
            log(
                LogLevel::Error,
                "BLOCK_FUZZER",
                &format!(
                    "Hash of block at height {} not found: Core='{}', Floresta='{}'",
                    height, core_err, floresta_err
                ),
            );
        }
        (Ok(core_hash), Err(floresta_err)) => {
            // Core accepted, Floresta rejected
            log_differential_bug(
                &height.to_string(),
                &format!(
                    "Core accepted ({}), Floresta rejected: {}",
                    core_hash, floresta_err
                ),
                true,
                false,
            );
        }
        (Err(core_err), Ok(floresta_hash)) => {
            // Floresta accepted, Core rejected
            log_differential_bug(
                &height.to_string(),
                &format!(
                    "Floresta accepted ({}), Core rejected: {}",
                    floresta_hash, core_err
                ),
                false,
                true,
            );
        }
    }
}
/// Differential fuzzing entry point for block parsing.

fuzz_target!(|data: &[u8]| {
    init_fuzzer();

    if data.is_empty() {
        return;
    }

    let block_count = get_block_count();

    // Choose fuzzing mode based on first byte
    match data[0] % 3 {
        0 => {
            // Mode 0: Fuzz getblock with malformed block hash
            if data.len() < 33 {
                return;
            }
            let block_hash = hex::encode(&data[1..33]);
            let verbosity = if data.len() > 33 { data[33] } else { 0 };
            test_getblock(&block_hash, verbosity);
        }
        1 => {
            // Mode 1: Fuzz getblockhash with various heights
            if data.len() < 5 {
                return;
            }
            let raw_height = i32::from_le_bytes([data[1], data[2], data[3], data[4]]) as i64;

            let height = match raw_height % 10 {
                // valid heights (0 to block_count-1)
                0..=6 => (raw_height.abs() % block_count).max(0),

                // edge case - at the tip (block_count-1)
                7..=8 => block_count - 1,

                // invalid heights (block_count and above)
                _ => block_count,
            };

            test_getblockhash(height);
        }
        2 => {
            // Mode 2: Fuzz getblockhash + getblock with verbosity variations
            if data.len() < 3 {
                return;
            }
            // Get block hash at this height
            if block_count > 0 {
                let block_height = (data[1] as i64) % block_count; // To keep the height within the total generated blocks

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
