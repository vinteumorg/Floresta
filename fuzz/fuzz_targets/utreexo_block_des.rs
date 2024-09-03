#![no_main]

use bitcoin::consensus::deserialize;
use floresta_chain::UtreexoBlock;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = deserialize::<UtreexoBlock>(data);
});
