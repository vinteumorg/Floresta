#![no_main]

use bitcoin::consensus::deserialize;
use floresta_wire::block_proof::UtreexoProof;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = deserialize::<UtreexoProof>(data);
});
