#![no_main]

use std::io::Cursor;

use arbitrary::Arbitrary;
use arbitrary::Unstructured;
use bitcoin::consensus::Decodable;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use floresta_chain::BestChain;
use libfuzzer_sys::fuzz_target;

fn gen_blockhash(u: &mut Unstructured<'_>) -> arbitrary::Result<BlockHash> {
    let bytes: [u8; 32] = Arbitrary::arbitrary(u)?;
    Ok(BlockHash::from_byte_array(bytes))
}

const MAX_TIPS: usize = 64;

fn gen_alt_tips(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<BlockHash>> {
    let hint: u8 = Arbitrary::arbitrary(u)?;
    let len = (hint as usize) % (MAX_TIPS + 1);
    let mut v = Vec::with_capacity(len);
    for _ in 0..len {
        v.push(gen_blockhash(u)?);
    }
    Ok(v)
}

#[derive(Arbitrary)]
struct Inputs {
    #[arbitrary(with = gen_blockhash)]
    best_block: BlockHash,
    depth: u32,
    #[arbitrary(with = gen_blockhash)]
    validation_index: BlockHash,
    #[arbitrary(with = gen_alt_tips)]
    alternative_tips: Vec<BlockHash>,
}

fuzz_target!(|data: &[u8]| {
    if let Ok(inp) = Inputs::arbitrary(&mut Unstructured::new(data)) {
        let best = BestChain {
            best_block: inp.best_block,
            depth: inp.depth,
            validation_index: inp.validation_index,
            alternative_tips: inp.alternative_tips,
        };

        // Encode
        let mut buf = Vec::new();
        let written = best.consensus_encode(&mut buf).expect("encode failed");
        assert_eq!(written, buf.len(), "encode returned wrong length");

        // Decode and compare
        let decoded = BestChain::consensus_decode(&mut Cursor::new(&buf)).expect("decode failed");
        assert_eq!(decoded, best, "roundtrip mismatch");
    }
});
