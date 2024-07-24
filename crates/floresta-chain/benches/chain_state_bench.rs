use std::collections::HashMap;
use std::io::Cursor;

use bitcoin::block::Header as BlockHeader;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::Decodable;
use bitcoin::Block;
use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;
use floresta_chain::pruned_utreexo::nodetime::standard_node_time::StdNodeTime;
use floresta_chain::pruned_utreexo::UpdatableChainstate;
use floresta_chain::AssumeValidArg;
use floresta_chain::ChainState;
use floresta_chain::KvChainStore;
use floresta_chain::Network;
use rustreexo::accumulator::proof::Proof;

// Reads the first 151 blocks (or 150 blocks on top of genesis) from blocks.txt, which are regtest
fn read_blocks_txt() -> Vec<Block> {
    let blocks: Vec<_> = include_str!("../testdata/blocks.txt")
        .lines()
        .take(151)
        .map(|b| deserialize(&hex::decode(b).unwrap()).unwrap())
        .collect();

    assert_eq!(blocks.len(), 151, "Expected 151 blocks in blocks.txt");
    blocks
}

pub fn setup_test_chain<'a>(
    network: Network,
    assume_valid_arg: AssumeValidArg,
) -> ChainState<KvChainStore<'a>> {
    let test_id = rand::random::<u64>();
    let chainstore = KvChainStore::new(format!("./data/{test_id}/")).unwrap();
    ChainState::new(chainstore, network, assume_valid_arg)
}

fn accept_mainnet_headers_benchmark(c: &mut Criterion) {
    // Accepts the first 10235 mainnet headers
    let file = include_bytes!("../testdata/headers.zst");
    let uncompressed: Vec<u8> = zstd::decode_all(Cursor::new(file)).unwrap();
    let mut cursor = Cursor::new(uncompressed);

    // Read all headers into a vector
    let mut headers = Vec::new();
    while let Ok(header) = BlockHeader::consensus_decode(&mut cursor) {
        headers.push(header);
    }

    let chain = setup_test_chain(Network::Bitcoin, AssumeValidArg::Hardcoded);

    c.bench_function("accept_10k_mainnet_headers", |b| {
        b.iter(|| {
            headers
                .iter()
                .for_each(|header| chain.accept_header(*header, &StdNodeTime).unwrap())
        })
    });
}

fn accept_headers_benchmark(c: &mut Criterion) {
    let chain = setup_test_chain(Network::Regtest, AssumeValidArg::Disabled);
    let blocks = read_blocks_txt();

    c.bench_function("accept_150_headers", |b| {
        b.iter(|| {
            blocks
                .iter()
                .for_each(|block| chain.accept_header(block.header, &StdNodeTime).unwrap());
        })
    });
}

fn connect_blocks_benchmark(c: &mut Criterion) {
    let chain = setup_test_chain(Network::Regtest, AssumeValidArg::Disabled);
    let blocks = read_blocks_txt();

    blocks
        .iter()
        .for_each(|block| chain.accept_header(block.header, &StdNodeTime).unwrap());

    c.bench_function("connect_150_blocks", |b| {
        b.iter(|| {
            blocks.iter().for_each(|block| {
                chain
                    .connect_block(
                        block,
                        Proof::default(),
                        HashMap::new(),
                        Vec::new(),
                        &StdNodeTime,
                    )
                    .unwrap();
            })
        })
    });
}

criterion_group!(
    benches,
    accept_mainnet_headers_benchmark,
    accept_headers_benchmark,
    connect_blocks_benchmark
);
criterion_main!(benches);
