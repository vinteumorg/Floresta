use std::collections::HashMap;
use std::fs::File;
use std::io::Cursor;

use bitcoin::block::Header as BlockHeader;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::Decodable;
use bitcoin::Block;
use bitcoin::OutPoint;
use bitcoin::TxOut;
use criterion::criterion_group;
use criterion::criterion_main;
use criterion::BatchSize;
use criterion::Criterion;
use criterion::SamplingMode;
use floresta_chain::pruned_utreexo::utxo_data::UtxoData;
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

fn setup_test_chain<'a>(
    network: Network,
    assume_valid_arg: AssumeValidArg,
) -> ChainState<KvChainStore<'a>> {
    let test_id = rand::random::<u64>();
    let chainstore = KvChainStore::new(format!("./tmp-db/{test_id}/")).unwrap();
    ChainState::new(chainstore, network, assume_valid_arg)
}

fn decode_block_and_inputs(
    block_file: File,
    stxos_file: File,
) -> (Block, HashMap<OutPoint, UtxoData>) {
    let block_bytes = zstd::decode_all(block_file).unwrap();
    let block: Block = deserialize(&block_bytes).unwrap();

    // Get txos spent in the block
    let stxos_bytes = zstd::decode_all(stxos_file).unwrap();
    let mut stxos: Vec<TxOut> =
        serde_json::from_slice(&stxos_bytes).expect("Failed to deserialize JSON");

    let inputs = block
        .txdata
        .iter()
        .skip(1) // Skip the coinbase transaction
        .flat_map(|tx| &tx.input)
        .map(|txin| {
            (
                txin.previous_output,
                UtxoData {
                    txout: stxos.remove(0),
                    commited_height: 0,
                    commited_time: 0,
                },
            )
        })
        .collect();

    assert!(stxos.is_empty(), "Moved all stxos to the inputs map");

    (block, inputs)
}

fn accept_mainnet_headers_benchmark(c: &mut Criterion) {
    // Accepts the first 10235 mainnet headers
    let file = include_bytes!("../testdata/headers.zst");
    let uncompressed: Vec<u8> = zstd::decode_all(Cursor::new(file)).unwrap();
    let mut buffer = uncompressed.as_slice();

    // Read all headers into a vector
    let mut headers = Vec::new();
    while let Ok(header) = BlockHeader::consensus_decode(&mut buffer) {
        headers.push(header);
    }

    let chain = setup_test_chain(Network::Bitcoin, AssumeValidArg::Hardcoded);

    c.bench_function("accept_10k_mainnet_headers", |b| {
        b.iter(|| {
            headers
                .iter()
                .for_each(|header| chain.accept_header(*header).unwrap())
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
                .for_each(|block| chain.accept_header(block.header).unwrap());
        })
    });
}

fn connect_blocks_benchmark(c: &mut Criterion) {
    let chain = setup_test_chain(Network::Regtest, AssumeValidArg::Disabled);
    let blocks = read_blocks_txt();

    blocks
        .iter()
        .for_each(|block| chain.accept_header(block.header).unwrap());

    c.bench_function("connect_150_blocks", |b| {
        b.iter(|| {
            blocks.iter().for_each(|block| {
                chain
                    .connect_block(block, Proof::default(), HashMap::new(), Vec::new())
                    .unwrap();
            })
        })
    });
}

fn validate_full_block_benchmark(c: &mut Criterion) {
    let block_file = File::open("./testdata/block_866342/raw.zst").unwrap();
    let stxos_file = File::open("./testdata/block_866342/spent_txos.zst").unwrap();
    let (block, inputs) = decode_block_and_inputs(block_file, stxos_file);

    let chain = setup_test_chain(Network::Bitcoin, AssumeValidArg::Disabled);

    c.bench_function("validate_block_866342", |b| {
        b.iter_batched(
            || inputs.clone(),
            |inputs| chain.validate_block_no_acc(&block, 866342, inputs).unwrap(),
            BatchSize::LargeInput,
        )
    });
}

fn validate_many_inputs_block_benchmark(c: &mut Criterion) {
    if std::env::var("EXPENSIVE_BENCHES").is_err() {
        println!(
            "validate_many_inputs_block_benchmark ... \x1b[33mskipped\x1b[0m\n\
            > Set EXPENSIVE_BENCHES=1 to include this benchmark\n"
        );

        return;
    }

    let block_file = File::open("./testdata/block_367891/raw.zst").unwrap();
    let stxos_file = File::open("./testdata/block_367891/spent_txos.zst").unwrap();
    let (block, inputs) = decode_block_and_inputs(block_file, stxos_file);

    let chain = setup_test_chain(Network::Bitcoin, AssumeValidArg::Disabled);

    // Create a group with the lowest possible sample size, as validating this block is very slow
    let mut group = c.benchmark_group("validate_block_367891");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(10);

    group.bench_function("validate_block_367891", |b| {
        b.iter_batched(
            || inputs.clone(),
            |inputs| chain.validate_block_no_acc(&block, 367891, inputs).unwrap(),
            BatchSize::LargeInput,
        )
    });
    group.finish();
}

criterion_group!(
    benches,
    accept_mainnet_headers_benchmark,
    accept_headers_benchmark,
    connect_blocks_benchmark,
    validate_full_block_benchmark,
    validate_many_inputs_block_benchmark
);
criterion_main!(benches);
