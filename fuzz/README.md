# Floresta Differential Fuzzer

Differential fuzzing harness for **Bitcoin Core**, **Floresta**. 

## Quick Start

```bash
# Make scripts executable
chmod +x run_fuzzer.sh
chmod +x fuzz/scripts/*.sh

# List targets
./run_fuzzer.sh --list

# Run fuzzer (60 seconds)
./run_fuzzer.sh block_parsing_differential

# Run with custom duration
./run_fuzzer.sh block_parsing_differential 300

# Keep logs for debugging
./run_fuzzer.sh block_parsing_differential 60 --save-logs
```

## What It Does

1. **Generates corpus** - Creates binary seed files for fuzzing
2. **Builds binaries** - Compiles Bitcoin Core, Floresta, Utreexo (cached)
3. **Starts nodes** - Launches 3 regtest nodes on random ports
4. **Mines blocks** - Generates 10,000 test blocks on Utreexo node
5. **Sync** - Syncs Bitcoin Core and Floresta via Utreexo
6. **Fuzzes** - Sends mutated inputs to all 2 implementations
7. **Compares** - Detects when implementations differ

## Prerequisites

```bash
# macOS
brew install git gcc make cmake go cargo rust

# Ubuntu/Debian
sudo apt-get install git build-essential cmake golang-go cargo rustc

# Nightly Rust
rustup install nightly
rustup component add --toolchain nightly rust-src
```

## Project Layout

```
fuzz/
├── Cargo.toml
├── fuzz_targets/
│   ├── block_parsing_differential.rs
├── corpus/                    # Auto-generated seed files
├── scripts/                   # Corpus generators
│   ├── generate_corpus_block_parsing_differential.sh
│   ├── run_fuzzer.sh          # Main execution script
└── helpers/
    ├── rpc_helper.rs          # RPC client
    ├── logging.rs             # Bug logging
    └── tx_types.rs
```

## Output

**Successful run:**
```
No bugs found
Corpus: 22 seeds
Logs: /tmp/floresta-fuzz.*/logs
```

**Bug found:**
```
Artifacts found: 1
File: /tmp/floresta-fuzz.*/artifacts/crash-xxx
```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Generator not found | `chmod +x fuzz/scripts/*.sh` |
| Nodes won't start | Check logs: `cat /tmp/floresta-fuzz.*/logs/*.log` |
| Port conflicts | Ports auto-randomize; stop manually: `pkill -f bitcoind; pkill -f florestad; pkill -f utreexod` |