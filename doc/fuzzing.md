# Fuzzing
This project uses `cargo-fuzz` (libfuzzer) for fuzzing, you can run a fuzz target with:
```bash
cargo +nightly fuzz run local_address_str
```

You can replace `local_address_str` with the name of any other target you want to run.

Available fuzz targets:
- `local_address_str`
- `utreexo_block_des`
- `addrman`
- `flat_chainstore_header_insertion`
- `flat_chainstore_memory_access`
- `flat_chainstore_reorg`
