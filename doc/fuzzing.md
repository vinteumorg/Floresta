# Fuzzing
This project uses `cargo-fuzz` (libfuzzer) for fuzzing, you can run a fuzz target with:

```bash
cargo +nightly fuzz run local_address_str
```

You can replace `local_address_str` with the name of any other target you want to run.

Available fuzz targets:

- `addrman`
- `best_chain_decode`
- `best_chain_roundtrip`
- `disk_block_header_decode`
- `disk_block_header_roundtrip`
- `local_address_str`
- `utreexo_proof_des`
- `flat_chainstore_header_insertion`
