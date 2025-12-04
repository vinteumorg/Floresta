# Benchmarking

Floresta uses `criterion.rs` for benchmarking. Assuming you have the [Just](https://github.com/casey/just) command runner installed, you can run the default set of benchmarks with:

```bash
just bench
```

Under the hood this runs:

```bash
cargo bench -p floresta-chain --no-default-features --features test-utils,flat-chainstore
```

By default, benchmarks that are resource-intensive are excluded to allow for quicker testing. If you'd like to include all benchmarks, use the following command:

```bash
# with Just:
EXPENSIVE_BENCHES=1 just bench

# or, without Just:
EXPENSIVE_BENCHES=1 cargo bench -p floresta-chain --no-default-features --features test-utils,flat-chainstore
```

> **Note**: Running with `EXPENSIVE_BENCHES=1` enables the full benchmark suite, which will take several minutes to complete.
