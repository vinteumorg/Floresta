## Running Benchmarks

Floresta uses `criterion.rs` for benchmarking. You can run the default set of benchmarks with:

```bash
cargo bench
```

By default, benchmarks that are resource-intensive are excluded to allow for quicker testing. If you'd like to include all benchmarks, use the following command:

```bash
EXPENSIVE_BENCHES=1 cargo bench
```

> **Note**: Running with `EXPENSIVE_BENCHES=1` enables the full benchmark suite, which will take several minutes to complete.