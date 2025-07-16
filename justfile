# List the available commands
default:
  @just --list

# Run Florestad locally
run:
    cargo run --bin florestad

# Runs Florestad locally with release options
run-release:
    cargo run --release --bin florestad

# Compile project with debug options
build:
    cargo build

# Compile project with release options
build-release:
    cargo build --release

# Clean project build directory
clean:
    cargo clean

# Execute all tests
test name="":
    @just test-doc {{name}}
    @just test-unit {{name}}
    @just test-wkspc

# Execute doc tests
test-doc name="":
    cargo test {{name}} --doc

# Execute unit tests
test-unit name="":
    cargo test --lib {{name}} -- --nocapture

# Execute workspace-related tests
test-wkspc:
    cargo test --workspace -- --nocapture

# Execute tests/prepare.sh.
test-functional-prepare arg="":
    bash tests/prepare.sh {{arg}}

# Execute tests/run.sh
test-functional-run arg="":
    bash tests/run.sh {{arg}}

# Format and lint functional tests
test-functional-uv-fmt:
    uv run black --verbose ./tests
    uv run pylint --verbose ./tests

# Run the functional tests
test-functional:
    @just test-functional-prepare
    @just test-functional-run

# Run the benchmarks
bench:
    cargo bench -p floresta-chain --no-default-features --features test-utils,kv-chainstore
    cargo bench -p floresta-chain --no-default-features --features test-utils,flat-chainstore

# Generate the public documentation for all crates
doc:
    RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --workspace --no-deps --all-features

# Generate and open the public documentation for all crates
open-doc:
    RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --workspace --no-deps --all-features --open

# Generate the documentation for all crates, including private items, and fail on warnings
doc-check:
    RUSTDOCFLAGS="--cfg docsrs -D warnings" \
    cargo +nightly doc --workspace --no-deps --all-features --document-private-items

# Format code and run configured linters
lint:
    @just fmt
    @just doc-check

    # 1) Run with no features
    cargo +nightly clippy --workspace --all-targets --no-default-features \
        --exclude floresta-chain \
        --exclude florestad

    # 2) Run with all features
    cargo +nightly clippy --workspace --all-targets --all-features \
        --exclude floresta-chain \
        --exclude florestad

    # Run both cases in floresta-chain (one with kv, another with flat)
    cargo +nightly clippy -p floresta-chain --all-targets --no-default-features --features kv-chainstore
    cargo +nightly clippy -p floresta-chain --all-targets \
        --features bitcoinconsensus,metrics,test-utils,flat-chainstore

    # Run both cases in florestad (one with kv, another with flat)
    cargo +nightly clippy -p florestad --all-targets --no-default-features --features kv-chainstore
    cargo +nightly clippy -p florestad --all-targets \
        --features compact-filters,zmq-server,json-rpc,metrics,flat-chainstore

    # Lint the functional tests
    @just test-functional-uv-fmt

# Format code
fmt:
    cargo +nightly fmt --all

# Checks the formatting
format:
    cargo +nightly fmt --all --check

# Test all feature combinations in each crate (arg: optional, e.g., --quiet or --verbose)
test-features arg="":
    cargo install cargo-hack --locked
    ./contrib/feature_matrix.sh test {{arg}}

# Format code and run clippy for all feature combinations in each crate (arg: optional, e.g., '-- -D warnings')
lint-features arg="":
    @just fmt
    @just doc-check
    @just test-functional-uv-fmt

    cargo install cargo-hack --locked
    ./contrib/feature_matrix.sh clippy '{{arg}}'

# Remove test-generated data
clean-data:
    ./contrib/clean_data.sh

# Run all needed checks before contributing code (pre-commit check)
pcc:
    @just lint-features '-- -D warnings'
    @just test-features
    @just test-functional

# Must have pandoc installed
# Needs sudo to overwrite existing man pages
# Convert all markdown files on /doc/rpc/ to man pages on /doc/rpc_man/
gen-manpages path="":
    ./contrib/dist/gen_manpages.sh {{path}}
