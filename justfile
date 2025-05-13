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

# format and lint functional tests
test-functional-uv-fmt:
    uv run black --check --verbose ./tests
    uv run pylint --verbose ./tests

# Run all required stuff to functional tests
test-functional:
  @just test-functional-uv-fmt
  @just test-functional-prepare --build
  @just test-functional-run

# Run the benchmarks
bench:
    cargo bench --features test-utils

# Generate documentation for all crates
doc:
    cargo +nightly doc --workspace --no-deps

# Generate and open documentation for all crates
open-doc:
    cargo +nightly doc --workspace --no-deps --open

# Format code and run configured linters
lint:
    @just fmt
    cargo +nightly clippy --all-targets --no-default-features
    cargo +nightly clippy --all-targets --all-features

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
