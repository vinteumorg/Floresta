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
test-functional-prepare:
    bash tests/prepare.sh

# Execute tests/run.sh
test-functional-run:
    bash tests/run.sh

# Execute our python integration tests inside /tests.
#
# Make sure you have done the necessary setup explained in our README.md in the root of the folder.
test-functional-uv-run:
    uv run tests/run_tests.py

# Generate documentation for all crates
doc:
    @just test-doc
    cargo +nightly doc --no-deps

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

# Run clippy for all feature combinations in each crate (arg: optional, e.g., '-- -D warnings')
lint-features arg="":
    cargo install cargo-hack --locked
    ./contrib/feature_matrix.sh clippy '{{arg}}'

# Remove test-generated data
clean-data:
    ./contrib/clean_data.sh

# Run all needed checks before contributing code (pre-commit check)
pcc:
    @just fmt
    @just lint-features '-- -D warnings'
    @just test-features
