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

# Execute our python integration tests inside /tests using nix for all setup needed.
test-int-nix:
    nix develop .#pythonTests

# Execute tests/prepare.sh.
test-int-setup:
    bash tests/prepare.sh

# Execute tests/run.sh
test-int-run:
    bash tests/run.sh

# Execute our python integration tests inside /tests.
#
# Make sure you have done the necessary setup explained in our README.md in the root of the folder.
test-int:
    poetry run poe tests

# Generate documentation for all crates
doc:
    @just test-doc
    cargo +nightly doc --no-deps

# Format code and run configured linters
lint:
    cargo +nightly fmt --all && cargo +nightly clippy --all-targets

# Format code
fmt:
    cargo +nightly fmt --all

# Checks the formatting
format:
    cargo +nightly fmt --all --check

# Test all feature combinations for each crate using cargo-hack (arg: optional, e.g., --quiet or --verbose)
test-features arg="":
    cargo install cargo-hack --locked
    ./contrib/test_features.sh {{arg}}

# Remove test-generated data
clean-data:
    ./contrib/clean_data.sh

# Run all needed checks before contributing code (pre-commit check)
pcc: lint test-features
