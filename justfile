# List the available commands
default:
  @just --list

# Checks whether a command is available.
check-command cmd recipe="check-command" link_to_package="":
    @if ! command -v "{{cmd}}" >/dev/null; then \
        echo "Command '{{cmd}}' is not available, but 'just {{recipe}}' requires it." >&2; \
        if [ -n "{{link_to_package}}" ]; then \
            echo "This might help you: {{link_to_package}}" >&2; \
        fi; \
        exit 1; \
    fi

# Compile project with debug options
[group('Build')]
build:
    cargo build

# Compile project with release options
[group('Build')]
build-release:
    cargo build --release

# Clean project build directory
[group('Build')]
clean:
    cargo clean

# Format code and run clippy for all feature combinations in each crate (arg: optional, e.g., '-- -D warnings')
[group('Development')]
lint-features arg="":
    @just fmt
    @just doc-check

    cargo install cargo-hack --locked
    ./contrib/feature_matrix.sh clippy '{{arg}}'

    @just spell-check
    @just test-functional-uv-fmt

# Remove test-generated data
[group('Development')]
clean-data:
    ./contrib/clean_data.sh

# Run all needed checks before contributing code (pre-commit check)
[group('Development')]
pcc:
    @just lint-features '-- -D warnings'
    @just test-features
    @just test-functional

# Run typos
[group('Development')]
spell-check:
    @just check-command typos spell-check "cargo +nightly install typos-cli --locked"
    typos

# Generate the public documentation for all crates
[group('Documentation')]
doc:
    RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --workspace --no-deps --lib --all-features

# Generate and open the public documentation for all crates
[group('Documentation')]
open-doc:
    RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --workspace --no-deps --all-features --open

# Generate the documentation for all crates, including private items, and fail on warnings
[group('Documentation')]
doc-check:
    RUSTDOCFLAGS="--cfg docsrs -D warnings" \
    cargo +nightly doc --workspace --no-deps --all-features --lib --document-private-items

# Must have pandoc installed
# Needs sudo to overwrite existing man pages
# Convert all markdown files on /doc/rpc/ to man pages on /doc/rpc_man/
[group('Documentation')]
gen-manpages path="":
    @just check-command pandoc gen-manpages "https://pandoc.org/installing.html"
    ./contrib/dist/gen_manpages.sh {{path}}


# Usage:
#   just install                   # installs both florestad and floresta-cli
#   just install florestad         # installs only florestad
#   just install floresta-cli      # installs only floresta-cli
#
# Floresta recipe to help installing the binaries without versioning problems.
[group('Installation')]
install bin="all":
    if [ "{{bin}}" = "all" ]; then \
        cargo install --path bin/florestad --locked && \
        cargo install --path bin/floresta-cli --locked; \
    elif [ "{{bin}}" = "florestad" ]; then \
        cargo install --path bin/florestad --locked; \
    elif [ "{{bin}}" = "floresta-cli" ]; then \
        cargo install --path bin/floresta-cli --locked; \
    else \
        printf "Unknown binary: %s\n" "{{bin}}" >&2; \
        exit 1; \
    fi


# Format code and run configured linters
[group('Linting')]
lint:
    @just fmt
    @just doc-check

    # 1) Run with no features
    cargo +nightly clippy --workspace --all-targets --no-default-features \
        --exclude floresta-chain \
        --exclude florestad \
        --exclude floresta-node

    # 2) Run with all features
    cargo +nightly clippy --workspace --all-targets --all-features \
        --exclude floresta-chain \
        --exclude florestad \
        --exclude floresta-node

    # Run both cases in floresta-chain (one with kv, another with flat)
    cargo +nightly clippy -p floresta-chain --all-targets --no-default-features --features kv-chainstore
    cargo +nightly clippy -p floresta-chain --all-targets \
        --features bitcoinconsensus,metrics,test-utils,flat-chainstore

    # Run both cases in florestad (one with kv, another with flat)
    cargo +nightly clippy -p florestad --all-targets --no-default-features --features kv-chainstore
    cargo +nightly clippy -p florestad --all-targets \
        --features compact-filters,zmq-server,json-rpc,metrics,tokio-console,flat-chainstore

    # Run both cases in floresta-node (one with kv, another with flat)
    cargo +nightly clippy -p floresta-node --all-targets --no-default-features --features kv-chainstore
    cargo +nightly clippy -p floresta-node --all-targets \
        --features compact-filters,zmq-server,json-rpc,metrics,flat-chainstore

    @just spell-check

    # Lint the functional tests
    @just test-functional-uv-fmt

# Format code
[group('Linting')]
fmt:
    cargo +nightly fmt --all

# Checks the formatting
[group('Linting')]
format:
    cargo +nightly fmt --all --check

# Run Florestad locally
[group('Run')]
run:
    cargo run --bin florestad

# Runs Florestad locally with release options
[group('Run')]
run-release:
    cargo run --release --bin florestad

# Execute all tests
[group('Testing')]
test name="":
    @just test-doc {{name}}
    @just test-unit {{name}}
    @just test-wkspc

# Execute doc tests
[group('Testing')]
test-doc name="":
    cargo test {{name}} --doc

# Execute unit tests
[group('Testing')]
test-unit name="":
    cargo test --lib {{name}} -- --nocapture

# Execute workspace-related tests
[group('Testing')]
test-wkspc:
    cargo test --workspace -- --nocapture

# Execute tests/prepare.sh.
[group('Testing')]
test-functional-prepare arg="":
    bash tests/prepare.sh {{arg}}

# Execute tests/run.sh
[group('Testing')]
test-functional-run arg="":
    bash tests/run.sh {{arg}}

# Format and lint functional tests
[group('Testing')]
test-functional-uv-fmt:
    @just check-command uv test-functional-uv-fmt "https://docs.astral.sh/uv/getting-started/installation/"
    uv run black --verbose ./tests
    uv run pylint --verbose ./tests

# Run the functional tests
[group('Testing')]
test-functional:
    @just test-functional-prepare
    @just test-functional-run

# Run the benchmarks
[group('Testing')]
bench:
    cargo bench -p floresta-chain --no-default-features --features test-utils,kv-chainstore
    cargo bench -p floresta-chain --no-default-features --features test-utils,flat-chainstore

# Test all feature combinations in each crate (arg: optional, e.g., --quiet or --verbose)
[group('Testing')]
test-features arg="":
    cargo install cargo-hack --locked
    ./contrib/feature_matrix.sh test {{arg}}
