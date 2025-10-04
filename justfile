# Prints welcome message with useful recipes
_default:
    @printf "%b\n" "Welcome to the Floresta Project — lets get you up and running!\n\nYou can run the node with:\n\njust run-release\n\nAnd see the docs with:\n\njust open-doc\n\nLearn more about recipes in doc/justfile.md or running just --list\n"
    @just -l --groups

# Checks whether a command is available.
[group('Utilitty')]
check-command cmd recipe="check-command" link_to_package="":
    @if ! command -v "{{ cmd }}" >/dev/null; then \
        echo "Command '{{ cmd }}' is not available, but 'just {{ recipe }}' requires it." >&2; \
        if [ -n "{{ link_to_package }}" ]; then \
            echo "This might help you: {{ link_to_package }}" >&2; \
        fi; \
        exit 1; \
    fi

# Compile project with debug options
[group('Running')]
build:
    cargo build

# Compile project with release options
[group('Aliases')]
[group('Running')]
build-release:
    cargo build --release

# Clean project build directory
[group('Development')]
clean:
    cargo clean

# Format code and run clippy for all feature combinations in each crate (arg: optional, e.g., '-- -D warnings')
[group('Development')]
[group('Linting')]
lint-features arg="":
    @just fmt
    @just doc-check

    cargo install cargo-hack --locked
    ./contrib/feature_matrix.sh clippy '{{ arg }}'

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
[group('Aliases')]
[group('Development')]
doc:
    RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --workspace --no-deps --lib --all-features

# Generate and open the public documentation for all crates
[group('Aliases')]
[group('Development')]
open-doc:
    RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --workspace --no-deps --all-features --open

# Generate the documentation for all crates, including private items, and fail on warnings
[group('Development')]
doc-check:
    RUSTDOCFLAGS="--cfg docsrs -D warnings" \
    cargo +nightly doc --workspace --no-deps --all-features --lib --document-private-items

# Must have pandoc installed
# Needs sudo to overwrite existing man pages

# Convert all markdown files on /doc/rpc/ to man pages on /doc/rpc_man/
[group('Aliases')]
[group('Development')]
gen-manpages path="":
    @just check-command pandoc gen-manpages "https://pandoc.org/installing.html"
    ./contrib/dist/gen_manpages.sh {{ path }}

# Usage:
#   just install                   # installs both florestad and floresta-cli
#   just install florestad         # installs only florestad
#   just install floresta-cli      # installs only floresta-cli
#

# Floresta recipe to help installing the binaries without versioning problems.
[group('Aliases')]
[group('Running')]
install bin="all":
    if [ "{{ bin }}" = "all" ]; then \
        cargo install --path bin/florestad --locked && \
        cargo install --path bin/floresta-cli --locked; \
    elif [ "{{ bin }}" = "florestad" ]; then \
        cargo install --path bin/florestad --locked; \
    elif [ "{{ bin }}" = "floresta-cli" ]; then \
        cargo install --path bin/floresta-cli --locked; \
    else \
        printf "Unknown binary: %s\n" "{{ bin }}" >&2; \
        exit 1; \
    fi

# Format code and run configured linters
[group('Development')]
[group('Linting')]
lint:
    @just fmt
    @just doc-check

    # 1) Run with no features
    cargo +nightly clippy --workspace --all-targets --no-default-features

    # 2) Run with all features
    cargo +nightly clippy --workspace --all-targets --all-features

    @just spell-check

    # Lint the functional tests
    @just test-functional-uv-fmt

# Format code
[group('Development')]
[group('Linting')]
fmt:
    cargo +nightly fmt --all

# Run Florestad locally
[group('Running')]
run:
    cargo run --bin florestad

# Runs Florestad locally with release options
[group('Aliases')]
[group('Running')]
run-release:
    cargo run --release --bin florestad

# Execute all tests, you can pass name to specify a package.
[group('Development')]
[group('Testing')]
test name="":
    @just _test-doc {{ name }}
    @just _test-unit {{ name }}
    @just _test-wkspc

# Execute doc tests
[group('Testing')]
[group('Utility')]
_test-doc name="":
    cargo test {{ name }} --doc

# Execute unit tests
[group('Testing')]
[group('Utility')]
_test-unit name="":
    cargo test --lib {{ name }} -- --nocapture

# Execute workspace-related tests
[group('Testing')]
[group('Utility')]
_test-wkspc:
    cargo test --workspace -- --nocapture

# Execute tests/prepare.sh.
[group('Testing')]
test-functional-prepare arg="":
    bash tests/prepare.sh {{ arg }}

# Execute tests/run.sh
[group('Testing')]
test-functional-run arg="":
    bash tests/run.sh {{ arg }}

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
    cargo bench -p floresta-chain --no-default-features --features test-utils,flat-chainstore

# Test all feature combinations in each crate (arg: optional, e.g., --quiet or --verbose)
[group('Testing')]
test-features arg="":
    cargo install cargo-hack --locked
    ./contrib/feature_matrix.sh test {{ arg }}
