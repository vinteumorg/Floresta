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

# Convert all markdown files on /doc/rpc/ to man pages on /doc/rpc_man/
# Must have pandoc installed
convert-all:
    #!/usr/bin/env bash
    set -euo pipefail

    # Create man page directory if it doesn't exist
    mkdir -p doc/rpc_man

    # Convert each .md file to man page
    for md_file in doc/rpc/*.md; do
        if [[ -f "$md_file" ]]; then
            echo "Converting $md_file..."
            just convert-single "$md_file"
        fi
    done

    echo "All markdown files converted to man pages in ./doc/rpc_man/"

# Convert a single markdown file on doc/rpc/ to man page on doc/rpc_man/
# Must have pandoc installed
convert-single FILE:
    #!/usr/bin/env bash
    set -euo pipefail

    if [[ ! -f "{{FILE}}" ]]; then
        echo "Error: File {{FILE}} not found"
        exit 1
    fi

    # Extract filename without extension
    basename=$(basename "{{FILE}}" .md)

    # Create man page directory if it doesn't exist
    mkdir -p doc/rpc_man

    # Convert markdown to man page using pandoc
    # Default to section 1 (user commands) unless specified in filename
    section=1
    if [[ "$basename" =~ \.[0-9]$ ]]; then
        section="${basename##*.}"
        basename="${basename%.*}"
    fi

    # Convert to man page format
    pandoc "{{FILE}}" \
        -s \
        -t man \
        --metadata title="$basename" \
        --metadata section="$section" \
        --metadata date="$(date +'%B %Y')" \
        -o "doc/rpc_man/${basename}.${section}"

    # Compress the man page
    gzip -f "doc/rpc_man/${basename}.${section}"

    echo "Created: doc/rpc_man/${basename}.${section}.gz"
