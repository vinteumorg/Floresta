#!/usr/bin/env bash

# Differential fuzzer execution script

set -e

# Configuration
###############
REPO_ROOT=$(git rev-parse --show-toplevel)
GIT_DESCRIBE=$(git describe --tags --always 2>/dev/null || echo "unknown")
FLORESTA_TEMP_DIR="/tmp/floresta-fuzz.${GIT_DESCRIBE}"
BINARIES_DIR="$FLORESTA_TEMP_DIR/binaries"
LOGS_DIR="$FLORESTA_TEMP_DIR/logs"
ARTIFACTS_DIR="$FLORESTA_TEMP_DIR/artifacts"

# Bitcoin version (default: 29.0)
BITCOIN_REVISION="${BITCOIN_REVISION:-29.0}"

# Node ports
BITCOIN_RPC_PORT=""
BITCOIN_P2P_PORT=""
FLORESTA_RPC_PORT=""
FLORESTA_ELECTRUM_PORT=""
UTREEXO_RPC_PORT=""

# Arguments
TARGET="${1:-address_differential}"
DURATION="${2:-60}"
SAVE_LOGS="${3:---no-cleanup}"

# Create logs directory
mkdir -p "$LOGS_DIR"

# Create log file with timestamp
RUN_LOG="$LOGS_DIR/run_fuzzer_$(date +%Y%m%d_%H%M%S).log"

# Redirect everything to BOTH terminal and log file
exec > >(tee -a "$RUN_LOG") 2>&1

echo "Script output logging to: $RUN_LOG"
echo ""


# CORPUS GENERATION
# ============================================================================
generate_corpus() {
    local target=$1
    local corpus_dir="./corpus/$target"
    local generator="./scripts/generate_corpus_${target}.sh"

    echo ""
    echo "=========================================="
    echo "Corpus Generation"
    echo "=========================================="
    
    # Check generator exists
    if [ ! -f "$generator" ]; then
        echo "ERROR: Corpus generator not found!"
        echo "  Expected: $generator"
        exit 1
    fi

    # Generate corpus
    echo "Generating corpus for: $target"
    mkdir -p "$corpus_dir"
    bash "$generator" "$corpus_dir"

    # Verify corpus created
    if [ ! -d "$corpus_dir" ] || [ -z "$(find "$corpus_dir" -type f 2>/dev/null)" ]; then
        echo "ERROR: Corpus generation failed!"
        exit 1
    fi

    SEED_COUNT=$(find "$corpus_dir" -type f | wc -l)
    echo "Corpus ready: $SEED_COUNT seeds"
    echo ""
}


# LOG CLEANUP
# ============================================================================
cleanup_logs() {
    local save_flag=$1
    
    # Cleanup if --no-cleanup is NOT specified
    if [[ "$save_flag" != "--save-logs" ]]; then
        echo ""
        echo "Cleaning up logs (fuzzing succeeded)..."

        # Remove session-specific logs and node logs
        find "$LOGS_DIR" -name "${TARGET}_*.log" -type f -delete 2>/dev/null || true
        find "$LOGS_DIR" -name "bitcoind.log" -type f -delete 2>/dev/null || true
        find "$LOGS_DIR" -name "florestad.log" -type f -delete 2>/dev/null || true
        find "$LOGS_DIR" -name "utreexod.log" -type f -delete 2>/dev/null || true
        
        echo "Logs cleaned"
        echo "Artifacts preserved at: $ARTIFACTS_DIR"
        echo "Main log: $RUN_LOG"
    else
        echo ""
        echo "Log cleanup disabled (--save-logs flag)"
        echo "  All logs preserved at: $LOGS_DIR"
    fi
}

# Find fuzz targets directory
#############################
find_fuzz_targets_dir() {
    local current_dir="$(pwd)"
    while [[ "$current_dir" != "/" ]]; do
        if [[ -d "$current_dir/fuzz/fuzz_targets" ]]; then
            echo "$current_dir/fuzz/fuzz_targets"
            return 0
        fi
        current_dir="$(dirname "$current_dir")"
    done

    local repo_root
    repo_root=$(git rev-parse --show-toplevel 2>/dev/null || echo "")
    if [[ -n "$repo_root" ]] && [[ -d "$repo_root/fuzz/fuzz_targets" ]]; then
        echo "$repo_root/fuzz/fuzz_targets"
        return 0
    fi

    return 1
}

# Check Dependencies
####################
check_installed() {
    if ! command -v "$1" &>/dev/null; then
        echo "You must have $1 installed to run fuzzing!"
        exit 1
    fi
    echo " OK: $1"
}

check_dependencies() {
    echo ""
    echo "Checking dependencies..."
    check_installed git
    check_installed gcc
    check_installed make
    check_installed cmake
    check_installed go
    check_installed cargo
}

# Build Binaries
################
build_core() {
    echo ""
    echo "Building Bitcoin Core v$BITCOIN_REVISION..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS: Export Homebrew library paths for CMake
        export LDFLAGS="-L/opt/homebrew/lib"
        export CPPFLAGS="-I/opt/homebrew/include"
        export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig"
        echo "Configured macOS build environment"
    fi

    mkdir -p "$BINARIES_DIR/build"
    cd "$BINARIES_DIR/build" || exit 1

    # Clone into Bitcoin
    if [ ! -d "bitcoin" ]; then
        git clone https://github.com/bitcoin/bitcoin
    fi

    cd bitcoin || exit 1

    # Checkout the given version
    if git --no-pager tag -l | grep -q "^v$BITCOIN_REVISION$"; then
        git checkout "v$BITCOIN_REVISION"
    else
        echo "Bitcoin v$BITCOIN_REVISION not found. Available:"
        git tag -l | grep "^v29\|^v28" | tail -10
        exit 1
    fi

    # Build based on version
    major_version="${BITCOIN_REVISION%%.*}"
    if [ "$major_version" -ge 29 ]; then
        # CMake build (Bitcoin 29+)
        cmake -S . -B build \
            -DBUILD_CLI=OFF \
            -DBUILD_TESTS=OFF \
            -DENABLE_WALLET=OFF \
            -DCMAKE_BUILD_TYPE=MinSizeRel \
            -DENABLE_EXTERNAL_SIGNER=OFF \
            -DINSTALL_MAN=OFF
        cmake_nprocs="${BUILD_BITCOIND_NPROCS:-4}"
        cmake --build build --target bitcoind -j"${cmake_nprocs}"
        mv "$BINARIES_DIR/build/bitcoin/build/bin/bitcoind" "$BINARIES_DIR/bitcoind"
    else
        # Autotools build (Bitcoin <29)
        ./autogen.sh
        ./configure \
            --without-gui \
            --disable-tests \
            --disable-bench \
            --disable-wallet
        make_nprocs="${BUILD_BITCOIND_NPROCS:-4}"
        make -j"${make_nprocs}"
        mv "$BINARIES_DIR/build/bitcoin/src/bitcoind" "$BINARIES_DIR/bitcoind"
    fi

    rm -rf "$BINARIES_DIR/build"
    echo "!!! Bitcoin Core built !!!"
}

build_utreexod() {
    echo ""
    echo "Building Utreexo bridge node..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        export LDFLAGS="-L/opt/homebrew/lib"
        export CPPFLAGS="-I/opt/homebrew/include"
        export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig"
        echo "Configured macOS build environment"
    fi

    mkdir -p "$BINARIES_DIR/build"
    cd "$BINARIES_DIR/build" || exit 1

    if [ ! -d "utreexod" ]; then
        git clone https://github.com/utreexo/utreexod
    fi

    cd utreexod || exit 1
    go build -o "$BINARIES_DIR/." .
    rm -rf "$BINARIES_DIR/build"
    echo "!!! Utreexo bridge node built !!!"
}

build_floresta() {
    echo ""
    echo "Building Floresta..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        export LDFLAGS="-L/opt/homebrew/lib"
        export CPPFLAGS="-I/opt/homebrew/include"
        export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig"
        echo "Configured macOS build environment"
    fi

    cd "$REPO_ROOT"
    cargo build --release --bin florestad 2>&1 | tail -5
    ln -fs "$(pwd)/target/release/florestad" "$BINARIES_DIR/florestad"
    echo "!!! Floresta built !!!"
}

# Ensure Binaries Exist
#######################
ensure_binaries() {
    echo ""
    echo "Checking binaries..."
    mkdir -p "$BINARIES_DIR"

    if [ ! -L "$BINARIES_DIR/florestad" ]; then
        build_floresta
    else
        echo " !!! Floresta binary exists !!!"
    fi

    if [ ! -f "$BINARIES_DIR/bitcoind" ] || [ "$1" == "--rebuild" ]; then
        build_core
    else
        echo " !!! Bitcoin Core binary exists !!!"
    fi

    if [ ! -f "$BINARIES_DIR/utreexod" ] || [ "$1" == "--rebuild" ]; then
        build_utreexod
    else
        echo " !!! Utreexo binary exists !!!"
    fi
}

# Ensure Directories Exist
##########################
ensure_directories() {
    mkdir -p "$LOGS_DIR" "$ARTIFACTS_DIR"
    mkdir -p "$FLORESTA_TEMP_DIR/data/bitcoind"
    mkdir -p "$FLORESTA_TEMP_DIR/data/florestad"
    mkdir -p "$FLORESTA_TEMP_DIR/data/utreexod"
}

# Check and Start Nodes
#######################
are_nodes_running() {
    pgrep -f "bitcoind.*regtest" > /dev/null 2>&1 && \
        pgrep -f "florestad" > /dev/null 2>&1
}

start_nodes() {
    echo ""
    echo "Starting nodes..." >&2

    # CLEAN OLD DATA
    echo " Cleaning old data directories..."
    rm -rf "$FLORESTA_TEMP_DIR/data/bitcoind"
    rm -rf "$FLORESTA_TEMP_DIR/data/florestad"
    rm -rf "$FLORESTA_TEMP_DIR/data/utreexod"

    # Recreate directories
    mkdir -p "$FLORESTA_TEMP_DIR/data/bitcoind"
    mkdir -p "$FLORESTA_TEMP_DIR/data/florestad"
    mkdir -p "$FLORESTA_TEMP_DIR/data/utreexod"

    # Stop any existing instances
    pkill -f "bitcoind.*regtest" || true
    pkill -f "florestad" || true
    pkill -f "utreexod" || true
    sleep 2

    # Generate random ports
    BITCOIN_RPC_PORT=$(shuf -i 20443-21443 -n 1)
    BITCOIN_P2P_PORT=$(shuf -i 18445-19445 -n 1)
    FLORESTA_RPC_PORT=$(shuf -i 18443-19443 -n 1)
    FLORESTA_ELECTRUM_PORT=$(shuf -i 20001-21001 -n 1)
    UTREEXO_RPC_PORT=$(shuf -i 18543-19543 -n 1)
    UTREEXO_P2P_PORT=$(shuf -i 18642-19642 -n 1)

    # Start Floresta
    echo " Starting Floresta (RPC: $FLORESTA_RPC_PORT)..." >&2
    "$BINARIES_DIR/florestad" \
        --network=regtest \
        --data-dir="$FLORESTA_TEMP_DIR/data/florestad" \
        --rpc-address="127.0.0.1:$FLORESTA_RPC_PORT" \
        --electrum-address="127.0.0.1:$FLORESTA_ELECTRUM_PORT" \
        > "$LOGS_DIR/florestad.log" 2>&1 &
    sleep 5

    # Start Utreexo
    echo " Starting Utreexo (RPC: $UTREEXO_RPC_PORT, P2P: $UTREEXO_P2P_PORT)..." >&2
    "$BINARIES_DIR/utreexod" \
        --regtest \
        --datadir="$FLORESTA_TEMP_DIR/data/utreexod" \
        --rpclisten="127.0.0.1:$UTREEXO_RPC_PORT" \
        --listen="127.0.0.1:$UTREEXO_P2P_PORT" \
        --rpcuser=fuzzer --rpcpass=fuzzing123 \
        --notls \
        --miningaddr="bcrt1q4gfcga7jfjmm02zpvrh4ttc5k7lmnq2re52z2y" \
        --prune=0 \
        --utreexoproofindex \
        > "$LOGS_DIR/utreexod.log" 2>&1 &
    sleep 5

    # Start Bitcoin Core
    echo " Starting Bitcoin Core (RPC: $BITCOIN_RPC_PORT)..." >&2
    "$BINARIES_DIR/bitcoind" \
        -regtest -server -daemon \
        -datadir="$FLORESTA_TEMP_DIR/data/bitcoind" \
        -rpcuser=fuzzer -rpcpassword=fuzzing123 \
        -rpcallowip=127.0.0.1 \
        -rpcbind=127.0.0.1:$BITCOIN_RPC_PORT \
        -bind=127.0.0.1:$BITCOIN_P2P_PORT \
        -fallbackfee=0.00001 \
        > "$LOGS_DIR/bitcoind.log" 2>&1
    sleep 5

    # Wait for nodes to be responsive
    local max_attempts=30
    local attempt=0
    echo " Waiting for nodes to be responsive..." >&2
    while [ $attempt -lt $max_attempts ]; do
        CORE_HEIGHT=$(bitcoin-cli -regtest -rpcuser=fuzzer -rpcpassword=fuzzing123 \
            -rpcport=$BITCOIN_RPC_PORT getblockcount 2>/dev/null || echo "0")
        CORE_READY=$([[ "$CORE_HEIGHT" =~ ^[0-9]+$ ]] && echo "yes" || echo "no")

        UTREEXO_HEIGHT=$(bitcoin-cli -regtest -rpcuser=fuzzer -rpcpassword=fuzzing123 \
            -rpcport=$UTREEXO_RPC_PORT getblockcount 2>/dev/null || echo "0")
        UTREEXO_READY=$([[ "$UTREEXO_HEIGHT" =~ ^[0-9]+$ ]] && echo "yes" || echo "no")

        FLORESTA_HEIGHT=$(curl -s --connect-timeout 2 \
            -X POST \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}' \
            http://127.0.0.1:$FLORESTA_RPC_PORT 2>/dev/null | jq -r '.result // 0')
        FLORESTA_READY=$([[ "$FLORESTA_HEIGHT" =~ ^[0-9]+$ ]] && echo "yes" || echo "no")

        if [ "$CORE_READY" = "yes" ] && \
           [ "$UTREEXO_READY" = "yes" ] && \
           [ "$FLORESTA_READY" = "yes" ]; then
            echo "OK: All nodes responsive" >&2
            echo " Bitcoin Core: $BITCOIN_RPC_PORT" >&2
            echo " Utreexo: $UTREEXO_RPC_PORT" >&2
            echo " Floresta: $FLORESTA_RPC_PORT" >&2
            break
        fi

        attempt=$((attempt + 1))
        sleep 1
    done

    if [ $attempt -ge $max_attempts ]; then
        echo "!!! Nodes failed to start properly !!!" >&2
        tail -20 "$LOGS_DIR/utreexod.log" >&2
        tail -20 "$LOGS_DIR/florestad.log" >&2
        exit 1
    fi

    # Mine blocks on Utreexo Bridge
    echo ""
    echo "Setting up blockchain state..."
    echo "Mining 10000 blocks on Utreexo Bridge..." >&2
    MINE_RESPONSE=$(curl -s --user "fuzzer:fuzzing123" \
        --data-binary '{"jsonrpc": "1.0","id": "generate","method": "generate","params": [10000]}' \
        -H "Content-Type: application/json" \
        http://127.0.0.1:$UTREEXO_RPC_PORT)

    ERROR=$(echo "$MINE_RESPONSE" | jq -r '.error' 2>/dev/null)
    if [ "$ERROR" != "null" ] && [ -n "$ERROR" ]; then
        echo " ERR: Mining failed!" >&2
        echo " Error: $ERROR" >&2
        exit 1
    fi

    BLOCKS=$(echo "$MINE_RESPONSE" | jq -r '.result | length' 2>/dev/null || echo "0")
    echo " OK: Mined $BLOCKS blocks on Utreexo" >&2

    # Verify block height
    UTREEXO_HEIGHT=$(curl -s --user "fuzzer:fuzzing123" \
        --data-binary '{"jsonrpc": "1.0","id": "getblockcount","method": "getblockcount","params": []}' \
        -H "Content-Type: application/json" \
        http://127.0.0.1:$UTREEXO_RPC_PORT 2>/dev/null | jq -r '.result // 0')

    echo " OK: Utreexo Bridge: $UTREEXO_HEIGHT blocks" >&2

    # Connect nodes
    echo "Connecting Bitcoin Core to Utreexo bridge..."
    bitcoin-cli -regtest -rpcuser=fuzzer -rpcpassword=fuzzing123 \
        -rpcport=$BITCOIN_RPC_PORT addnode "127.0.0.1:$UTREEXO_P2P_PORT" add > /dev/null 2>&1 || true

    echo "Connecting Floresta to Utreexo bridge..."
    curl -s -X POST -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"addnode\",\"params\":[\"127.0.0.1:$UTREEXO_P2P_PORT\",\"onetry\",false]}" \
        http://127.0.0.1:$FLORESTA_RPC_PORT > /dev/null 2>&1 || true

    sleep 5

    echo "OK: Setup complete! Nodes are ready for fuzzing."
}

# List Fuzz Targets
###################
if [[ "$TARGET" == "--list" ]] || [[ "$TARGET" == "-l" ]]; then
    echo ""
    echo "Available Fuzz Targets:"
    echo "======================"
    FUZZ_TARGETS_DIR=$(find_fuzz_targets_dir)
    if [ -z "$FUZZ_TARGETS_DIR" ]; then
        echo "Could not find fuzz_targets directory"
        exit 1
    fi
    for file in "$FUZZ_TARGETS_DIR"/*.rs; do
        if [ -f "$file" ]; then
            target=$(basename "$file" .rs)
            printf " %s\n" "$target"
        fi
    done
    echo ""
    exit 0
fi

# Main Workflow
###############
echo ""
echo "========================================="
echo "Floresta Differential Fuzzer"
echo "========================================="

# Step 0: Generate corpus (NEW!)
generate_corpus "$TARGET"

# Step 1: Check dependencies
check_dependencies

# Step 2: Build binaries
ensure_binaries

# Step 3: Create directories
ensure_directories

# Step 4: Start nodes
start_nodes

# Step 5: Run fuzzer
echo ""
echo "========================================="
echo "Fuzzing Configuration"
echo "========================================="
echo "Target: $TARGET"
echo "Duration: ${DURATION}s ($((DURATION / 60))m)"
echo "Bitcoin: http://127.0.0.1:$BITCOIN_RPC_PORT"
echo "Floresta: http://127.0.0.1:$FLORESTA_RPC_PORT"
echo "Utreexo: http://127.0.0.1:$UTREEXO_RPC_PORT"
echo "Logs: $LOGS_DIR"
echo "========================================="
echo ""

CONFIG_FILE="$LOGS_DIR/.fuzz_config"
cat > "$CONFIG_FILE" << EOF
export BITCOIN_RPC_PORT=$BITCOIN_RPC_PORT
export FLORESTA_RPC_PORT=$FLORESTA_RPC_PORT
export UTREEXO_RPC_PORT=$UTREEXO_RPC_PORT
export FLORESTA_FUZZ_LOGS_DIR=$LOGS_DIR
export FLORESTA_FUZZ_ARTIFACTS_DIR=$ARTIFACTS_DIR
EOF

echo ""
echo "OK: Port config written to: $CONFIG_FILE"
echo ""

cd "$REPO_ROOT/fuzz"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
SESSION_LOG="$LOGS_DIR/${TARGET}_${TIMESTAMP}.log"

echo "========================================"
echo "Session: $(date)"
echo "========================================"
echo "Target: $TARGET"
echo "Duration: ${DURATION}s"
echo "Ports: BTC=$BITCOIN_RPC_PORT FLORESTA=$FLORESTA_RPC_PORT UTREEXO=$UTREEXO_RPC_PORT"
echo "Config: $CONFIG_FILE"
echo "========================================"
echo ""

source "$CONFIG_FILE"

# Get corpus directory
CORPUS_DIR="./corpus/$TARGET"
if [ ! -d "$CORPUS_DIR" ]; then
    echo "ERROR: Corpus not found at: $CORPUS_DIR"
    exit 1
fi

cargo +nightly fuzz run "$TARGET" -- \
    -seed_corpus="$CORPUS_DIR" \
    -max_len=100 \
    -timeout=5 \
    -max_total_time="$DURATION" \
    -print_final_stats=1 \
    -verbosity=1 \
    -artifact_prefix="$ARTIFACTS_DIR/" \
    2>&1 | tee -a "$SESSION_LOG"

EXIT_CODE=$?

# Summary
echo ""
echo "========================================="
echo "Fuzzing Complete"
echo "========================================="

ARTIFACT_COUNT=$(find "$ARTIFACTS_DIR" -type f 2>/dev/null | wc -l)
if [ $ARTIFACT_COUNT -gt 0 ]; then
    echo "Artifacts found: $ARTIFACT_COUNT"
    find "$ARTIFACTS_DIR" -type f | head -10
fi

# Cleanup logs (NEW!)
cleanup_logs "$SAVE_LOGS"

echo ""
echo "Session: $SESSION_LOG"
echo ""

exit $EXIT_CODE
