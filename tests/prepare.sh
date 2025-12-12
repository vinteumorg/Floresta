#!/usr/bin/env bash

set -e

# Parse CLI flags:
# --build    : force rebuilding utreexod/bitcoind even if present
# --release  : build florestad in release mode (default: debug)
FORCE_BUILD=0
BUILD_RELEASE=0
for ARG in "$@"; do
    case "$ARG" in
        --build) FORCE_BUILD=1 ;;
        --release) BUILD_RELEASE=1 ;;
        *) ;;
    esac
done

BITCOIN_REVISION="${BITCOIN_REVISION:-30.0}"
# We Need for the current dir to be the root dir of the project.
FLORESTA_PROJ_DIR=$(git rev-parse --show-toplevel)
TEMP_DIR="/tmp/floresta-func-tests"
BINARIES_DIR="$TEMP_DIR/binaries"
# Dont use mktemp so we can have deterministic results for each version of floresta.
mkdir -p "$BINARIES_DIR"

create_disposable_dir() {
    DISPOSABLE_DIR=$(mktemp -d)
    trap 'rm -rf -- "$DISPOSABLE_DIR"' RETURN
    echo "$DISPOSABLE_DIR"
    # Change to the disposable directory
    pushd "$DISPOSABLE_DIR" >/dev/null
}

check_installed() {
    if ! command -v "$1" &>/dev/null; then
        echo "You must have $1 installed to run those tests!"
        exit 1
    fi
}

# If the user provided a bitcoind binary via BITCOIND_EXE, use it.
try_use_provided_bitcoind() {
    if [ -n "${BITCOIND_EXE:-}" ]; then
        if [ ! -f "$BITCOIND_EXE" ] || [ ! -x "$BITCOIND_EXE" ]; then
            echo "BITCOIND_EXE is set but does not point to an executable: $BITCOIND_EXE" >&2
            # Fail hard because user explicitly requested a custom binary.
            exit 1
        fi
        cp "$BITCOIND_EXE" "$BINARIES_DIR/bitcoind"
        chmod +x "$BINARIES_DIR/bitcoind"
        echo "Using user-provided bitcoind: $BINARIES_DIR/bitcoind"
        return 0
    fi
    return 1
}

download_prebuilt_bitcoind() {
    UNAME_S="$(uname -s)"

    if [ "$UNAME_S" = "Linux" ]; then
        PLATFORM="x86_64-linux-gnu"

        HASH=$(case "$BITCOIN_REVISION" in
            "30.0") echo "00964ae375084113b1162f2f493b9372421608af23539766e315a3cb0ee54248" ;;
            "29.0") echo "a681e4f6ce524c338a105f214613605bac6c33d58c31dc5135bbc02bc458bb6c" ;;
            "28.3") echo "732b8d5d56ffd341d4b7c8caeddcaa60c712e36b7e7665dc485bcb37f0f81d98" ;;
            "27.2") echo "6ebc56ca1397615d5a6df2b5cf6727b768e3dcac320c2d5c2f321dcaabc7efa2" ;;
            *) echo "" ;;
        esac)
    elif [ "$UNAME_S" = "Darwin" ]; then
        PLATFORM="x86_64-apple-darwin"

        HASH=$(case "$BITCOIN_REVISION" in
            "30.0") echo "4eadf7b06dca695b940ad30f46247aacbd439544a1be25b0ef3baab73777b3d2" ;;
            "29.0") echo "5bb824fc86a15318d6a83a1b821ff4cd4b3d3d0e1ec3d162b805ccf7cae6fca8" ;;
            "28.3") echo "9a98cca968edf2cf4de07e5fdf83716e93b870699f5d36cb8cb5af1cc1b63fdc" ;;
            "27.2") echo "acc223af46c178064c132b235392476f66d486453ddbd6bca6f1f8411547da78" ;;
            *) echo "" ;;
        esac)
    else
        echo "Unsupported platform for prebuilt bitcoind: $UNAME_S"
        return 1
    fi

    if [ -z "$HASH" ]; then
        echo "No prebuilt hash for bitcoin version $BITCOIN_REVISION on platform $PLATFORM"
        return 1
    fi

    FILE_NAME="bitcoin-${BITCOIN_REVISION}-${PLATFORM}.tar.gz"
    DL_URL="https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_REVISION}/${FILE_NAME}"

    # Change to a disposable directory for download and extraction
    DISPOSABLE_DIR=$(create_disposable_dir)

    echo "Downloading $DL_URL"
    if ! curl -L -o "$FILE_NAME" "$DL_URL"; then
        echo "Failed to download $DL_URL"
        return 1
    fi

    echo "${HASH}  ${FILE_NAME}" | shasum -a 256 -c - >/dev/null 2>&1 || {
        echo "SHA256 mismatch for $FILE_NAME"
        return 1
    }

    if ! tar xzf "$FILE_NAME"; then
        echo "Failed to extract $FILE_NAME"
        return 1
    fi

    cp "bitcoin-${BITCOIN_REVISION}/bin/bitcoind" "$BINARIES_DIR/bitcoind"
    chmod +x "$BINARIES_DIR/bitcoind"

    echo "bitcoind downloaded to $BINARIES_DIR/bitcoind"
    return 0
}

ensure_bitcoind() {
    mkdir -p "$BINARIES_DIR"

    # 1) user-provided binary
    if try_use_provided_bitcoind; then
        return 0
    fi

    # 2) try download prebuilt tarball for supported versions/platforms
    if download_prebuilt_bitcoind; then
        return 0
    fi

    echo "Failed to obtain bitcoind (tried BITCOIND_EXE and prebuilt tarball)"
    return 1
}

build_utreexod() {
    check_installed go

    # Change to a disposable directory for download and build
    DISPOSABLE_DIR=$(create_disposable_dir)

    echo "Downloading and Building utreexod..."
    git clone https://github.com/utreexo/utreexod "$DISPOSABLE_DIR/utreexod"

    cd "$DISPOSABLE_DIR/utreexod"

    go build -o "$BINARIES_DIR/." .
}

build_floresta() {
    # We dont check if floresta already exist because a floresta binary could be already be installed on PATH
    # causing collisions with the tests.
    echo "Building florestad..."

    cd "$FLORESTA_PROJ_DIR"

    if [ "$BUILD_RELEASE" -eq 1 ]; then
        echo "Building florestad (release)..."
        cargo build --bin florestad --release
        PROFILE="release"
    else
        echo "Building florestad (debug)..."
        cargo build --bin florestad
        PROFILE="debug"
    fi

    ln -fs "$(pwd)/target/${PROFILE}/florestad" "$BINARIES_DIR/florestad"
}

check_installed git
check_installed cargo

build_floresta

# Check if utreexod is already built or if --build is passed
if [ ! -f "$BINARIES_DIR/utreexod" ] || [ "$FORCE_BUILD" -eq 1 ]; then
    build_utreexod
else
    echo "Utreexod already built, skipping..."
fi

# Ensure bitcoind is obtained (downloaded, built, or reused) if --build is passed or not already present
if [ ! -f "$BINARIES_DIR/bitcoind" ] || [ "$FORCE_BUILD" -eq 1 ]; then
    ensure_bitcoind
else
    echo "Bitcoind already built/downloaded, skipping..."
fi

echo "All done!"

echo "Temporary Directory at $TEMP_DIR"

exit 0
