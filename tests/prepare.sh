#!/usr/bin/env bash

set -e

BITCOIN_REVISION="${BITCOIN_REVISION:-30.0}"
# We expect for the current dir to be the root dir of the project.
FLORESTA_PROJ_DIR=$(git rev-parse --show-toplevel)
TEMP_DIR="/tmp/floresta-func-tests"
BINARIES_DIR="$TEMP_DIR/binaries"
# Dont use mktemp so we can have deterministic results for each version of floresta.
mkdir -p $BINARIES_DIR

create_disposable_dir() {
    local disposable_dir
    disposable_dir=$(mktemp -d)
    trap 'rm -rf -- "$disposable_dir"' RETURN
    echo "$disposable_dir"
    # Change to the disposable directory
    pushd "$disposable_dir" >/dev/null
}

check_installed() {
    if ! command -v "$1" &>/dev/null; then
        echo "You must have $1 installed to run those tests!"
        exit 1
    fi
}

use_user_bitcoind() {
    # If user provided a custom bitcoind binary via BITCOIND_EXE, use it.
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
    uname_s="$(uname -s)"
    case "$uname_s" in
        Linux*) platform="x86_64-linux-gnu" ;;
        Darwin*) platform="x86_64-apple-darwin" ;;
        *)
            echo "Unsupported platform for prebuilt bitcoind: $uname_s"
            return 1
            ;;
    esac

    # mapping: add/remove supported versions + sha256 here
    declare -A hashes_linux=(
        ["30.0"]="00964ae375084113b1162f2f493b9372421608af23539766e315a3cb0ee54248"
        ["29.0"]="a681e4f6ce524c338a105f214613605bac6c33d58c31dc5135bbc02bc458bb6c"
        ["28.3"]="732b8d5d56ffd341d4b7c8caeddcaa60c712e36b7e7665dc485bcb37f0f81d98"
        ["27.2"]="6ebc56ca1397615d5a6df2b5cf6727b768e3dcac320c2d5c2f321dcaabc7efa2"
    )
    declare -A hashes_darwin=(
        ["30.0"]="4eadf7b06dca695b940ad30f46247aacbd439544a1be25b0ef3baab73777b3d2"
        ["29.0"]="5bb824fc86a15318d6a83a1b821ff4cd4b3d3d0e1ec3d162b805ccf7cae6fca8"
        ["28.3"]="9a98cca968edf2cf4de07e5fdf83716e93b870699f5d36cb8cb5af1cc1b63fdc"
        ["27.2"]="acc223af46c178064c132b235392476f66d486453ddbd6bca6f1f8411547da78"
    )

    if [ "$platform" = "x86_64-linux-gnu" ]; then
        hash="${hashes_linux[$BITCOIN_REVISION]}"
    else
        hash="${hashes_darwin[$BITCOIN_REVISION]}"
    fi

    if [ -z "$hash" ]; then
        echo "No prebuilt hash for bitcoin version $BITCOIN_REVISION on platform $platform"
        return 1
    fi

    file_name="bitcoin-${BITCOIN_REVISION}-${platform}.tar.gz"
    dl_url="https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_REVISION}/${file_name}"

    # Change to a disposable directory for download and extraction
    disposable_dir=$(create_disposable_dir)

    echo "Downloading $dl_url"
    if ! curl -L -o "$file_name" "$dl_url"; then
        return 1
    fi

    echo "${hash}  ${file_name}" | shasum -a 256 -c - >/dev/null 2>&1 || {
        echo "SHA256 mismatch for $file_name"
        return 1
    }

    if ! tar xzf "$file_name"; then
        return 1
    fi

    extracted_bin="bitcoin-${BITCOIN_REVISION}/bin/bitcoind"
    if [ ! -f "$extracted_bin" ]; then
        echo "Unexpected archive layout: $extracted_bin not found"
        return 1
    fi

    cp "$extracted_bin" "$BINARIES_DIR/bitcoind"
    chmod +x "$BINARIES_DIR/bitcoind"

    echo "bitcoind downloaded to $BINARIES_DIR/bitcoind"
    return 0
}

build_bitcoind_from_source() {
    check_installed gcc
    check_installed make
    check_installed cmake

    # Change to a disposable directory for download and build
    disposable_dir=$(create_disposable_dir)

    echo "Downloading and Building Bitcoin Core..."
    git clone https://github.com/bitcoin/bitcoin "$disposable_dir/bitcoin"
    cd "$disposable_dir/bitcoin" || exit 1

    # If BITCOIN_REVISION is set, check it out
    # if not, set the default to 29 (the last one)
    if [ -n "$BITCOIN_REVISION" ]; then
        # Check if the revision exists as a tag only
        if git --no-pager tag -l | grep -q "^v$BITCOIN_REVISION$"; then
            git checkout "v$BITCOIN_REVISION"
        else
            echo "bitcoin 'v$BITCOIN_REVISION' is not a valid tag."
            exit 1
        fi
    fi

    # Check compatibility with cmake arguments with those used with make
    # See https://gist.github.com/hebasto/2ef97d3a726bfce08ded9df07f7dab5e and
    # https://github.com/bitcoin-core/bitcoin-devwiki/wiki/Autotools-to-CMake-Options-Mapping
    major_version="${$BITCOIN_REVISION%%.*}"
    if [ "$major_version" -ge 29 ]; then
        cmake -S . -B build \
            -DBUILD_CLI=OFF \
            -DBUILD_TESTS=OFF \
            -DENABLE_WALLET=OFF \
            -DCMAKE_BUILD_TYPE=MinSizeRel \
            -DENABLE_EXTERNAL_SIGNER=OFF \
            -DINSTALL_MAN=OFF
        cmake_nprocs="${BUILD_BITCOIND_NPROCS:-4}"
        cmake --build build --target bitcoind -j"${cmake_nprocs}"
        mv "$disposable_dir/bitcoin/build/bin/bitcoind" "$BINARIES_DIR/bitcoind"
    else
        ./autogen.sh
        ./configure \
            --without-gui \
            --disable-tests \
            --disable-bench \
            --disable-wallet
        make_nprocs="${BUILD_BITCOIND_NPROCS:-4}"
        make -j"$(make_nprocs)"
        mv "$disposable_dir/bitcoin/src/bitcoind" "$BINARIES_DIR/bitcoind"
    fi

    return 0
}

ensure_bitcoind() {
    mkdir -p "$BINARIES_DIR"

    # 1) user-provided binary
    if use_user_bitcoind; then
        return 0
    fi

    # 2) try download prebuilt tarball for supported versions/platforms
    if download_prebuilt_bitcoind; then
        return 0
    fi

    # 3) fallback: clone & build from source
    if build_bitcoind_from_source; then
        return 0
    fi

    echo "Failed to obtain bitcoind (tried BITCOIND_EXE, prebuilt tarball and source build)"
    return 1
}

build_utreexod() {
    check_installed go

    # Change to a disposable directory for download and build
    disposable_dir=$(create_disposable_dir)

    echo "Downloading and Building utreexod..."
    git clone https://github.com/utreexo/utreexod "$disposable_dir/utreexod"

    cd "$disposable_dir/utreexod"

    go build -o "$BINARIES_DIR/." .
}

build_floresta() {
    # We dont check if floresta already exist because a floresta binary could be already be installed on PATH
    # causing collisions with the tests.
    echo "Building florestad..."

    cd $FLORESTA_PROJ_DIR
    cargo build --bin florestad --release

    ln -fs $(pwd)/target/release/florestad "$BINARIES_DIR/florestad"
}

check_installed git
check_installed cargo

build_floresta

# Check if utreexod is already built or if --build is passed
if [ ! -f "$BINARIES_DIR/utreexod" ] || [ "$1" == "--build" ]; then
    build_utreexod
else
    echo "Utreexod already built, skipping..."
fi

# Ensure bitcoind is obtained (downloaded, built, or reused) if --build is passed or not already present
if [ ! -f "$BINARIES_DIR/bitcoind" ] || [ "$1" == "--build" ]; then
    ensure_bitcoind
else
    echo "Bitcoind already built/downloaded, skipping..."
fi

echo "All done!"

echo "Temporary Directory at $TEMP_DIR"

exit 0
