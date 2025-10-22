#!/usr/bin/env bash
set -eox pipefail

check_installed() {
    if ! command -v "$1" &>/dev/null; then
        echo "You must have $1 installed to run those tests!"
        exit 1
    fi
}

check_installed git
check_installed go
check_installed cargo

# Script to run bitcoind.sh and utreexod.sh, then move the binaries to a persistent location.

# Set FLORESTA_TEMP_DIR if not set
export FLORESTA_TEMP_DIR="/tmp/floresta-func-tests"
mkdir -p "$FLORESTA_TEMP_DIR/binaries"

# Get the directory where this script is located (use BASH_SOURCE for sourced scripts)
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Define target paths
BITCOIND_TARGET="$FLORESTA_TEMP_DIR/binaries/bitcoind"
UTREEXOD_TARGET="$FLORESTA_TEMP_DIR/binaries/utreexod"

# Check if bitcoind is already in the correct location
if [ -f "$BITCOIND_TARGET" ]; then
    export BITCOIND_EXE="$BITCOIND_TARGET"
    echo "Bitcoind already available in $BITCOIND_EXE"
else
    # Check if BITCOIND_EXE is already set and the file exists; if so, copy it directly
    if [ -n "$BITCOIND_EXE" ] && [ -f "$BITCOIND_EXE" ]; then
        cp "$BITCOIND_EXE" "$BITCOIND_TARGET"
        export BITCOIND_EXE="$BITCOIND_TARGET"
        echo "Bitcoind already available, copied to $BITCOIND_EXE"
    else
        # Run the script to download/build bitcoind
        . "$SCRIPT_DIR/bitcoind.sh"
        # After sourcing, copy the binary
        if [ -n "$BITCOIND_EXE" ] && [ -f "$BITCOIND_EXE" ]; then
            cp "$BITCOIND_EXE" "$BITCOIND_TARGET"
            export BITCOIND_EXE="$BITCOIND_TARGET"
            echo "Bitcoind moved to $BITCOIND_EXE"
        else
            echo "BITCOIND_EXE not found or invalid after running script"
            exit 1
        fi
    fi
fi

# Check if utreexod is already in the correct location
if [ -f "$UTREEXOD_TARGET" ]; then
    export UTREEXOD_EXE="$UTREEXOD_TARGET"
    echo "Utreexod already available in $UTREEXOD_EXE"
else
    # Check if UTREEXOD_EXE is already set and the file exists; if so, copy it directly
    if [ -n "$UTREEXOD_EXE" ] && [ -f "$UTREEXOD_EXE" ]; then
        cp "$UTREEXOD_EXE" "$UTREEXOD_TARGET"
        export UTREEXOD_EXE="$UTREEXOD_TARGET"
        echo "Utreexod already available, copied to $UTREEXOD_EXE"
    else
        # Run the script to download/build utreexod
        . "$SCRIPT_DIR/utreexod.sh"
        # After sourcing, copy the binary
        if [ -n "$UTREEXOD_EXE" ] && [ -f "$UTREEXOD_EXE" ]; then
            cp "$UTREEXOD_EXE" "$UTREEXOD_TARGET"
            export UTREEXOD_EXE="$UTREEXOD_TARGET"
            echo "Utreexod moved to $UTREEXOD_EXE"
        else
            echo "UTREEXOD_EXE not found or invalid after running script"
            exit 1
        fi
    fi
fi

echo "All binaries pushed to $FLORESTA_TEMP_DIR/binaries"