#!/bin/bash
set -eox pipefail

# Our tests require `bitcoind` binary. Here, we download the binary, validate it, and export its
# location via `BITCOIND_EXE` which will be used by the `bitcoind` crate in our tests.

HOST_PLATFORM="$(rustc --version --verbose | grep "host:" | awk '{ print $2 }')"
BITCOIND_DL_ENDPOINT="https://bitcoincore.org/bin/"
BITCOIND_VERSION="29.0"
if [[ "$HOST_PLATFORM" == *linux* ]]; then
    BITCOIND_DL_FILE_NAME=bitcoin-"$BITCOIND_VERSION"-x86_64-linux-gnu.tar.gz
    BITCOIND_DL_HASH="a681e4f6ce524c338a105f214613605bac6c33d58c31dc5135bbc02bc458bb6c"
elif [[ "$HOST_PLATFORM" == *darwin* ]]; then
    BITCOIND_DL_FILE_NAME=bitcoin-"$BITCOIND_VERSION"-x86_64-apple-darwin.tar.gz
    BITCOIND_DL_HASH="5bb824fc86a15318d6a83a1b821ff4cd4b3d3d0e1ec3d162b805ccf7cae6fca8"
else
    printf "\n\n"
    echo "Unsupported platform: $HOST_PLATFORM Exiting.."
    exit 1
fi

DL_TMP_DIR=$(mktemp -d)
trap 'rm -rf -- "$DL_TMP_DIR"' EXIT

pushd "$DL_TMP_DIR"
BITCOIND_DL_URL="$BITCOIND_DL_ENDPOINT"/bitcoin-core-"$BITCOIND_VERSION"/"$BITCOIND_DL_FILE_NAME"
curl -L -o "$BITCOIND_DL_FILE_NAME" "$BITCOIND_DL_URL"
echo "$BITCOIND_DL_HASH  $BITCOIND_DL_FILE_NAME"|shasum -a 256 -c
tar xzf "$BITCOIND_DL_FILE_NAME"
export BITCOIND_EXE="$DL_TMP_DIR"/bitcoin-"$BITCOIND_VERSION"/bin/bitcoind
chmod +x "$BITCOIND_EXE"
popd