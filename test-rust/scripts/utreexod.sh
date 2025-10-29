#!/bin/bash
set -eox pipefail

# Our tests require `utreexod` binary. Here, we clone the repository, build it, and export its
# location via `UTREEXOD_EXE` which will be used by the `utreexod` crate in our tests.

UTREEXOD_REPO="https://github.com/utreexo/utreexod"
UTREEXOD_REVISION="${UTREEXO_REVISION:-}"  # Optional: set to a specific tag or commit if needed

DL_TMP_DIR=$(mktemp -d)
trap 'rm -rf -- "$DL_TMP_DIR"' EXIT

pushd "$DL_TMP_DIR"
echo "Cloning and building utreexod..."
git clone "$UTREEXOD_REPO" utreexod
cd utreexod

# Checkout specific revision if provided
if [ -n "$UTREEXOD_REVISION" ]; then
    git checkout "$UTREEXOD_REVISION"
fi

# Build the binary
go build -o utreexod .

# Export the executable path
export UTREEXOD_EXE="$DL_TMP_DIR/utreexod/utreexod"
chmod +x "$UTREEXOD_EXE"

popd