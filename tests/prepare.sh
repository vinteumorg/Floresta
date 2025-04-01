#!/bin/bash

# Prepare a directory with the right testing binaries to avoid conflicts with different versions of floresta.
#
# What this script do ?
#
# 0. While checking build dependencies;
#
# 1. Clone and build utreexod at $FLORESTA_TEMP_DIR/binaries/utreexod.
#
# 2. Build florestad at $FLORESTA_TEMP_DIR/binaries/florestad.
#
# 3. export FLORESTA_TEMP_DIR which points to /tmp/floresta-functional-tests.${HEAD_COMMIT_HASH}/binaries

set -e

# We expect for the current dir to be the root dir of the project.
FLORESTA_PROJ_DIR=$(git rev-parse --show-toplevel)

# This helps us to keep track of the actual version being tested without conflicting with any already installed binaries.
HEAD_COMMIT_HASH=$(git rev-parse HEAD)

export FLORESTA_TEMP_DIR="/tmp/floresta-functional-tests.${HEAD_COMMIT_HASH}"

echo "Temporary Directory at $FLORESTA_TEMP_DIR"


go version &>/dev/null

if [ $? -ne 0 ]
then
	echo "You must have golang installed to run those tests!"
	exit 1
fi


cargo version &>/dev/null

if [ $? -ne 0 ]
then
	echo "You must have rust with cargo installed to run those tests!"
	exit 1
fi

uv -V  &>/dev/null

if [ $? -ne 0 ]
then
	echo "You must have uv installed to run those tests!"
	exit 1
fi

# Dont use mktemp so we can have deterministic results for each version of floresta.
mkdir -p $FLORESTA_TEMP_DIR/binaries

# Download and build utreexod
echo "Downloading and Building utreexod..."
git clone https://github.com/utreexo/utreexod

cd utreexod
go build -o $FLORESTA_TEMP_DIR/binaries/. ./...
cd ..
# We dont check if floresta already exist because a floresta binary could be already be installed on PATH
# causing collisions with the tests.
echo "Building florestad..."

cargo build --bin florestad  --release --target-dir $FLORESTA_TEMP_DIR/binaries/

ln -s $FLORESTA_TEMP_DIR/binaries/release/florestad $FLORESTA_TEMP_DIR/binaries/.

echo "All done!"
exit 0
