#!/bin/bash

# Prepares a temporary environment to run our tests
#
# This script should be executed once, before running our functinal test
# for the first time we are testing a specific commit or in a session, since all the created files are temporary.
#
# It'll download and build only utreexod and florestad, since we are not testing the other binaries.
#
# Make sure to have python(for the tests), golang(for building utreexod) and rust(for building florestad) installed.
#

# We expect for the current dir to be the root dir of the project.
FLORESTA_PROJ_DIR=$(pwd)

# This helps us to keep track of the actual version being tested without conflicting with any already installed binaries.
HEAD_COMMIT_HASH=$(git rev-parse HEAD)

FLORESTA_TEMP_DIR="/tmp/floresta-integration-tests.${HEAD_COMMIT_HASH}"


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

if [[ -v FLORESTA_TEMP_DIR ]]; then
	echo "The temp dir for the tests does not exist. Creating it..."
	# Dont use mktemp so we can have deterministic results for each version of floresta.
	mkdir -p $FLORESTA_TEMP_DIR/binaries
fi

cd $FLORESTA_TEMP_DIR/

# Download and build utreexod
ls -la utreexod &>/dev/null
if [ $? -ne 0 ]
then
    echo "Utreexo not found on PATH"
	git clone https://github.com/utreexo/utreexod &>/dev/null
	echo "Building utreexod..."
	cd utreexod
    go build -o  $FLORESTA_TEMP_DIR/binaries/. ./... &>/dev/null
fi

# We dont check if floresta already exist because a floresta binary could be already be installed on PATH
# causing collisions with the tests.
echo "Building florestad..."
cd $FLORESTA_PROJ_DIR
cargo build --bin florestad --features json-rpc --target-dir $FLORESTA_TEMP_DIR/binaries/. &>/dev/null


echo "All done!"
exit 0
