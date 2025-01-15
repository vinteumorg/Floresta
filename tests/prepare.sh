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


# We expect the current dir is the root dir of the project.
FLORESTA_PROJ_DIR=$(pwd)
# This helps us to keep track of the actual version being tested without conflicting with any already installed binaries.
HEAD_COMMIT_HASH=$(git rev-parse HEAD)

TEMP_DIR="/tmp/floresta-integration-tests.${HEAD_COMMIT_HASH}"


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

poetry -V  &>/dev/null

if [ $? -ne 0 ]
then
	echo "You must have poetry installed to run those tests!"
	exit 1
fi



ls $TEMP_DIR &>/dev/null
if [ $? -ne 0 ]
then
	echo "The tests dir for the tests does not exist. Creating it..."
	# Dont use mktemp so we can have deterministic results for each version of floresta.
	mkdir -p "$TEMP_DIR"
fi

echo "$TEMP_DIR exists. Delete it with"
echo "$ rm -rf $TEMP_DIR"
echo "if you want to start fresh."

cd $TEMP_DIR/

# Download and build utreexod
ls -la utreexod &>/dev/null
if [ $? -ne 0 ]
then
    echo "Utreexo not found on $TEMP_DIR/utreexod."
    echo "Downloading utreexod..."
	git clone https://github.com/utreexo/utreexod &>/dev/null
	echo "Building utreexod..."
	cd utreexod
    go build . &>/dev/null
fi

# Checks if needed and build floresta setting the specific version of this build to the one we are testing
ls -la florestad &>/dev/null
if [ $? -ne 0 ]
then
    echo "Floresta not found on $TEMP_DIR/florestad."
    echo "Building florestad..."
    cd $FLORESTA_PROJ_DIR
    cargo build --bin florestad --features json-rpc --target-dir $TEMP_DIR/florestad &>/dev/null
fi

echo "All done!"
exit 0
