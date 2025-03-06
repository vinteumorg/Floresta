#!/bin/bash

# We expect the current dir is the root dir of the project.
FLORESTA_PROJ_DIR=$(pwd)

# This helps us to keep track of the actual version being tested without conflicting with any already installed binaries.
HEAD_COMMIT_HASH=$(git rev-parse HEAD)


# Since its deterministic how we make the setup, we already know where to search for the binaries to be testing.
TEMP_DIR="/tmp/floresta-integration-tests.${HEAD_COMMIT_HASH}"

FLORESTA_BIN_DIR="$TEMP_DIR/florestad/debug"
UTREEXO_BIN_DIR="$TEMP_DIR/utreexod"

ls $TEMP_DIR &>/dev/null
if [ $? -ne 0 ]
then
    echo "The expected test dir for this version of floresta isnt setted yet."
    echo "Did you run prepare.sh? Please read the README.md file."
	exit 1
fi
# Here we save the original path from the bash session to restore it later. Cmon, we are not savages.
ORIGINAL_PATH=$PATH
# We add the generated binaries for testing to the PATH.
export PATH="$FLORESTA_BIN_DIR:$UTREEXO_BIN_DIR:$PATH"

# Actually runs the tests
uv run tests/run_tests.py

# Restores the original PATH
export PATH=$ORIGINAL_PATH
