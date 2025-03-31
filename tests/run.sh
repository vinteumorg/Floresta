
\# Sets a temporary environment to run our tests
#
# This script should be executed after prepare.sh for running our functional test.
#
## What this script do  ?
#
# 1. Sets $PATH to include the compiled florestad and utreexod at FLORESTA_TEMP_DIR/binaries.
#
# 2. Run all needed commands for batch executing all python tests suites:
#
#       uv run tests/run_tests.py

find_binaries_and_run_tests() {

    if [[ ! -v FLORESTA_TEMP_DIR ]]; then
        # This helps us to keep track of the actual version being tested without conflicting with any already installed binaries.
        HEAD_COMMIT_HASH=$(git rev-parse HEAD)

        # Since its deterministic how we make the setup, we already know where to search for the binaries to be testing.
        FLORESTA_TEMP_DIR="/tmp/floresta-functional-tests.${HEAD_COMMIT_HASH}"
    fi

    #prepare.sh will store the binaries in the same place, so we can find them.
    FLORESTA_BIN_DIR="$FLORESTA_TEMP_DIR/binaries/florestad"
    
    UTREEXO_BIN_DIR="$FLORESTA_TEMP_DIR/binaries/utreexod"

    # Here we save the original path from the bash session to restore it later. Cmon, we are not savages.
    ORIGINAL_PATH=$PATH


    # We add the generated binaries for testing to the PATH.
    export PATH="$FLORESTA_BIN_DIR:$UTREEXO_BIN_DIR:$PATH"

    $1

    # Restores the original PATH
    export PATH=$ORIGINAL_PATH

}

find_binaries_and_run_tests "uv run ./tests/run_tests.py"



