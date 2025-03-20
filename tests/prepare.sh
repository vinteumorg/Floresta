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


# We expect for the current dir to be the root dir of the project.
FLORESTA_PROJ_DIR=$(git rev-parse --show-toplevel)

# This helps us to keep track of the actual version being tested without conflicting with any already installed binaries.
HEAD_COMMIT_HASH=$(git rev-parse HEAD)

FLORESTA_TEMP_DIR="/tmp/floresta-functional-tests.${HEAD_COMMIT_HASH}"


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

cargo build --bin florestad --features json-rpc --target-dir $FLORESTA_TEMP_DIR/binaries/. &>/dev/null


echo "All done!"
exit 0
