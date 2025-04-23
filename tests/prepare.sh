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
GIT_DESCRIBE=$(git describe --tags --always)

export FLORESTA_TEMP_DIR="/tmp/floresta-func-tests.${GIT_DESCRIBE}"

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

build_utreexod() {
	# Download and build utreexod
	mkdir -p $FLORESTA_TEMP_DIR/binaries/build
	cd $FLORESTA_TEMP_DIR/binaries/build
	echo "Downloading and Building utreexod..."
	git clone https://github.com/utreexo/utreexod

	cd utreexod
	
	# check if UTREEXO_REVISION is set, if so checkout to it
	if [ -n "$UTREEXO_REVISION" ]; then
		# Check if the revision exists as a tag only
		if git --no-pager tag -l | grep "$UTREEXO_REVISION"; then
			git checkout "tags/v$UTREEXO_REVISION"
		else
			echo "utreexod 'v$UTREEXO_REVISION' is not a valid tag in this repository."
			exit 1
		fi
	fi

	go build -o $FLORESTA_TEMP_DIR/binaries/. .
	rm -rf $FLORESTA_TEMP_DIR/binaries/build
}

build_floresta() {
	# We dont check if floresta already exist because a floresta binary could be already be installed on PATH
	# causing collisions with the tests.
	echo "Building florestad..."

	cd $FLORESTA_PROJ_DIR
	cargo build --bin florestad  --release --target-dir $FLORESTA_TEMP_DIR/binaries/

	rm -rf $FLORESTA_TEMP_DIR/binaries/target/
	ln -s $FLORESTA_TEMP_DIR/binaries/release/florestad $FLORESTA_TEMP_DIR/binaries/.
}

# Check if utreexod is already built or if --build is passed
if [ ! -f $FLORESTA_TEMP_DIR/binaries/utreexod ] || [ "$1" == "--build" ]
then
	build_utreexod
else
	echo "Utreexod already built, skipping..."
fi


# Check if florestad is already built
if [ ! -f $FLORESTA_TEMP_DIR/binaries/florestad ]
then
	build_floresta
else
	echo "Florestad already built, skipping..."
fi

echo "All done!"
exit 0

