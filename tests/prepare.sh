#!/usr/bin/env bash

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

# Dont use mktemp so we can have deterministic results for each version of floresta.
mkdir -p $FLORESTA_TEMP_DIR/binaries

check_installed() {
    if ! command -v "$1" &>/dev/null; then
        echo "You must have $1 installed to run those tests!"
        exit 1
    fi
}

build_core() {
    # Download and build bitcoind only
    mkdir -p "$FLORESTA_TEMP_DIR/binaries/build"
    cd "$FLORESTA_TEMP_DIR/binaries/build" || exit 1

    echo "Downloading and Building Bitcoin Core..."
    git clone https://github.com/bitcoin/bitcoin
    cd bitcoin || exit 1

    # If BITCOIN_REVISION is set, check it out
    # if not, set the default to 29 (the last one)
    bitcoin_rev="${BITCOIN_REVISION:-29.0}"
    if [ -n "$bitcoin_rev" ]; then
        # Check if the revision exists as a tag only
        if git --no-pager tag -l | grep -q "^v$bitcoin_rev$"; then
            git checkout "v$bitcoin_rev"
        else
            echo "bitcoin 'v$bitcoin_rev' is not a valid tag."
            exit 1
        fi
    fi

    # Check compatibility with cmake arguments with those used with make
    # See https://gist.github.com/hebasto/2ef97d3a726bfce08ded9df07f7dab5e and
    # https://github.com/bitcoin-core/bitcoin-devwiki/wiki/Autotools-to-CMake-Options-Mapping
    major_version="${bitcoin_rev%%.*}"
    if [ "$major_version" -ge 29 ]; then
        cmake -S . -B build \
            -DBUILD_CLI=OFF \
            -DBUILD_TESTS=OFF \
            -DENABLE_WALLET=OFF \
            -DCMAKE_BUILD_TYPE=MinSizeRel \
            -DENABLE_EXTERNAL_SIGNER=OFF \
            -DINSTALL_MAN=OFF
        cmake --build build --target bitcoind -j"$(nproc)"
        mv $FLORESTA_TEMP_DIR/binaries/build/bitcoin/build/bin/bitcoind $FLORESTA_TEMP_DIR/binaries/bitcoind
    else
        ./autogen.sh
        ./configure \
            --without-gui \
            --disable-tests \
            --disable-bench \
            --disable-wallet
        make -j"$(nproc)"
        mv $FLORESTA_TEMP_DIR/binaries/build/bitcoin/src/bitcoind $FLORESTA_TEMP_DIR/binaries/bitcoind
    fi

    rm -rf $FLORESTA_TEMP_DIR/binaries/build
}

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
	cargo build --bin florestad --release

	ln -fs $(pwd)/target/release/florestad $FLORESTA_TEMP_DIR/binaries/florestad
}

check_installed git
check_installed gcc
check_installed make
check_installed cmake
check_installed go
check_installed cargo
check_installed uv

# Check if florestad is already built or if --build is passed
if [ ! -f $FLORESTA_TEMP_DIR/binaries/florestad ] || [ "$1" == "--build" ]
then
	build_floresta
else
	echo "Florestad already built, skipping..."
fi

# Check if utreexod is already built or if --build is passed
if [ ! -f $FLORESTA_TEMP_DIR/binaries/utreexod ] || [ "$1" == "--build" ]
then
	build_utreexod
else
	echo "Utreexod already built, skipping..."
fi

# Check if utreexod is already built or if --build is passed
if [ ! -f $FLORESTA_TEMP_DIR/binaries/bitcoind ] || [ "$1" == "--build" ]
then
	build_core
else
	echo "Bitcoind already built, skipping..."
fi

echo "All done!"

echo "Temporary Directory at $FLORESTA_TEMP_DIR"

exit 0
