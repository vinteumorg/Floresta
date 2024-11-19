#!/bin/sh

# Exit immediately if any command fails
set -e

# Pass the first argument to the script as a cargo argument, defaults to empty string
cargo_arg="${1:-}"

crates="\
    floresta-chain \
    floresta-cli \
    floresta-common \
    floresta-compact-filters \
    floresta-electrum \
    floresta-watch-only \
    floresta-wire \
    floresta \
    florestad"

for crate in $crates; do
    # Determine the path to the crate
    if [ "$crate" = "florestad" ]; then
        path="$crate"
    else
        path="crates/$crate"
    fi

    # The default feature, if not used to conditionally compile code, can be skipped as the combinations already
    # include that case (see https://github.com/taiki-e/cargo-hack/issues/155#issuecomment-2474330839)
    if [ "$crate" = "floresta-compact-filters" ] || [ "$crate" = "floresta-electrum" ]; then
        # These two crates don't have a default feature
        skip_default=""
    else
        skip_default="--skip default"
    fi

    # Navigate to the crate's directory
    cd "$path" || exit 1
    printf "\033[1;35mTesting all feature combinations for %s...\033[0m\n" "$crate"

    # Test all feature combinations (to run with verbose output the `cargo_arg` must also be -v/--verbose)
    # shellcheck disable=SC2086
    cargo hack test --release --feature-powerset $skip_default -v $cargo_arg
    cd - > /dev/null || exit 1
done
