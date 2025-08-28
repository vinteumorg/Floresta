#!/bin/sh
# Exit immediately if any command fails
set -e

# The first argument specifies the action: "clippy" or "test".
action="${1:-}"
if [ "$action" != "clippy" ] && [ "$action" != "test" ]; then
    echo "Usage: $0 {clippy|test} [cargo_arg]" >&2
    exit 1
fi

# The second argument is passed to cargo (e.g., "-- -D warnings"); defaults to empty.
cargo_arg="${2:-}"

crates="\
    floresta \
    floresta-chain \
    floresta-common \
    floresta-compact-filters \
    floresta-electrum \
    floresta-node \
    floresta-rpc \
    floresta-watch-only \
    floresta-wire \
    florestad \
    floresta-cli \
    fuzz \
    metrics"

chainstore_feats="flat-chainstore,kv-chainstore"

for crate in $crates; do
    # Determine the path to the crate
    if [ "$crate" = "fuzz" ] || [ "$crate" = "metrics" ]; then
        path="$crate"
    elif [ "$crate" = "florestad" ] || [ "$crate" = "floresta-cli" ]; then
        path="bin/$crate"
    else
        path="crates/$crate"
    fi

    # The default feature, if not used to conditionally compile code, can be skipped as the combinations already
    # include that case (see https://github.com/taiki-e/cargo-hack/issues/155#issuecomment-2474330839)
    if [ "$crate" = "floresta-compact-filters" ] || \
       [ "$crate" = "floresta-electrum" ] || \
       [ "$crate" = "fuzz" ] || \
       [ "$crate" = "metrics" ]; then
        # These crates don't have a default feature
        skip_default=""
    else
        skip_default="--skip default"
    fi

    # For floresta-chain, floresta-node and florestad, require exactly one of 'flat-chainstore' or 'kv-chainstore'
    if [ "$crate" = "floresta-chain" ] || [ "$crate" = "florestad" ] || [ "$crate" = "floresta-node" ]; then
        store_feature="--mutually-exclusive-features $chainstore_feats --at-least-one-of $chainstore_feats"
    else
        store_feature=""
    fi

    # Navigate to the crate's directory
    cd "$path" || exit 1
    printf "\033[1;35mRunning cargo %s for all feature combinations in %s...\033[0m\n" "$action" "$crate"

    if [ "$action" = "clippy" ]; then
        # shellcheck disable=SC2086
        cargo +nightly hack clippy --all-targets --feature-powerset $skip_default $store_feature $cargo_arg
    elif [ "$action" = "test" ]; then
        # shellcheck disable=SC2086
        cargo hack test --release --feature-powerset $skip_default $store_feature -v $cargo_arg
    fi

    cd - > /dev/null || exit 1
done
