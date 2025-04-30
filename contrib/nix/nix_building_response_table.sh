#!/bin/bash

# This script is supposed to automatize the verification of the nix building outputs.

nix --version &>/dev/null

if [ $? -ne 0 ]
then
	echo "Cmon, you need atleast nix in your machine to run this. duhh"
	exit 1
fi

rm -r ./result

# the targets we have
NIX_BUILD_FLORESTAD=$(nix build .#florestad 2>&1)
NIX_BUILD_FLORESTACLI=$(nix build .#floresta-cli 2>&1)
NIX_BUILD_LIBFLORESTA=$(nix build .#libfloresta 2>&1)
NIX_BUILD_ALL=$(nix build 2>&1)


check_florestad() {
    ./result/bin/florestad --version >/dev/null 2>&1 && echo "✅" || echo "❌"
}

check_floresta_cli() {
    ./result/bin/floresta-cli --version >/dev/null 2>&1 && echo "✅" || echo "❌"
}

check_libfloresta() {
    [[ -f "./result/lib/libfloresta.so" ]] && echo "✅" || echo "❌"
}

check_all() {
    [[ $(check_florestad) == "✅" && \
       $(check_floresta_cli) == "✅" && \
       $(check_libfloresta) == "✅" ]] && echo "✅" || echo "❌"
}

# Print table
echo ""
echo "┌──────────────────────┬──────────────┬───────────────────────────────┐"
echo "│       Target         │ Build Status │          Check Test           │"
echo "├──────────────────────┼──────────────┼───────────────────────────────┤"
printf "│ %-20s │      %-7s │ %-28s │\n" "florestad" \
       "$(if [ $? -eq 0 ]; then echo '✅'; else echo '❌'; fi)" \
       "$(check_florestad)"
printf "│ %-20s │      %-7s │ %-28s │\n" "floresta-cli" \
       "$(if [ $? -eq 0 ]; then echo '✅'; else echo '❌'; fi)" \
       "$(check_floresta_cli)"
printf "│ %-20s │      %-7s │ %-28s │\n" "libfloresta" \
       "$(if [ $? -eq 0 ]; then echo '✅'; else echo '❌'; fi)" \
       "$(check_libfloresta)"
printf "│ %-20s │      %-7s │ %-28s │\n" "ALL (meta-build)" \
       "$(if [ $? -eq 0 ]; then echo '✅'; else echo '❌'; fi)" \
       "$(check_all)"
echo "└──────────────────────┴──────────────┴───────────────────────────────┘"
echo ""
