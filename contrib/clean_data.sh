#!/bin/bash

###############################################################################
# Clean utility script
# ---------------------
# This script deletes:
#   1. ./tmp directory in the project root
#   2. All "tmp-db" directories found anywhere in the repository
#   3. The ./contrib/dev_bin/ directory (where local cargo binaries are installed)
#
# It will:
#   - Show the user which directories will be deleted
#   - Ask for confirmation before proceeding
#   - Perform deletions safely
###############################################################################

clean() {
    tmp_dir="./tmp"
    contrib_bin_dir="./contrib/dev_bin"
    tmp_db_dirs=$(find . -type d -name 'tmp-db')

    echo "The following directories will be deleted:"
    echo "$tmp_dir"
    echo "$contrib_bin_dir"
    echo "$tmp_db_dirs"

    read -r -p "Are you sure you want to delete the above directories? [y/N] " ans

    if [[ "$ans" =~ ^[Yy]$ ]]; then
        echo "Proceeding with deletion..."

        rm -rf "$tmp_dir"

        rm -rf "$contrib_bin_dir"

        find . -type d -name 'tmp-db' -exec rm -rf {} +

        echo "Directories deleted."
    else
        echo "Deletion cancelled."
    fi
}

clean