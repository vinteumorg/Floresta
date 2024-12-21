#!/bin/bash

# Find all 'tmp-db' directories in subdirectories
dirs=$(find . -type d -name 'tmp-db')

# Display the directories that will be deleted
echo "The following 'tmp-db' directories will be deleted:"
echo "$dirs"

# Prompt the user for confirmation
read -r -p "Are you sure you want to delete './tmp' and all 'tmp-db' directories listed above? [y/N] " ans

# Check the user's response
if [[ "$ans" =~ ^[Yy]$ ]]; then
    # User confirmed, proceed with deletion

    # Delete 'tmp' in the current directory (if run via justfile this is the root)
    rm -rf tmp

    # Delete all 'tmp-db' directories found
    find . -type d -name 'tmp-db' -exec rm -rf {} +

    echo "Directories deleted."
else
    # User did not confirm, cancel the operation
    echo "Deletion cancelled."
fi
