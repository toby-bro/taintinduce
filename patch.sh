#!/bin/bash
cd peekaboo/

# 1. Try to see if the patch is already applied (by checking if we can reverse it)
if git apply --reverse --check ../0000-compile-in-2025.patch 2>/dev/null; then
    echo "Patch already applied. Skipping."

# 2. If not, try to check if it applies cleanly
elif git apply --check ../0000-compile-in-2025.patch 2>/dev/null; then
    echo "Applying patch..."
    git apply ../0000-compile-in-2025.patch

# 3. If both fail, something is wrong
else
    echo "Error: Patch cannot be applied nor reversed. The submodule might be in an unknown state."
    exit 1
fi

