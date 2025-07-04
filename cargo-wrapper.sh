#!/bin/bash

# Cargo wrapper to bypass Cursor proxy issues
# This script runs cargo in a clean environment

# Save current environment
ORIGINAL_PATH="$PATH"
ORIGINAL_LD_LIBRARY_PATH="$LD_LIBRARY_PATH"

# Clean environment - remove Cursor-specific paths
export PATH="/home/rafael/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
unset LD_LIBRARY_PATH

# Run cargo with the clean environment
exec /home/rafael/.cargo/bin/cargo "$@" 