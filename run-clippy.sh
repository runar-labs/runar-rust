#!/bin/bash
# Script to run clippy only on our own crates, ignoring dependency warnings

# Run clippy on our crates only
cargo clippy --all-targets --all-features --workspace -- -D warnings
