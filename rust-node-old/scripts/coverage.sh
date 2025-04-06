#!/usr/bin/env bash
set -e

# Check if cargo-llvm-cov is installed
if ! cargo llvm-cov --version &> /dev/null; then
    echo "Installing cargo-llvm-cov..."
    cargo install cargo-llvm-cov
fi

# Clean any previous coverage data
cargo llvm-cov clean --workspace

# Run the tests and generate HTML coverage report
echo "Running tests and generating coverage report..."
cargo llvm-cov --html

# Open the coverage report
echo "Coverage report generated at target/llvm-cov/html/index.html"
if [[ "$1" == "--open" ]]; then
    echo "Opening coverage report..."
    cargo llvm-cov --open
else
    echo "Run with --open flag to open the report in your browser"
fi

# Print coverage summary
echo ""
echo "Coverage Summary:"
cargo llvm-cov --no-run 