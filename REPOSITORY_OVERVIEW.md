# Runar Labs Rust Mono Repository Overview

This document provides an overview of the repository structure and key components.

## Directory Structure

- **rust-node**: The main implementation of the Runar Node system
- **rust-common**: Common utilities and types shared across the codebase
- **rust-docs**: Documentation for the project
- **rust-macros**: Rust procedural macros for the project
- **rust-macros-tests**: Tests for the macros
- **rust-node-old**: Original implementation of the Runar Node system, kept for reference only (not compiled)
- **rust-apps**: Applications built on top of the Runar Node system
- **rust-examples**: Example code demonstrating usage of the Runar Node system
- **node_webui**: Web UI for interacting with the Runar Node

## Key Components

### rust-node

The main implementation of the Runar Node system, which includes:
- Topic-based routing with path templating
- Service lifecycle management
- Request-response patterns
- Event publishing and subscription

### rust-node-old

**This is a reference implementation only and is not compiled with the project.**

The directory contains the original implementation of the Runar Node system before the refactoring. It's kept for reference purposes to:
1. Preserve the history of the codebase
2. Provide examples of the original approach
3. Serve as a reference for understanding design decisions in the new implementation

The `Cargo.toml` file has been renamed to `Cargo.toml.reference` to prevent it from being compiled.

## Development

All development work should be done in the appropriate directories, with `rust-node` being the primary focus for the core system implementation. Do not modify the `rust-node-old` directory as it is kept only for reference. 