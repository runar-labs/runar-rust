# Rust SQLite

This crate provides SQLite integration and utilities for the Runar ecosystem.

## Intention

- Offer a consistent, well-documented API for working with SQLite databases.
- Encapsulate all SQLite-specific logic and dependencies.
- Serve as the single point of integration for SQLite in the Runar project.

## Architectural Boundaries

- Only database-related code belongs here; business logic stays in higher-level crates.
- All external dependencies and FFI related to SQLite are isolated in this crate.

## Structure

- `src/lib.rs` – Core library interface (minimal for now)
- `tests/` – Integration tests

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
rust_sqlite = { path = "../rust-sqlite" }
```

## Contributing

- Follow documentation-first and test-driven development practices.
- Respect crate boundaries and update documentation with every change.
