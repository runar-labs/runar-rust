// Network integration tests for runar-node-tests
// This crate now only contains network integration tests that require
// multiple nodes and network communication

#[cfg(test)]
pub mod network;

// Re-export macros for convenience in tests
pub use runar_macros_common::{hmap, params, vmap};
