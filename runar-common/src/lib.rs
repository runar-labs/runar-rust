//! Runar Common
//!
//! Common traits and utilities for the Runar P2P stack.
//!
//! This crate provides:
//! - Component-based structured logging with node ID context
//! - Lightweight error utilities
//! - DNS-safe compact ID generation
//!
//! See the crate [README](https://github.com/runar-labs/runar-rust/tree/main/runar-common) for usage examples.

// Export modules
pub mod errors;
pub mod logging;
pub mod routing;
// Re-export traits and types at the root level
pub use logging::{Component, ComponentKey, LogLevel, Logger, LoggingConfig, LoggingContext};

/// Utility module for compact ID encoding
pub mod compact_ids {
    use data_encoding::BASE32HEX_NOPAD;
    use sha2::{Digest, Sha256};

    /// Generate a DNS-safe compact ID from public key bytes using SHA-256 hash.
    /// - Input: SEC1/X9.63 uncompressed (65 bytes)
    /// - Truncate: first 16 bytes of SHA-256 hash
    /// - Encode: Base32hex (no padding), lowercase (26 chars)
    pub fn compact_id(public_key: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        let hash_result = hasher.finalize();

        // Take first 16 bytes (128 bits) for compact representation
        let compact_hash = &hash_result[..16];
        // Base32hex no padding, lowercase
        BASE32HEX_NOPAD.encode(compact_hash).to_lowercase()
    }
}
