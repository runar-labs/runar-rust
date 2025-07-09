// runar_common/src/lib.rs
//
// Common traits and utilities for the Runar P2P stack

// Export modules
pub mod errors;
pub mod logging;
pub mod macros;
pub mod service_info;
pub mod types;
pub mod utils;

// Re-export traits and types at the root level
pub use logging::{Component, Logger, LoggingContext};
pub use service_info::ServiceInfo;

/// Utility module for compact ID encoding
pub mod compact_ids {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha2::{Digest, Sha256};

    /// Generate a compact node ID from public key bytes using SHA-256 hash
    /// Takes the first 16 bytes (128 bits) of the SHA-256 hash for a compact representation
    pub fn compact_id(public_key: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        let hash_result = hasher.finalize();

        // Take first 16 bytes (128 bits) for compact representation
        let compact_hash = &hash_result[..16];
        URL_SAFE_NO_PAD.encode(compact_hash)
    }

    /// Generate a shorter compact ID (8 bytes = 64 bits) for very compact representation
    pub fn short_compact_id(public_key: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        let hash_result = hasher.finalize();

        // Take the initial 4 bytes and last 4 bytes
        let initial_4 = &hash_result[..4];
        let last_4 = &hash_result[hash_result.len() - 4..];
        let compact_hash = [initial_4, last_4].concat();
        URL_SAFE_NO_PAD.encode(compact_hash)
    }
}
