//! Runar Keys Fix - Production-Ready Certificate System
//!
//! A robust, standards-compliant certificate management system for the Runar network.
//! This implementation replaces the existing custom certificate system with proper
//! X.509 certificates and a unified ECDSA P-256 cryptographic foundation.
//!
//! ## Key Features
//!
//! - **Standard X.509 Certificates**: Full compliance with PKI standards
//! - **Unified Cryptography**: Single ECDSA P-256 algorithm throughout
//! - **Proper CA Hierarchy**: Mobile CA signs all node certificates
//! - **QUIC Compatibility**: Certificates work seamlessly with QUIC transport
//! - **Production Quality**: Comprehensive validation and error handling
//!
//! ## Architecture
//!
//! ```text
//! Mobile User CA (Self-signed root)
//! └── Node TLS Certificate (signed by Mobile CA)
//!     └── Used for all QUIC/TLS operations
//! ```

pub mod certificate;
pub mod error;
pub mod mobile;
pub mod node;

/// Utility module for compact ID encoding
pub mod compact_ids {
    use crate::error::{KeyError, Result};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha2::{Digest, Sha256};

    /// Encode public key bytes to a compact Base64 URL-safe string
    pub fn encode_compact_id(public_key: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(public_key)
    }

    /// Decode compact Base64 URL-safe string back to public key bytes
    pub fn decode_compact_id(compact_id: &str) -> Result<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(compact_id)
            .map_err(|e| KeyError::InvalidKeyFormat(format!("Failed to decode compact ID: {e}")))
    }

    /// Generate a compact node ID from public key bytes using SHA-256 hash
    /// Takes the first 16 bytes (128 bits) of the SHA-256 hash for a compact representation
    pub fn compact_node_id(public_key: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        let hash_result = hasher.finalize();

        // Take first 16 bytes (128 bits) for compact representation
        let compact_hash = &hash_result[..16];
        URL_SAFE_NO_PAD.encode(compact_hash)
    }

    /// Generate a compact network ID from public key bytes using SHA-256 hash
    /// Takes the first 16 bytes (128 bits) of the SHA-256 hash for a compact representation
    pub fn compact_network_id(public_key: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        let hash_result = hasher.finalize();

        // Take first 16 bytes (128 bits) for compact representation
        let compact_hash = &hash_result[..16];
        URL_SAFE_NO_PAD.encode(compact_hash)
    }

    /// Generate a compact ID from public key bytes using SHA-256 hash
    /// This is the new recommended function for creating compact IDs
    pub fn hash_compact_id(public_key: &[u8]) -> String {
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

        // Take first 8 bytes (64 bits) for very compact representation
        let compact_hash = &hash_result[..8];
        URL_SAFE_NO_PAD.encode(compact_hash)
    }
}

// Re-export key types for convenience
pub use certificate::{CertificateAuthority, CertificateValidator, X509Certificate};
pub use error::{KeyError, Result};
pub use mobile::MobileKeyManager;
pub use node::NodeKeyManager;

// ---------------------------------------------------------------------------
// Common envelope crypto abstraction (shared with serializer)
// ---------------------------------------------------------------------------
use crate::mobile::EnvelopeEncryptedData;

/// High-level envelope encryption / decryption used by higher layers.
pub trait EnvelopeCrypto: Send + Sync {
    fn encrypt_with_envelope(
        &self,
        data: &[u8],
        network_id: &str,
        profile_ids: Vec<String>,
    ) -> Result<EnvelopeEncryptedData>;

    fn decrypt_envelope_data(&self, env: &EnvelopeEncryptedData) -> Result<Vec<u8>>;
}
