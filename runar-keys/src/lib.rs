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
pub mod derivation;
pub mod error;
pub mod mobile;
pub mod node;
#[macro_use]
mod macros;
pub mod pure_x509;

// Re-export key types for convenience
pub use certificate::{CertificateAuthority, CertificateValidator, X509Certificate};
pub use error::{KeyError, Result};
pub use mobile::MobileKeyManager;
pub use node::NodeKeyManager;

// Device keystore abstraction lives in runar-keys and is used by Mobile/Node managers for
// on-device encrypted persistence. Apple backend is behind `apple-keystore` feature.
pub mod keystore;
// expose profile public key registration convenience re-export

// ---------------------------------------------------------------------------
// Common envelope crypto abstraction (shared with serializer)
// ---------------------------------------------------------------------------
use crate::mobile::EnvelopeEncryptedData;

/// High-level envelope encryption / decryption used by higher layers.
pub trait EnvelopeCrypto: Send + Sync {
    fn encrypt_with_envelope(
        &self,
        data: &[u8],
        network_public_key: Option<&[u8]>, // CHANGED: &[u8] instead of &str
        profile_public_keys: Vec<Vec<u8>>,
    ) -> Result<EnvelopeEncryptedData>;

    fn decrypt_envelope_data(&self, env: &EnvelopeEncryptedData) -> Result<Vec<u8>>;

    /// Get network public key by network ID
    fn get_network_public_key(&self, network_id: &str) -> Result<Vec<u8>>;
}
