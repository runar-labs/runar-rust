//! Error definitions for runar-keys
//!
//! All failures in this crate map to `KeyError`, an enum implementing
//! `std::error::Error` and `thiserror::Error`.

use ed25519_dalek::SignatureError;

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, KeyError>;

#[derive(thiserror::Error, Debug)]
pub enum KeyError {
    #[error("Invalid seed: {0}")]
    InvalidSeed(String),

    #[error("Derivation error: {0}")]
    DerivationError(String),

    #[error("Cryptography error: {0}")]
    CryptoError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Signature error: {0}")]
    Signature(#[from] SignatureError),

    #[error("Other: {0}")]
    Other(String),
}

impl From<hex::FromHexError> for KeyError {
    fn from(err: hex::FromHexError) -> Self {
        KeyError::SerializationError(err.to_string())
    }
}

impl From<aes_gcm::Error> for KeyError {
    fn from(err: aes_gcm::Error) -> Self {
        KeyError::CryptoError(err.to_string())
    }
}

impl From<hkdf::InvalidLength> for KeyError {
    fn from(err: hkdf::InvalidLength) -> Self {
        KeyError::CryptoError(err.to_string())
    }
}

impl From<sha2::digest::InvalidLength> for KeyError {
    fn from(err: sha2::digest::InvalidLength) -> Self {
        KeyError::CryptoError(err.to_string())
    }
}
