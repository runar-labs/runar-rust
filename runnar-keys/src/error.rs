use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum KeyError {
    #[error("Invalid seed length or format: {0}")]
    InvalidSeed(String),

    #[error("Key derivation failed: {0}")]
    DerivationError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("Invalid access token: {0}")]
    InvalidToken(String),

    #[error("Access token has expired")]
    TokenExpired,

    #[error("Invalid capability specified: {0}")]
    InvalidCapability(String),

    #[error("Hex decoding error: {0}")]
    HexError(String),

    #[error("IO error: {0}")]
    IoError(String), // For potential future use if reading keys from disk etc.

    #[error("Key not found in manager: {0}")]
    KeyNotFound(String),

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("Invalid signature format: {0}")]
    InvalidSignatureFormat(String),
}

// Implement From<hex::FromHexError> for KeyError
impl From<hex::FromHexError> for KeyError {
    fn from(err: hex::FromHexError) -> Self {
        KeyError::HexError(err.to_string())
    }
}

// Implement From<serde_json::Error> for KeyError for token serialization
impl From<serde_json::Error> for KeyError {
    fn from(err: serde_json::Error) -> Self {
        KeyError::SerializationError(format!("JSON error: {}", err))
    }
}

// Placeholder for other potential error conversions if needed, e.g.:
// impl From<ed25519_dalek::SignatureError> for KeyError {
//     fn from(err: ed25519_dalek::SignatureError) -> Self {
//         KeyError::CryptoError(format!("Signature error: {}", err))
//     }
// }
