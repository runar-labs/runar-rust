use thiserror::Error;

/// Error types for the runar-keys crate
#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Key derivation error: {0}")]
    DerivationError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Signature error: {0}")]
    SignatureError(String),

    #[error("Certificate error: {0}")]
    CertificateError(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Invalid key length")]
    InvalidKeyLength,

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Envelope error: {0}")]
    EnvelopeError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    #[error("Conversion error: {0}")]
    ConversionError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for runar-keys operations
pub type Result<T> = std::result::Result<T, KeyError>;
