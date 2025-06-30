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

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Keyring error: {0}")]
    KeyringError(String),

    #[error("HKDF error")]
    HkdfError,

    #[error("Symmetric encryption/decryption error: {0}")]
    SymmetricCryptoError(String),

    #[error("AES-GCM error")]
    AesGcmError,

    #[error("Asymmetric encryption/decryption error: {0}")]
    AsymmetricCryptoError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Service connection error: {0}")]
    ServiceConnectionError(String),
}

impl From<ed25519_dalek::ed25519::Error> for KeyError {
    fn from(err: ed25519_dalek::ed25519::Error) -> Self {
        KeyError::CryptoError(err.to_string())
    }
}

impl From<std::array::TryFromSliceError> for KeyError {
    fn from(err: std::array::TryFromSliceError) -> Self {
        KeyError::InvalidKeyFormat(err.to_string())
    }
}

impl From<keyring::Error> for KeyError {
    fn from(err: keyring::Error) -> Self {
        match err {
            keyring::Error::NoEntry => {
                KeyError::KeyNotFound("No credentials found in secure store.".to_string())
            }
            other => KeyError::KeyringError(other.to_string()),
        }
    }
}

impl From<hex::FromHexError> for KeyError {
    fn from(err: hex::FromHexError) -> Self {
        KeyError::ConversionError(err.to_string())
    }
}

impl From<hkdf::InvalidLength> for KeyError {
    fn from(_err: hkdf::InvalidLength) -> Self {
        KeyError::HkdfError
    }
}

impl From<Box<bincode::ErrorKind>> for KeyError {
    fn from(err: Box<bincode::ErrorKind>) -> Self {
        KeyError::SerializationError(err.to_string())
    }
}

/// Result type for runar-keys operations
pub type Result<T> = std::result::Result<T, KeyError>;
