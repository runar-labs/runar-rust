//! Error types for the certificate system

use thiserror::Error;

/// Result type alias for certificate operations
pub type Result<T> = std::result::Result<T, KeyError>;

/// Comprehensive error types for certificate operations
#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Certificate error: {0}")]
    CertificateError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("Signing error: {0}")]
    SigningError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("PKCS8 error: {0}")]
    Pkcs8Error(#[from] pkcs8::Error),

    #[error("ECDSA error: {0}")]
    EcdsaError(#[from] p256::ecdsa::Error),

    #[error("OpenSSL error: {0}")]
    OpenSslError(#[from] openssl::error::ErrorStack),

    #[error("X509 parser error: {0}")]
    X509ParserError(String),

    #[error("Certificate validation error: {0}")]
    CertificateValidationError(String),

    #[error("Chain validation error: {0}")]
    ChainValidationError(String),

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Certificate not found: {0}")]
    CertificateNotFound(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Key derivation error: {0}")]
    KeyDerivationError(String),

    #[error("ECDH error: {0}")]
    EcdhError(String),

    #[error("Symmetric cipher error: {0}")]
    SymmetricCipherError(String),
}

// Convert from rcgen errors
impl From<rcgen::Error> for KeyError {
    fn from(err: rcgen::Error) -> Self {
        KeyError::CertificateError(err.to_string())
    }
}

// Convert from x509-parser errors
impl From<x509_parser::error::X509Error> for KeyError {
    fn from(err: x509_parser::error::X509Error) -> Self {
        KeyError::X509ParserError(err.to_string())
    }
}

impl From<x509_parser::nom::Err<x509_parser::error::X509Error>> for KeyError {
    fn from(err: x509_parser::nom::Err<x509_parser::error::X509Error>) -> Self {
        KeyError::X509ParserError(format!("Parse error: {}", err))
    }
}
