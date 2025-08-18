#![cfg(feature = "pure-x509")]

use crate::certificate::{EcdsaKeyPair, X509Certificate};
use crate::error::{KeyError, Result};

pub fn create_self_signed_ca(
    _key_pair: &EcdsaKeyPair,
    _subject_str: &str,
) -> Result<X509Certificate> {
    Err(KeyError::UnsupportedAlgorithm(
        "pure-x509 issuance not implemented yet".to_string(),
    ))
}

pub fn sign_csr_with_ca(
    _ca_key_pair: &EcdsaKeyPair,
    _ca_subject_str: &str,
    _csr_der: &[u8],
    _validity_days: u32,
    _serial_override: Option<u64>,
) -> Result<X509Certificate> {
    Err(KeyError::UnsupportedAlgorithm(
        "pure-x509 issuance not implemented yet".to_string(),
    ))
}
