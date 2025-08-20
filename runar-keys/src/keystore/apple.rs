//! Apple Keychain/Secure Enclave backend (macOS/iOS).
//!
//! This backend uses the `keychain-services` crate to generate a Secure Enclave keypair,
//! wrap/unwrap a symmetric AEAD key, and encrypt/decrypt state with AES-GCM.

use super::{DeviceKeystore, DeviceKeystoreCaps};
use crate::error::{KeyError, Result};

#[cfg(feature = "apple-keystore")]
use keychain_services as kc;

#[cfg(feature = "apple-keystore")]
use zeroize::Zeroize;

pub struct AppleDeviceKeystore {
    // Placeholder for cached metadata/handles. We intentionally do not store the symmetric key.
    pub label: String,
}

impl AppleDeviceKeystore {
    pub fn new(label: &str) -> Result<Self> {
        // Actual key generation or lookup will happen lazily in encrypt/decrypt paths.
        Ok(Self {
            label: label.to_string(),
        })
    }

    #[allow(unused)]
    fn get_caps(&self) -> DeviceKeystoreCaps {
        // TODO: query via SecKeyCopyAttributes and SecAccessControl; return accurate flags.
        DeviceKeystoreCaps {
            version: 1,
            hardware_backed: true,
            biometric_gate: false,
            screenlock_required: true,
            strongbox: false,
        }
    }
}

impl DeviceKeystore for AppleDeviceKeystore {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        // TODO: Generate or fetch AES-256 key, wrap with Secure Enclave public key if not present,
        // store wrapped blob in Keychain, then use AES-GCM to encrypt (nonce || tag || ciphertext).
        // For now, return an explicit error to ensure we don't accidentally ship a stub.
        let _ = (plaintext, aad);
        Err(KeyError::InvalidOperation(
            "AppleDeviceKeystore::encrypt not yet implemented".into(),
        ))
    }

    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        // TODO: Fetch wrapped blob from Keychain, unwrap with Secure Enclave private key (user presence
        // may be required), then AES-GCM decrypt.
        let _ = (ciphertext, aad);
        Err(KeyError::InvalidOperation(
            "AppleDeviceKeystore::decrypt not yet implemented".into(),
        ))
    }

    fn capabilities(&self) -> DeviceKeystoreCaps {
        self.get_caps()
    }
}
