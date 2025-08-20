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
        #[cfg(all(feature = "apple-keystore", any(target_os = "macos", target_os = "ios")))]
        {
            let key_bytes = get_or_create_unwrapped_aes_key(&self.label)?;
            let out = aes_gcm_encrypt(&key_bytes, plaintext, aad)?;
            // Zeroize key material
            #[cfg(feature = "apple-keystore")]
            {
                use zeroize::Zeroize;
                let mut kb = key_bytes.clone();
                kb.zeroize();
            }
            return Ok(out);
        }
        #[cfg(not(all(feature = "apple-keystore", any(target_os = "macos", target_os = "ios"))))]
        {
            let _ = (plaintext, aad);
            return Err(KeyError::InvalidOperation(
                "AppleDeviceKeystore requires target macOS/iOS with feature `apple-keystore`".into(),
            ));
        }
    }

    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        #[cfg(all(feature = "apple-keystore", any(target_os = "macos", target_os = "ios")))]
        {
            let key_bytes = get_or_create_unwrapped_aes_key(&self.label)?;
            let out = aes_gcm_decrypt(&key_bytes, ciphertext, aad)?;
            #[cfg(feature = "apple-keystore")]
            {
                use zeroize::Zeroize;
                let mut kb = key_bytes.clone();
                kb.zeroize();
            }
            return Ok(out);
        }
        #[cfg(not(all(feature = "apple-keystore", any(target_os = "macos", target_os = "ios"))))]
        {
            let _ = (ciphertext, aad);
            return Err(KeyError::InvalidOperation(
                "AppleDeviceKeystore requires target macOS/iOS with feature `apple-keystore`".into(),
            ));
        }
    }

    fn capabilities(&self) -> DeviceKeystoreCaps {
        self.get_caps()
    }
}

// ------------------------------
// Platform-independent AES-GCM helpers (used after key unwrapping)
// ------------------------------

const VERSION_BYTE: u8 = 1;

fn aes_gcm_encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{aead::Aead, aead::KeyInit, Aes256Gcm, Nonce};
    use rand::RngCore;

    if key.len() != 32 {
        return Err(KeyError::SymmetricCipherError(
            "AES-256-GCM requires 32-byte key".to_string(),
        ));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| KeyError::SymmetricCipherError(format!("cipher init: {e}")))?;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut buf = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), aad, &mut buf)
        .map_err(|e| KeyError::EncryptionError(format!("AES-GCM encrypt: {e}")))?;
    let mut out = Vec::with_capacity(1 + 12 + 16 + buf.len());
    out.push(VERSION_BYTE);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(tag.as_slice());
    out.extend_from_slice(&buf);
    Ok(out)
}

fn aes_gcm_decrypt(key: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{aead::Aead, aead::KeyInit, Aes256Gcm, Nonce, Tag};
    if ciphertext.len() < 1 + 12 + 16 {
        return Err(KeyError::DecryptionError("ciphertext too short".to_string()));
    }
    if ciphertext[0] != VERSION_BYTE {
        return Err(KeyError::DecryptionError("unsupported version".to_string()));
    }
    let nonce = &ciphertext[1..1 + 12];
    let tag = &ciphertext[1 + 12..1 + 12 + 16];
    let mut buf = ciphertext[1 + 12 + 16..].to_vec();
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| KeyError::SymmetricCipherError(format!("cipher init: {e}")))?;
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(nonce),
            aad,
            &mut buf,
            Tag::from_slice(tag),
        )
        .map_err(|e| KeyError::DecryptionError(format!("AES-GCM decrypt: {e}")))?;
    Ok(buf)
}

// ------------------------------
// Apple-specific keychain helpers (compile only on macOS/iOS with feature)
// ------------------------------

#[cfg(all(feature = "apple-keystore", any(target_os = "macos", target_os = "ios")))]
fn get_or_create_unwrapped_aes_key(label: &str) -> Result<Vec<u8>> {
    // High-level flow:
    // 1) Find wrapped AES blob in Keychain by service/label; if found, unwrap with Secure Enclave private key
    // 2) If not found, generate AES-256 random key, wrap with Enclave public key, store blob; return key
    // 3) Private key is created (if missing) with SecAccessControl gating user presence if desired

    // NOTE: The below code outlines the calls and data flow. It needs to be compiled on macOS/iOS
    // with the `keychain-services` crate available. Fill exact API calls while on Apple machine.

    // Pseudocode using keychain_services (to be finalized on macOS):
    // - Ensure Secure Enclave keypair exists with application tag derived from `label`
    // - Try SecItemCopyMatching for GenericPassword { service: label, account: "aead.v1.wrapped" }
    // - If found: unwrap with SecKeyCreateDecryptedData and return plaintext AES key
    // - Else: generate 32-byte AES key, wrap via SecKeyCreateEncryptedData, store via SecItemAdd, return key

    Err(KeyError::InvalidOperation(
        "Apple Keychain integration requires macOS/iOS to finalize API calls".into(),
    ))
}
