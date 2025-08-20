//! Device keystore abstraction for on-device encrypted persistence.
//!
//! Backends:
//! - Apple (macOS/iOS) using Keychain/Secure Enclave when feature `apple-keystore` is enabled.

use crate::error::Result;

#[derive(Debug, Clone, Copy, Default)]
pub struct DeviceKeystoreCaps {
    pub version: u32,              // struct version; start at 1
    pub hardware_backed: bool,     // true when Secure Enclave/TEE is used
    pub biometric_gate: bool,      // true when FaceID/TouchID gating is configured
    pub screenlock_required: bool, // true when device passcode required
    pub strongbox: bool,           // Android strongbox; always false on Apple
}

pub trait DeviceKeystore: Send + Sync {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
    fn capabilities(&self) -> DeviceKeystoreCaps;
}

#[cfg(all(feature = "apple-keystore", any(target_os = "macos", target_os = "ios")))]
pub mod apple;

pub mod persistence;

#[cfg(all(feature = "linux-keystore", target_os = "linux"))]
pub mod linux;

// Shared AES-GCM helpers used by all backends after obtaining the symmetric key
const VERSION_BYTE: u8 = 1;

pub(crate) fn aes_gcm_encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> crate::error::Result<Vec<u8>> {
    use aes_gcm::{aead::Aead, aead::KeyInit, Aes256Gcm, Nonce};
    use rand::RngCore;
    use crate::error::{KeyError, Result};

    if key.len() != 32 {
        return Err(KeyError::SymmetricCipherError("AES-256-GCM requires 32-byte key".to_string()));
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

pub(crate) fn aes_gcm_decrypt(key: &[u8], ciphertext: &[u8], aad: &[u8]) -> crate::error::Result<Vec<u8>> {
    use aes_gcm::{aead::Aead, aead::KeyInit, Aes256Gcm, Nonce, Tag};
    use crate::error::{KeyError, Result};
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
