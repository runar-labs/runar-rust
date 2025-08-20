//! Linux system keyring backend using the `keyring` crate.
//! Stores a 32-byte AES key in the session keyring and performs AEAD via `aes-gcm`.

use super::{DeviceKeystore, DeviceKeystoreCaps};
use crate::error::{KeyError, Result};

#[cfg(feature = "linux-keystore")]
use keyring::Entry;

#[cfg(feature = "linux-keystore")]
use base64::Engine;
#[cfg(feature = "linux-keystore")]
use rand::RngCore;
#[cfg(feature = "linux-keystore")]
use zeroize::Zeroize;

pub struct LinuxDeviceKeystore {
    service: String,
    account: String,
}

impl LinuxDeviceKeystore {
    pub fn new(service: &str, account: &str) -> Result<Self> {
        Ok(Self {
            service: service.to_string(),
            account: account.to_string(),
        })
    }

    #[cfg(feature = "linux-keystore")]
    fn get_or_create_aes_key(&self) -> Result<Vec<u8>> {
        let entry = Entry::new(&self.service, &self.account);
        match entry.get_password() {
            Ok(secret) => {
                // We store base64-encoded key material
                let engine = base64::engine::general_purpose::STANDARD;
                let bytes = engine
                    .decode(secret.as_bytes())
                    .map_err(|e| KeyError::InvalidOperation(format!("decode key: {e}")))?;
                if bytes.len() != 32 {
                    return Err(KeyError::InvalidOperation("stored key wrong length".into()));
                }
                Ok(bytes)
            }
            Err(_e) => {
                // Create new 32-byte key and store
                let mut key = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut key);
                let engine = base64::engine::general_purpose::STANDARD;
                let b64 = engine.encode(key);
                entry
                    .set_password(&b64)
                    .map_err(|e| KeyError::InvalidOperation(format!("set key: {e}")))?;
                Ok(key.to_vec())
            }
        }
    }
}

impl DeviceKeystore for LinuxDeviceKeystore {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "linux-keystore")]
        {
            let key = self.get_or_create_aes_key()?;
            let out = super::aes_gcm_encrypt(&key, plaintext, aad)?;
            let mut k = key;
            k.zeroize();
            Ok(out)
        }
        #[cfg(not(feature = "linux-keystore"))]
        {
            let _ = (plaintext, aad);
            Err(KeyError::InvalidOperation(
                "LinuxDeviceKeystore requires feature `linux-keystore`".into(),
            ))
        }
    }

    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "linux-keystore")]
        {
            let key = self.get_or_create_aes_key()?;
            let out = super::aes_gcm_decrypt(&key, ciphertext, aad)?;
            let mut k = key;
            k.zeroize();
            Ok(out)
        }
        #[cfg(not(feature = "linux-keystore"))]
        {
            let _ = (ciphertext, aad);
            Err(KeyError::InvalidOperation(
                "LinuxDeviceKeystore requires feature `linux-keystore`".into(),
            ))
        }
    }

    fn capabilities(&self) -> DeviceKeystoreCaps {
        DeviceKeystoreCaps {
            version: 1,
            hardware_backed: false,
            biometric_gate: false,
            screenlock_required: false,
            strongbox: false,
        }
    }
}
