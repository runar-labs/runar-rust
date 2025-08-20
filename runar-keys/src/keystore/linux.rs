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
            Ok(secret) => Self::decode_key_from_b64(secret.as_bytes()),
            Err(e) => {
                // Deterministic behavior by default: do not fallback silently.
                // For CI/dev environments without org.freedesktop.secrets, opt-in fallback via env var:
                //   RUNAR_KEYS_LINUX_FILE_KEYSTORE=1
                let msg = format!("{e}");
                let allow_file = std::env::var("RUNAR_KEYS_LINUX_FILE_KEYSTORE")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                if (msg.contains("org.freedesktop.secrets") || msg.contains("ServiceUnknown"))
                    && allow_file
                {
                    return self.get_or_create_aes_key_file();
                }
                // Otherwise, attempt to create in keyring; do not fallback unless env allows
                let mut key = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut key);
                let engine = base64::engine::general_purpose::STANDARD;
                let b64 = engine.encode(key);
                match entry.set_password(&b64) {
                    Ok(()) => Ok(key.to_vec()),
                    Err(e2) => {
                        if allow_file {
                            return self.get_or_create_aes_key_file();
                        }
                        Err(KeyError::InvalidOperation(format!(
                            "Platform secure storage failure: {e2}"
                        )))
                    }
                }
            }
        }
    }

    #[cfg(feature = "linux-keystore")]
    fn decode_key_from_b64(bytes: &[u8]) -> Result<Vec<u8>> {
        let engine = base64::engine::general_purpose::STANDARD;
        let decoded = engine
            .decode(bytes)
            .map_err(|e| KeyError::InvalidOperation(format!("decode key: {e}")))?;
        if decoded.len() != 32 {
            return Err(KeyError::InvalidOperation("stored key wrong length".into()));
        }
        Ok(decoded)
    }

    #[cfg(feature = "linux-keystore")]
    fn get_or_create_aes_key_file(&self) -> Result<Vec<u8>> {
        use std::fs;
        use std::io::Write;
        use std::path::PathBuf;

        let base: PathBuf = if let Ok(p) = std::env::var("XDG_CACHE_HOME") {
            PathBuf::from(p)
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".cache")
        } else {
            PathBuf::from("/tmp")
        };
        let safe_service = Self::sanitize_component(&self.service);
        let safe_account = Self::sanitize_component(&self.account);
        let dir = base.join("runar_keys").join(safe_service);
        let path = dir.join(format!("{safe_account}.key"));

        if let Ok(b) = fs::read(&path) {
            return Self::decode_key_from_b64(&b);
        }

        fs::create_dir_all(&dir)
            .map_err(|e| KeyError::InvalidOperation(format!("create dir: {e}")))?;
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let engine = base64::engine::general_purpose::STANDARD;
        let b64 = engine.encode(key);
        let tmp = path.with_extension("key.tmp");
        {
            let mut f = fs::File::create(&tmp)
                .map_err(|e| KeyError::InvalidOperation(format!("create key file: {e}")))?;
            f.write_all(b64.as_bytes())
                .map_err(|e| KeyError::InvalidOperation(format!("write key file: {e}")))?;
            f.sync_all()
                .map_err(|e| KeyError::InvalidOperation(format!("sync key file: {e}")))?;
        }
        fs::rename(&tmp, &path)
            .map_err(|e| KeyError::InvalidOperation(format!("rename key file: {e}")))?;
        Ok(key.to_vec())
    }

    #[cfg(feature = "linux-keystore")]
    fn sanitize_component(s: &str) -> String {
        s.chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect()
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
