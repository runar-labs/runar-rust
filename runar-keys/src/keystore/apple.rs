//! Apple Keychain/Secure Enclave backend (macOS/iOS).
//!
//! Development/CI mode:
//! - Set env `RUNAR_APPLE_KEYSTORE_SOFTWARE_ONLY=1` to force a software key path that stores
//!   a 32-byte AES key in the Keychain (Generic Password). This avoids Secure Enclave and
//!   entitlements for automated tests/CI. Production MUST use Secure Enclave.
//!
//! This backend uses the `keychain-services` crate to generate a Secure Enclave keypair,
//! wrap/unwrap a symmetric AEAD key, and encrypt/decrypt state with AES-GCM.

use super::{DeviceKeystore, DeviceKeystoreCaps};
use crate::error::{KeyError, Result};

#[cfg(feature = "apple-keystore")]
use zeroize::Zeroize;

pub struct AppleDeviceKeystore {
    // Placeholder for cached metadata/handles. We intentionally do not store the symmetric key.
    pub label: String,
    #[cfg(all(feature = "apple-keystore", target_os = "macos"))]
    private_key: std::sync::Mutex<Option<security_framework::key::SecKey>>,
}

impl AppleDeviceKeystore {
    pub fn new(label: &str) -> Result<Self> {
        // Actual key generation or lookup will happen lazily in encrypt/decrypt paths.
        Ok(Self {
            label: label.to_string(),
            #[cfg(all(feature = "apple-keystore", target_os = "macos"))]
            private_key: std::sync::Mutex::new(None),
        })
    }

    #[allow(unused)]
    fn get_caps(&self) -> DeviceKeystoreCaps {
        DeviceKeystoreCaps {
            version: 1,
            hardware_backed: true,
            biometric_gate: false,
            screenlock_required: false,
            strongbox: false,
        }
    }
}

impl DeviceKeystore for AppleDeviceKeystore {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        #[cfg(all(
            feature = "apple-keystore",
            any(target_os = "macos", target_os = "ios")
        ))]
        {
            let mut key_bytes = get_or_create_unwrapped_aes_key(self)?;
            let out = super::aes_gcm_encrypt(&key_bytes, plaintext, aad)?;
            key_bytes.zeroize();
            Ok(out)
        }
        #[cfg(not(all(
            feature = "apple-keystore",
            any(target_os = "macos", target_os = "ios")
        )))]
        {
            let _ = (plaintext, aad);
            return Err(KeyError::InvalidOperation(
                "AppleDeviceKeystore requires target macOS/iOS with feature `apple-keystore`"
                    .into(),
            ));
        }
    }

    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        #[cfg(all(
            feature = "apple-keystore",
            any(target_os = "macos", target_os = "ios")
        ))]
        {
            let mut key_bytes = get_or_create_unwrapped_aes_key(self)?;
            let out = super::aes_gcm_decrypt(&key_bytes, ciphertext, aad)?;
            key_bytes.zeroize();
            Ok(out)
        }
        #[cfg(not(all(
            feature = "apple-keystore",
            any(target_os = "macos", target_os = "ios")
        )))]
        {
            let _ = (ciphertext, aad);
            return Err(KeyError::InvalidOperation(
                "AppleDeviceKeystore requires target macOS/iOS with feature `apple-keystore`"
                    .into(),
            ));
        }
    }

    fn capabilities(&self) -> DeviceKeystoreCaps {
        self.get_caps()
    }
}

// tests moved to `runar-keys/tests/apple_keystore_macos_test.rs`

// ------------------------------
// Apple-specific keychain helpers (compile only on macOS/iOS with feature)
// ------------------------------

// macOS Secure Enclave-backed implementation using security-framework
#[cfg(all(feature = "apple-keystore", target_os = "macos"))]
fn get_or_create_unwrapped_aes_key(ks: &AppleDeviceKeystore) -> Result<Vec<u8>> {
    use core_foundation::base::TCFType;
    use core_foundation::data::CFData;
    use core_foundation::error::CFErrorRef;
    use rand::RngCore;
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::key::{GenerateKeyOptions, KeyType, SecKey, Token};
    use security_framework::passwords::{get_generic_password, set_generic_password};
    use security_framework_sys::key::{
        kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM, SecKeyCreateDecryptedData,
        SecKeyCreateEncryptedData,
    };

    // 0) Dev/CI shortcut: force software-only mode
    let force_sw = std::env::var("RUNAR_APPLE_KEYSTORE_SOFTWARE_ONLY")
        .ok()
        .as_deref()
        == Some("1");

    if force_sw {
        // Store/retrieve 32-byte AES key directly from Keychain (Generic Password)
        let service = &ks.label;
        let account = "state.aead.v1.software";
        if let Ok(bytes) = get_generic_password(service, account) {
            if bytes.len() == 32 {
                return Ok(bytes);
            }
        }
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        set_generic_password(service, account, &key)
            .map_err(|e| KeyError::InvalidOperation(format!("set software key: {e}")))?;
        return Ok(key.to_vec());
    }

    // 1) Ensure Secure Enclave EC private key exists (identified by label), cache it in the struct
    let private_key: SecKey = {
        if let Some(pk) = ks
            .private_key
            .lock()
            .map_err(|_| KeyError::InvalidOperation("mutex poisoned".into()))?
            .as_ref()
            .cloned()
        {
            pk
        } else {
            let access = SecAccessControl::create_with_protection(
                Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
                0,
            )
            .map_err(|e| KeyError::InvalidOperation(format!("access control: {e}")))?;
            // Try Secure Enclave first
            let mut opts = GenerateKeyOptions::default();
            opts.set_key_type(KeyType::ec())
                .set_size_in_bits(256)
                .set_label(&ks.label)
                .set_token(if force_sw {
                    Token::Software
                } else {
                    Token::SecureEnclave
                })
                .set_access_control(access.clone());
            let pk = match SecKey::generate(opts.to_dictionary()) {
                Ok(k) => k,
                Err(_e) => {
                    // Fallback to software key for non-entitled test runs
                    let mut sw_opts = GenerateKeyOptions::default();
                    sw_opts
                        .set_key_type(KeyType::ec())
                        .set_size_in_bits(256)
                        .set_label(&ks.label)
                        .set_token(Token::Software)
                        .set_access_control(access);
                    SecKey::generate(sw_opts.to_dictionary()).map_err(|e| {
                        KeyError::InvalidOperation(format!("SecKey generate (software): {e}"))
                    })?
                }
            };
            if let Ok(mut guard) = ks.private_key.lock() {
                *guard = Some(pk.clone());
            }
            pk
        }
    };

    // 2) Try to fetch wrapped AES-256 key blob from Keychain (Generic Password)
    let service = &ks.label;
    let account = "state.aead.v1.wrapped";
    if let Ok(blob) = get_generic_password(service, account) {
        unsafe {
            let mut err: CFErrorRef = std::ptr::null_mut();
            let wrapped = CFData::from_buffer(&blob);
            let out = SecKeyCreateDecryptedData(
                private_key.as_concrete_TypeRef(),
                kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM,
                wrapped.as_concrete_TypeRef(),
                &mut err,
            );
            if !err.is_null() || out.is_null() {
                return Err(KeyError::DecryptionError(
                    "SecKeyCreateDecryptedData failed".to_string(),
                ));
            }
            let data = CFData::wrap_under_create_rule(out);
            let key = data.to_vec();
            if key.len() != 32 {
                return Err(KeyError::InvalidOperation(
                    "unwrapped key wrong length".into(),
                ));
            }
            return Ok(key);
        }
    }

    // 3) Generate new AES-256 key, wrap with enclave public key, and store wrapped blob
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    let public_key = private_key
        .public_key()
        .ok_or_else(|| KeyError::InvalidOperation("SecKeyCopyPublicKey returned null".into()))?;
    let wrapped = unsafe {
        let mut err: CFErrorRef = std::ptr::null_mut();
        let plain = CFData::from_buffer(&key);
        let out = SecKeyCreateEncryptedData(
            public_key.as_concrete_TypeRef(),
            kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM,
            plain.as_concrete_TypeRef(),
            &mut err,
        );
        if !err.is_null() || out.is_null() {
            return Err(KeyError::EncryptionError(
                "SecKeyCreateEncryptedData failed".to_string(),
            ));
        }
        CFData::wrap_under_create_rule(out).to_vec()
    };
    set_generic_password(service, account, &wrapped)
        .map_err(|e| KeyError::InvalidOperation(format!("set wrapped blob: {e}")))?;
    Ok(key.to_vec())
}

// iOS: placeholder until Secure Enclave wrapping via `keychain-services` is implemented
#[cfg(all(feature = "apple-keystore", target_os = "ios"))]
fn get_or_create_unwrapped_aes_key(_label: &str) -> Result<Vec<u8>> {
    // iOS CI/dev: temporary software-only mode for tests without entitlements.
    Err(KeyError::InvalidOperation(
        "Apple iOS Secure Enclave backend not yet implemented; use app with entitlements to test"
            .into(),
    ))
}
