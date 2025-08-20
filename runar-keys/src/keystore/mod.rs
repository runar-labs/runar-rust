//! Device keystore abstraction for on-device encrypted persistence.
//!
//! Backends:
//! - Apple (macOS/iOS) using Keychain/Secure Enclave when feature `apple-keystore` is enabled.

use crate::error::Result;

#[derive(Debug, Clone, Copy, Default)]
pub struct DeviceKeystoreCaps {
    pub version: u32,           // struct version; start at 1
    pub hardware_backed: bool,  // true when Secure Enclave/TEE is used
    pub biometric_gate: bool,   // true when FaceID/TouchID gating is configured
    pub screenlock_required: bool, // true when device passcode required
    pub strongbox: bool,        // Android strongbox; always false on Apple
}

pub trait DeviceKeystore: Send + Sync {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
    fn capabilities(&self) -> DeviceKeystoreCaps;
}

#[cfg(feature = "apple-keystore")]
pub mod apple;

pub mod persistence;

