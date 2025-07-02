use crate::compact_ids;
use crate::mobile::{EnvelopeEncryptedData, MobileKeyManager};
use crate::node::NodeKeyManager;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Common envelope structs (moved from runar-serializer)
// ---------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedKey {
    pub public_key: Vec<u8>,
    pub encrypted_envelope_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedEnvelope {
    pub encrypted_data: Vec<u8>,
    pub encrypted_keys: Vec<EncryptedKey>,
    pub nonce: Vec<u8>,
    pub algorithm: String,
}

// ---------------------------------------------------------------------------
// KeyStore trait
// ---------------------------------------------------------------------------
/// Abstraction over a key manager that can perform envelope encryption /
/// decryption for arbitrary recipient public-keys.
pub trait KeyStore: Send + Sync {
    fn encrypt_with_envelope(&self, data: &[u8], public_key: &[u8]) -> Result<EncryptedEnvelope>;
    fn decrypt_envelope_data(&self, envelope: &EncryptedEnvelope) -> Result<Vec<u8>>;
    fn can_decrypt_for_key(&self, public_key: &[u8]) -> bool;
    fn available_public_keys(&self) -> Vec<Vec<u8>>;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------
// Convert between rich EnvelopeEncryptedData and lightweight EncryptedEnvelope
fn to_encrypted_envelope(env: &EnvelopeEncryptedData) -> Result<EncryptedEnvelope> {
    // Build key list
    let mut keys = Vec::new();
    // Network key
    let network_pub = compact_ids::public_key_from_compact_id(&env.network_id)?;
    keys.push(EncryptedKey {
        public_key: network_pub,
        encrypted_envelope_key: env.network_encrypted_key.clone(),
    });
    // Profile keys
    for (pid, enc_key) in &env.profile_encrypted_keys {
        keys.push(EncryptedKey {
            public_key: pid.as_bytes().to_vec(),
            encrypted_envelope_key: enc_key.clone(),
        });
    }
    Ok(EncryptedEnvelope {
        encrypted_data: bincode::serialize(env)?,
        encrypted_keys: keys,
        nonce: Vec::new(),
        algorithm: "runar-keys-envelope-v1".to_string(),
    })
}

fn from_encrypted_envelope(env: &EncryptedEnvelope) -> Result<EnvelopeEncryptedData> {
    bincode::deserialize::<EnvelopeEncryptedData>(&env.encrypted_data)
        .map_err(|e| anyhow!(format!("Failed to deserialize envelope: {e}")))
}

// ---------------------------------------------------------------------------
// KeyStore impl for MobileKeyManager
// ---------------------------------------------------------------------------
impl KeyStore for MobileKeyManager {
    fn encrypt_with_envelope(&self, data: &[u8], public_key: &[u8]) -> Result<EncryptedEnvelope> {
        let env = MobileKeyManager::encrypt_for_public_key(self, data, public_key)?;
        to_encrypted_envelope(&env)
    }

    fn decrypt_envelope_data(&self, envelope: &EncryptedEnvelope) -> Result<Vec<u8>> {
        let env = from_encrypted_envelope(envelope)?;
        // Try profile keys first
        for pid in env.profile_encrypted_keys.keys() {
            if let Ok(pt) = self.decrypt_with_profile(&env, pid) {
                return Ok(pt);
            }
        }
        Ok(self.decrypt_with_network(&env)?)
    }

    fn can_decrypt_for_key(&self, public_key: &[u8]) -> bool {
        MobileKeyManager::has_public_key(self, public_key)
    }

    fn available_public_keys(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// KeyStore impl for NodeKeyManager
// ---------------------------------------------------------------------------
impl KeyStore for NodeKeyManager {
    fn encrypt_with_envelope(&self, data: &[u8], public_key: &[u8]) -> Result<EncryptedEnvelope> {
        let env = NodeKeyManager::encrypt_for_public_key(self, data, public_key)?;
        to_encrypted_envelope(&env)
    }

    fn decrypt_envelope_data(&self, envelope: &EncryptedEnvelope) -> Result<Vec<u8>> {
        let env = from_encrypted_envelope(envelope)?;
        Ok(self.decrypt_envelope_data(&env)?)
    }

    fn can_decrypt_for_key(&self, public_key: &[u8]) -> bool {
        NodeKeyManager::has_public_key(self, public_key)
    }

    fn available_public_keys(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }
}
