//! Core types and utilities for Runar Keys.
//!
//! Intention: Provide strongly-typed wrappers over raw Ed25519 keys and identifiers
//! while hiding secret material behind safe abstractions.

use crate::error::{KeyError, Result};
use ed25519_dalek::{
    self as dalek, Signer, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
};
use rand::{rngs::OsRng, RngCore};
use std::time::{SystemTime, UNIX_EPOCH};

/* ------------------------------ User Master ------------------------------ */

pub const USER_MASTER_KEY_SEED_LEN: usize = SECRET_KEY_LENGTH; // 32 bytes

#[derive(Clone)]
pub struct UserMasterKey {
    seed: [u8; USER_MASTER_KEY_SEED_LEN],
}

impl UserMasterKey {
    pub fn new(seed: [u8; USER_MASTER_KEY_SEED_LEN]) -> Self {
        Self { seed }
    }

    pub fn generate() -> Self {
        let mut seed = [0u8; USER_MASTER_KEY_SEED_LEN];
        OsRng.fill_bytes(&mut seed);
        Self { seed }
    }

    pub fn as_bytes(&self) -> &[u8; USER_MASTER_KEY_SEED_LEN] {
        &self.seed
    }
}

/* ------------------------------ Network Id ------------------------------- */

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct NetworkId([u8; PUBLIC_KEY_LENGTH]);

impl NetworkId {
    pub fn new(bytes: [u8; PUBLIC_KEY_LENGTH]) -> Self {
        Self(bytes)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)?;
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(KeyError::SerializationError(
                "Invalid NetworkId length".into(),
            ));
        }
        let mut arr = [0u8; PUBLIC_KEY_LENGTH];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.0
    }

    /// Recreate a Dalek `VerifyingKey` from the stored bytes.
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&self.0).map_err(|e| KeyError::SerializationError(e.to_string()))
    }
}

/* ------------------------------ Peer / Profile --------------------------- */

/// `PeerId` === public key of a `UserProfileKey`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct PeerId(pub [u8; PUBLIC_KEY_LENGTH]);

impl PeerId {
    pub fn from_public_key(pk: &VerifyingKey) -> Result<Self> {
        Ok(Self(*pk.as_bytes()))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

#[derive(Clone)]
pub struct UserProfileKey {
    pub(crate) keypair: SigningKey,
    pub(crate) peer_id: PeerId,
}

impl UserProfileKey {
    pub fn new_random() -> Self {
        let kp = SigningKey::generate(&mut OsRng);
        let peer_id = PeerId::from_public_key(&kp.verifying_key()).unwrap();
        Self {
            keypair: kp,
            peer_id,
        }
    }

    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    pub fn sign(&self, msg: &[u8]) -> dalek::Signature {
        self.keypair.sign(msg)
    }

    pub fn verify(&self, msg: &[u8], sig: &dalek::Signature) -> Result<()> {
        self.keypair.verifying_key().verify_strict(msg, sig)?;
        Ok(())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.keypair.verifying_key()
    }
}

/* ------------------------------ Network Key ------------------------------ */

#[derive(Clone)]
pub struct NetworkKey {
    pub keypair: SigningKey,
    pub(crate) id: NetworkId,
}

impl NetworkKey {
    pub fn new_random() -> Self {
        let kp = SigningKey::generate(&mut OsRng);
        let id = NetworkId::new(*kp.verifying_key().as_bytes());
        Self { keypair: kp, id }
    }

    pub fn id(&self) -> &NetworkId {
        &self.id
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.keypair.verifying_key()
    }

    pub fn sign(&self, msg: &[u8]) -> dalek::Signature {
        self.keypair.sign(msg)
    }

    pub fn verify(&self, msg: &[u8], sig: &dalek::Signature) -> Result<()> {
        self.public_key().verify_strict(msg, sig)?;
        Ok(())
    }
}

/* ------------------------------ Node Key --------------------------------- */

#[derive(Clone)]
pub struct NodeKey {
    pub(crate) keypair: SigningKey,
}

impl NodeKey {
    pub fn new_random() -> Self {
        Self {
            keypair: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> dalek::Signature {
        self.keypair.sign(msg)
    }

    pub fn verify(&self, msg: &[u8], sig: &dalek::Signature) -> Result<()> {
        self.keypair.verifying_key().verify_strict(msg, sig)?;
        Ok(())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.keypair.verifying_key()
    }
}

/* ------------------------------ SharedKey ------------------------------- */

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedKey {
    key: [u8; 32],
    expires_at: Option<u64>,
}

impl SharedKey {
    pub fn new(key: [u8; 32], expires_at: Option<u64>) -> Self {
        Self { key, expires_at }
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(ts) => current_unix_timestamp() > ts,
            None => false,
        }
    }
}

/* ------------------------------ Time util -------------------------------- */

pub fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
