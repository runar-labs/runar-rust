//! HD derivation helpers using `ed25519_hd_key`.
//!
//! Path conventions come from the specification.

use crate::error::Result;
use crate::types::{NetworkKey, NodeKey, UserMasterKey, UserProfileKey};
use ed25519_dalek::SigningKey;
use ed25519_hd_key;

/// Derive a network `SigningKey` from master.
pub fn derive_network_key(master: &UserMasterKey, index: u32) -> Result<NetworkKey> {
    let path = format!("m/44'/0'/{}'", index);
    derive_signing_key(master, &path).map(NetworkKey::from)
}

/// Derive a node `SigningKey` from master.
pub fn derive_node_key(master: &UserMasterKey, index: u32) -> Result<NodeKey> {
    let path = format!("m/44'/0'/{}'", index);
    derive_signing_key(master, &path).map(NodeKey::from)
}

/// Derive a user profile key.
pub fn derive_profile_key(master: &UserMasterKey, index: u32) -> Result<UserProfileKey> {
    let path = format!("m/44'/1'/{}'", index);
    derive_signing_key(master, &path).map(UserProfileKey::from_signing_key)
}

/* ------------------------------------------------------------------------- */

fn derive_signing_key(master: &UserMasterKey, path: &str) -> Result<SigningKey> {
    // `derive_from_path` returns (key_bytes, chain_code)
    let (key_bytes, _cc) = ed25519_hd_key::derive_from_path(path, master.as_bytes());
    Ok(SigningKey::from_bytes(&key_bytes))
}

/* ------------------------------ Conversions ------------------------------ */

impl From<SigningKey> for NetworkKey {
    fn from(k: SigningKey) -> Self {
        NetworkKey::from_signing_key(k)
    }
}

impl NetworkKey {
    pub(crate) fn from_signing_key(k: SigningKey) -> Self {
        let id = crate::types::NetworkId::new(*k.verifying_key().as_bytes());
        Self { keypair: k, id }
    }
}

impl From<SigningKey> for NodeKey {
    fn from(k: SigningKey) -> Self {
        NodeKey { keypair: k }
    }
}

impl UserProfileKey {
    pub(crate) fn from_signing_key(k: SigningKey) -> Self {
        let peer_id = crate::types::PeerId::from_public_key(&k.verifying_key()).unwrap();
        Self { keypair: k, peer_id }
    }
}
