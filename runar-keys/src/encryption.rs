//! Symmetric encryption helpers and shared-key derivation.
//!
//! Intention:
//! * Encrypt/decrypt node data with AES-GCM-256 using a key derived from `NodeKey`.
//! * Derive shared symmetric keys (user↔node, user↔network) via HKDF on a
//!   concatenation of a private Ed25519 scalar and the counter-party public key.

use crate::error::Result;
use crate::types::{current_unix_timestamp, NetworkKey, NodeKey, SharedKey, UserProfileKey};
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ed25519_dalek::SECRET_KEY_LENGTH;
use hkdf::Hkdf;
use sha2::Sha256;

pub const SYMMETRIC_KEY_LEN: usize = 32;

/* -------------------------------------------------------------------------
 * Symmetric key derivation from a private key (NodeKey scenario)
 * ---------------------------------------------------------------------- */

pub fn derive_symmetric_key_from_node(
    node: &NodeKey,
    context: &[u8],
) -> Result<[u8; SYMMETRIC_KEY_LEN]> {
    let ikm = &node.keypair.to_keypair_bytes()[..SECRET_KEY_LENGTH];
    hkdf_derive(ikm, context)
}

/* -------------------------------------------------------------------------
 * Shared-key derivation (ECDH-like) – simple concat then HKDF.
 * For real-world deployments X25519 should be preferred, but Ed25519 secret is
 * usable for HKDF-based KDF as an interim approach.
 * ---------------------------------------------------------------------- */

pub fn derive_node_shared_key(
    profile: &UserProfileKey,
    node: &NodeKey,
    expires_secs: u64,
) -> Result<SharedKey> {
    let ikm = [
        profile.keypair.to_keypair_bytes()[..SECRET_KEY_LENGTH].as_ref(),
        node.verifying_key().as_bytes(),
    ]
    .concat();
    let key = hkdf_derive(&ikm, b"runar_node_shared")?;
    Ok(SharedKey::new(
        key,
        Some(current_unix_timestamp() + expires_secs),
    ))
}

pub fn derive_network_shared_key(
    profile: &UserProfileKey,
    network: &NetworkKey,
    expires_secs: u64,
) -> Result<SharedKey> {
    let ikm = [
        profile.keypair.to_keypair_bytes()[..SECRET_KEY_LENGTH].as_ref(),
        network.public_key().as_bytes(),
    ]
    .concat();
    let key = hkdf_derive(&ikm, b"runar_network_shared")?;
    Ok(SharedKey::new(
        key,
        Some(current_unix_timestamp() + expires_secs),
    ))
}

/* -------------------------------------------------------------------------
 * Encrypt / Decrypt helpers
 * ---------------------------------------------------------------------- */

pub fn encrypt(
    key: &[u8; SYMMETRIC_KEY_LEN],
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Result<(Vec<u8>, [u8; 12])> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| crate::error::KeyError::CryptoError(format!("AES init failed: {e}")))?;
    let nonce: [u8; 12] = Aes256Gcm::generate_nonce(&mut OsRng).into();
    let ciphertext = match aad {
        Some(a) => cipher.encrypt(
            &nonce.into(),
            Payload {
                msg: plaintext,
                aad: a,
            },
        )?,
        None => cipher.encrypt(&nonce.into(), plaintext.as_ref())?,
    };
    Ok((ciphertext, nonce))
}

pub fn decrypt(
    key: &[u8; SYMMETRIC_KEY_LEN],
    ciphertext: &[u8],
    nonce: &[u8; 12],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| crate::error::KeyError::CryptoError(format!("AES init failed: {e}")))?;
    let nonce_ref: &Nonce<aes_gcm::aead::generic_array::typenum::U12> = nonce.into();
    let plain = match aad {
        Some(a) => cipher.decrypt(
            nonce_ref,
            Payload {
                msg: ciphertext,
                aad: a,
            },
        )?,
        None => cipher.decrypt(nonce_ref, ciphertext.as_ref())?,
    };
    Ok(plain)
}

/* ------------------------------------------------------------------------- */

fn hkdf_derive(ikm: &[u8], info: &[u8]) -> Result<[u8; SYMMETRIC_KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; SYMMETRIC_KEY_LEN];
    hk.expand(info, &mut okm)?;
    Ok(okm)
}
