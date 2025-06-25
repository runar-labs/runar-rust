use crate::crypto::{
    EncryptionKeyPair, CHACHA20POLY1305_KEY_LENGTH as SYMMETRIC_KEY_LENGTH,
    CHACHA20POLY1305_NONCE_LENGTH as NONCE_LENGTH,
};
use crate::error::{KeyError, Result};
use aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

/// Represents an encrypted key for a recipient
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecipientKey {
    /// Identifier for the recipient (e.g., user profile ID or network ID)
    pub recipient_public_key: Vec<u8>,
    /// Encrypted envelope key (nonce || ciphertext)
    pub encrypted_key: Vec<u8>,
}

/// Represents an encrypted envelope containing data and keys for recipients
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Envelope {
    /// Ephemeral public key used for key agreement
    pub ephemeral_public_key: Vec<u8>,
    /// Encrypted data
    pub encrypted_data: Vec<u8>,
    /// Nonce used for data encryption
    pub data_nonce: [u8; NONCE_LENGTH],
    /// List of recipient keys
    pub recipient_keys: Vec<RecipientKey>,
}

impl Envelope {
    /// Create a new envelope by encrypting data for multiple recipients
    pub fn new<T: AsRef<[u8]>>(data: T, recipients: &[&EncryptionKeyPair]) -> Result<Self> {
        // 1. Generate a master key for this envelope
        let mut envelope_key = [0u8; SYMMETRIC_KEY_LENGTH];
        rand::thread_rng().fill_bytes(&mut envelope_key);

        // 2. Encrypt the data with the envelope key
        let cipher = ChaCha20Poly1305::new(&envelope_key.into());
        let mut data_nonce_bytes = [0u8; NONCE_LENGTH];
        rand::thread_rng().fill_bytes(&mut data_nonce_bytes);
        let nonce = Nonce::from_slice(&data_nonce_bytes);
        let encrypted_data = cipher
            .encrypt(nonce, data.as_ref())
            .map_err(|e| KeyError::CryptoError(e.to_string()))?;

        // 3. Generate an ephemeral key pair for this encryption session
        let ephemeral_key = EncryptionKeyPair::new();
        let ephemeral_public_key_bytes = ephemeral_key.public_key().to_vec();

        // 4. Encrypt the envelope key for each recipient
        let mut recipient_keys = Vec::with_capacity(recipients.len());
        for recipient_key in recipients {
            // Use the new encrypt method which handles DH, HKDF, and encryption
            let encrypted_key = ephemeral_key.encrypt(&envelope_key, recipient_key.public_key())?;

            recipient_keys.push(RecipientKey {
                recipient_public_key: recipient_key.public_key().to_vec(),
                encrypted_key,
            });
        }

        Ok(Self {
            ephemeral_public_key: ephemeral_public_key_bytes,
            encrypted_data,
            data_nonce: data_nonce_bytes,
            recipient_keys,
        })
    }

    /// Decrypt the envelope using a recipient's key
    pub fn decrypt(&self, recipient_key: &EncryptionKeyPair) -> Result<Vec<u8>> {
        let recipient_public_key_bytes = recipient_key.public_key();

        // 1. Find the encrypted key for this recipient
        let recipient_key_entry = self
            .recipient_keys
            .iter()
            .find(|r| r.recipient_public_key == recipient_public_key_bytes)
            .ok_or_else(|| {
                KeyError::EnvelopeError(format!(
                    "No key found for recipient: {}",
                    hex::encode(recipient_public_key_bytes)
                ))
            })?;

        // 2. The ephemeral public key is the sender's public key for decryption
        let ephemeral_public_key = &self.ephemeral_public_key;

        // 3. Decrypt the envelope key
        let envelope_key_vec =
            recipient_key.decrypt(&recipient_key_entry.encrypted_key, ephemeral_public_key)?;

        let envelope_key: [u8; SYMMETRIC_KEY_LENGTH] =
            envelope_key_vec.as_slice().try_into().map_err(|_| {
                KeyError::EnvelopeError("Decrypted envelope key has invalid length".to_string())
            })?;

        // 4. Decrypt the data with the envelope key
        let cipher = ChaCha20Poly1305::new(&envelope_key.into());
        let nonce = Nonce::from_slice(&self.data_nonce);
        cipher
            .decrypt(nonce, &*self.encrypted_data)
            .map_err(|e| KeyError::CryptoError(e.to_string()))
    }
}
