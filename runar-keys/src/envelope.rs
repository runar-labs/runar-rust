use crate::crypto::{
    EncryptionKeyPair, SymmetricEncryption, NONCE_LENGTH, SYMMETRIC_KEY_LENGTH,
};
use crate::error::{KeyError, Result};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use x25519_dalek::PublicKey as X25519PublicKey;

/// Represents an encrypted key for a recipient
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecipientKey {
    /// Identifier for the recipient (e.g., user profile ID or network ID)
    pub recipient_public_key: Vec<u8>,
    /// Encrypted envelope key
    pub encrypted_key: Vec<u8>,
    /// Nonce used for key encryption
    pub key_nonce: [u8; NONCE_LENGTH],
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
        let envelope_key = SymmetricEncryption::generate_key();

        // 2. Encrypt the data with the envelope key
        let (encrypted_data, data_nonce) =
            SymmetricEncryption::encrypt(&envelope_key, data.as_ref())?;

        // 3. Generate an ephemeral key pair for this encryption session
        let ephemeral_key = EncryptionKeyPair::generate();
        let ephemeral_public_key_bytes = ephemeral_key.public_key().as_bytes().to_vec();

        // 4. Encrypt the envelope key for each recipient
        let mut recipient_keys = Vec::with_capacity(recipients.len());
        for recipient_key in recipients {
            // Derive a shared secret using the ephemeral private key and recipient's public key
            let shared_secret = ephemeral_key.derive_shared_secret(recipient_key.public_key());

            // Use HKDF to derive a symmetric key from the shared secret
            let symmetric_key = EncryptionKeyPair::generate_symmetric_key(&shared_secret)?;

            // Encrypt the envelope key with the derived symmetric key
            let (encrypted_key, key_nonce) =
                SymmetricEncryption::encrypt(&symmetric_key, &envelope_key)?;

            recipient_keys.push(RecipientKey {
                recipient_public_key: recipient_key.public_key().as_bytes().to_vec(),
                encrypted_key,
                key_nonce,
            });
        }

        Ok(Self {
            ephemeral_public_key: ephemeral_public_key_bytes,
            encrypted_data,
            data_nonce,
            recipient_keys,
        })
    }

    /// Decrypt the envelope using a recipient's key
    pub fn decrypt(&self, recipient_key: &EncryptionKeyPair) -> Result<Vec<u8>> {
        let recipient_public_key_bytes = recipient_key.public_key().as_bytes();

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

        // 2. Parse the ephemeral public key from the envelope
        let ephemeral_public_key_bytes: [u8; 32] = self
            .ephemeral_public_key
            .as_slice()
            .try_into()
            .map_err(|_| KeyError::InvalidKeyLength)?;
        let ephemeral_public_key = X25519PublicKey::from(ephemeral_public_key_bytes);

        // 3. Derive the shared secret using the recipient's private key and the ephemeral public key
        let shared_secret = recipient_key.derive_shared_secret(&ephemeral_public_key);

        // 4. Derive the symmetric key using HKDF
        let symmetric_key = EncryptionKeyPair::generate_symmetric_key(&shared_secret)?;

        // 5. Decrypt the envelope key
        let envelope_key_vec = SymmetricEncryption::decrypt(
            &symmetric_key,
            &recipient_key_entry.encrypted_key,
            &recipient_key_entry.key_nonce,
        )?;

        let envelope_key: [u8; SYMMETRIC_KEY_LENGTH] = envelope_key_vec.try_into().map_err(|_| {
            KeyError::EnvelopeError("Decrypted envelope key has invalid length".to_string())
        })?;

        // 6. Decrypt the data with the envelope key
        SymmetricEncryption::decrypt(&envelope_key, &self.encrypted_data, &self.data_nonce)
    }
}
