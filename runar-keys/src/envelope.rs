use crate::crypto::{EncryptionKeyPair, SymmetricEncryption, NONCE_LENGTH, SYMMETRIC_KEY_LENGTH};
use crate::error::{KeyError, Result};
use serde::{Deserialize, Serialize};

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
        // Generate a fresh envelope key
        let envelope_key = SymmetricEncryption::generate_key();

        // Encrypt the data with the envelope key
        let (encrypted_data, data_nonce) =
            SymmetricEncryption::encrypt(&envelope_key, data.as_ref())?;

        // Encrypt the envelope key for each recipient
        let mut recipient_keys = Vec::with_capacity(recipients.len());

        for recipient_key in recipients {
            //TODO fix this;.; we do not want shorcuts like this;.. we are after the full cmoplete and robust implementation.
            //replace this simplified approach with a proper robust imnplementaion using X25519 key agreement

            // In a real implementation, this would use X25519 key agreement
            // For now, we'll use our simplified approach
            // Note: We're using a deterministic key derivation for testing purposes
            // In a real implementation, this would use proper X25519 key agreement
            let shared_secret = recipient_key.derive_shared_secret(&[0u8; 32])?;

            // Encrypt the envelope key with the shared secret
            // IMPORTANT: Save the nonce used for key encryption
            let (encrypted_key, key_nonce) =
                SymmetricEncryption::encrypt(&shared_secret, &envelope_key)?;

            recipient_keys.push(RecipientKey {
                recipient_public_key: recipient_key.public_key().to_vec(),
                encrypted_key,
                key_nonce,
            });
        }

        Ok(Self {
            encrypted_data,
            data_nonce,
            recipient_keys,
        })
    }

    /// Decrypt the envelope using a recipient's key
    pub fn decrypt(&self, recipient_key: &EncryptionKeyPair) -> Result<Vec<u8>> {
        let recipient_public_key = recipient_key.public_key().to_vec();
        // Find the encrypted key for this recipient
        let recipient_key_entry = self
            .recipient_keys
            .iter()
            .find(|r| r.recipient_public_key == recipient_public_key)
            .ok_or_else(|| {
                KeyError::EnvelopeError(format!(
                    "No key found for recipient: {}",
                    hex::encode(recipient_public_key)
                ))
            })?;

        // Derive the shared secret
        // Using the same deterministic approach as in the encryption
        let shared_secret = recipient_key.derive_shared_secret(&[0u8; 32])?;

        // Decrypt the envelope key using the saved nonce
        let envelope_key = SymmetricEncryption::decrypt(
            &shared_secret,
            &recipient_key_entry.encrypted_key,
            &recipient_key_entry.key_nonce, // Use the nonce that was saved during encryption
        )?;

        if envelope_key.len() != SYMMETRIC_KEY_LENGTH {
            return Err(KeyError::EnvelopeError(
                "Decrypted envelope key has invalid length".to_string(),
            ));
        }

        let mut key_array = [0u8; SYMMETRIC_KEY_LENGTH];
        key_array.copy_from_slice(&envelope_key);

        // Decrypt the data with the envelope key
        SymmetricEncryption::decrypt(&key_array, &self.encrypted_data, &self.data_nonce)
    }

    /// Add a new recipient to the envelope
    pub fn add_recipient(
        &mut self,
        recipient_id: String,
        recipient_key: &EncryptionKeyPair,
        envelope_key: &[u8; SYMMETRIC_KEY_LENGTH],
    ) -> Result<()> {
        // Derive the shared secret
        // Using the same deterministic approach as in the encryption
        let shared_secret = recipient_key.derive_shared_secret(&[0u8; 32])?;

        // Encrypt the envelope key with the shared secret
        let (encrypted_key, key_nonce) =
            SymmetricEncryption::encrypt(&shared_secret, envelope_key)?;

        // Add the recipient key with the nonce
        self.recipient_keys.push(RecipientKey {
            recipient_public_key: recipient_key.public_key().to_vec(),
            encrypted_key,
            key_nonce,
        });

        Ok(())
    }
}
