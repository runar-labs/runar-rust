use crate::traits::{EncryptedEnvelope, KeyStore, LabelResolver};
use anyhow::{anyhow, Result};
use bincode;
use serde::{Deserialize, Serialize};

/// Container for label-grouped encryption
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedLabelGroup {
    /// The label this group was encrypted with
    pub label: String,
    /// Encrypted envelope from runar-keys
    pub envelope: EncryptedEnvelope,
}

impl EncryptedLabelGroup {
    pub fn is_empty(&self) -> bool {
        self.envelope.encrypted_data.is_empty()
    }
}

/// Encrypt a group of fields with a specific label
pub fn encrypt_label_group<T: Serialize>(
    label: &str,
    fields_struct: &T,
    keystore: &dyn KeyStore,
    resolver: &dyn LabelResolver,
) -> Result<EncryptedLabelGroup> {
    // Serialize all fields in this label group
    let plaintext = bincode::serialize(fields_struct)?;

    // Resolve label to public key
    let public_key = resolver
        .resolve_label(label)?
        .ok_or_else(|| anyhow!("Label '{label}' not available in current context"))?;

    // Use keystore to encrypt with envelope encryption
    let envelope = keystore.encrypt_with_envelope(&plaintext, &public_key)?;

    Ok(EncryptedLabelGroup {
        label: label.to_string(),
        envelope,
    })
}

/// Decrypt a label group to the original fields struct
pub fn decrypt_label_group<T: for<'de> Deserialize<'de>>(
    encrypted_group: &EncryptedLabelGroup,
    keystore: &dyn KeyStore,
) -> Result<T> {
    if encrypted_group.is_empty() {
        return Err(anyhow!("Empty encrypted group"));
    }

    // Ensure we have a matching private key for at least one encrypted key
    let has_access = encrypted_group
        .envelope
        .encrypted_keys
        .iter()
        .any(|ek| keystore.can_decrypt_for_key(&ek.public_key));

    if !has_access {
        return Err(anyhow!(
            "Keystore cannot decrypt for any key in this label group"
        ));
    }

    // Attempt decryption (mock keystores will succeed/fail based on above check)
    let plaintext = keystore.decrypt_envelope_data(&encrypted_group.envelope)?;

    // Deserialize the entire fields struct
    let fields_struct: T = bincode::deserialize(&plaintext)?;
    Ok(fields_struct)
}
