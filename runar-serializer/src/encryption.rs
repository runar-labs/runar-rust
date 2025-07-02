use crate::traits::{EnvelopeEncryptedData, KeyStore, LabelResolver};
use anyhow::{anyhow, Result};
use bincode;
use runar_keys::compact_ids;
use serde::{Deserialize, Serialize};

/// Container for label-grouped encryption (one per label)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedLabelGroup {
    /// The label this group was encrypted with
    pub label: String,
    /// Envelope-encrypted payload produced by runar-keys
    pub envelope: EnvelopeEncryptedData,
}

impl EncryptedLabelGroup {
    pub fn is_empty(&self) -> bool {
        self.envelope.encrypted_data.is_empty()
    }
}

/// Encrypt a group of fields that share the same label ("user", "system", ...)
pub fn encrypt_label_group<T: Serialize>(
    label: &str,
    fields_struct: &T,
    keystore: &KeyStore,
    resolver: &dyn LabelResolver,
) -> Result<EncryptedLabelGroup> {
    // Serialize the fields within this label group
    let plaintext = bincode::serialize(fields_struct)?;

    // Resolve the label to a concrete public-key reference
    let public_key = resolver
        .resolve_label(label)?
        .ok_or_else(|| anyhow!("Label '{label}' not available in current context"))?;

    // Determine envelope encryption parameters
    let (network_id, profile_ids): (String, Vec<String>) = if label == "system" {
        // System-level data => encrypt with the network key only
        (compact_ids::compact_network_id(&public_key), Vec::new())
    } else {
        // User / other label => encrypt only for the associated profile(s)
        (String::new(), vec![label.to_string()])
    };

    let envelope = keystore.encrypt_with_envelope(&plaintext, &network_id, profile_ids)?;

    Ok(EncryptedLabelGroup {
        label: label.to_string(),
        envelope,
    })
}

/// Attempt to decrypt a label group back into its original struct.  
/// Returns an error if decryption fails, allowing callers to ignore failures
/// (e.g. when the current context lacks the required keys).
pub fn decrypt_label_group<T: for<'de> Deserialize<'de>>(
    encrypted_group: &EncryptedLabelGroup,
    keystore: &KeyStore,
) -> Result<T> {
    if encrypted_group.is_empty() {
        return Err(anyhow!("Empty encrypted group"));
    }

    // Attempt decryption using the provided key manager
    let plaintext = keystore.decrypt_envelope_data(&encrypted_group.envelope)?;

    // Deserialize the fields struct from plaintext
    let fields_struct: T = bincode::deserialize(&plaintext)?;
    Ok(fields_struct)
}
