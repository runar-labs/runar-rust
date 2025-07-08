use crate::traits::{EnvelopeEncryptedData, KeyScope, KeyStore, LabelResolver};
use anyhow::{anyhow, Result};
use prost::Message;
use runar_keys::compact_ids;
use serde::{Deserialize, Serialize};

/// Container for label-grouped encryption (one per label)
#[derive(Serialize, Deserialize, Clone, prost::Message)]
pub struct EncryptedLabelGroup {
    /// The label this group was encrypted with
    #[prost(string, tag = "1")]
    pub label: String,
    /// Envelope-encrypted payload produced by runar-keys
    #[prost(message, optional, tag = "2")]
    pub envelope: ::core::option::Option<EnvelopeEncryptedData>,
}

impl EncryptedLabelGroup {
    pub fn is_empty(&self) -> bool {
        match &self.envelope {
            Some(env) => env.encrypted_data.is_empty(),
            None => true,
        }
    }
}

/// Encrypt a group of fields that share the same label ("user", "system", ...)
pub fn encrypt_label_group<T: Serialize + prost::Message>(
    label: &str,
    fields_struct: &T,
    keystore: &KeyStore,
    resolver: &dyn LabelResolver,
) -> Result<EncryptedLabelGroup> {
    // Serialize the fields within this label group
    let mut plaintext = Vec::new();
    Message::encode(fields_struct, &mut plaintext)?;

    // Resolve the label to key info (public key + scope)
    let info = resolver
        .resolve_label_info(label)?
        .ok_or_else(|| anyhow!("Label '{label}' not available in current context"))?;

    // Determine envelope encryption parameters based on scope
    let (network_id, profile_ids): (String, Vec<String>) = match info.scope {
        KeyScope::Network => (
            compact_ids::compact_network_id(&info.public_key),
            Vec::new(),
        ),
        KeyScope::Profile => (String::new(), vec![label.to_string()]),
    };

    let envelope = keystore.encrypt_with_envelope(&plaintext, &network_id, profile_ids)?;

    Ok(EncryptedLabelGroup {
        label: label.to_string(),
        envelope: Some(envelope),
    })
}

/// Attempt to decrypt a label group back into its original struct.  
/// Returns an error if decryption fails, allowing callers to ignore failures
/// (e.g. when the current context lacks the required keys).
pub fn decrypt_label_group<T: for<'de> Deserialize<'de> + prost::Message + Default>(
    encrypted_group: &EncryptedLabelGroup,
    keystore: &KeyStore,
) -> Result<T> {
    if encrypted_group.is_empty() {
        return Err(anyhow!("Empty encrypted group"));
    }

    // Attempt decryption using the provided key manager
    let env = encrypted_group
        .envelope
        .as_ref()
        .ok_or_else(|| anyhow!("Empty encrypted group"))?;

    let plaintext = keystore.decrypt_envelope_data(env)?;

    // Deserialize the fields struct from plaintext
    let fields_struct: T = Message::decode(&*plaintext)?;
    Ok(fields_struct)
}
