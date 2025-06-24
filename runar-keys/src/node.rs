use crate::crypto::{Certificate, EncryptionKeyPair, SigningKeyPair};
use crate::envelope::Envelope;
use crate::error::{KeyError, Result};
use crate::manager::KeyManager;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

/// Represents a setup token for node initialization
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SetupToken {
    pub token_id: String,
    /// Node identifier (TLS public key)
    pub node_public_key: Vec<u8>,
    /// Node encryption public key for secure communication
    pub node_encryption_public_key: Vec<u8>,
    /// TLS certificate signing request
    pub tls_csr: Vec<u8>,
    /// Time to live in seconds
    pub ttl: u64,
}

/// Node key manager
pub struct NodeKeyManager {
    /// The underlying key manager
    key_manager: KeyManager,
    /// Node identifier
    node_public_key: Vec<u8>,
    //TODO review and remove this... node can participate in a multiple networiks not just one
    // Network identifier (if part of a network)
    //network_id: Option<String>,
}

impl NodeKeyManager {
    /// Create a new node key manager
    pub fn new() -> Self {
        let mut key_manager = KeyManager::new();
        let node_public_key = key_manager
            .generate_node_tls_key()
            .expect("Failed to generate node TLS key");
        
        // Generate an encryption key pair for the node
        key_manager
            .generate_encryption_key("node_encryption")
            .expect("Failed to generate node encryption key");
        
        Self {
            key_manager: key_manager,
            node_public_key: node_public_key,
        }
    }

    /// Get the node's encryption public key for secure communication
    pub fn get_encryption_public_key(&self) -> Result<Vec<u8>> {
        let encryption_key = self.key_manager
            .get_encryption_key("node_encryption")
            .ok_or_else(|| KeyError::KeyNotFound("Node encryption key not found".to_string()))?;
        
        Ok(encryption_key.public_key().to_vec())
    }

    pub fn new_with_key_manager(mut key_manager: KeyManager) -> Self {
        let node_public_key = key_manager
            .generate_node_tls_key()
            .expect("Failed to generate node TLS key");
        Self {
            key_manager: key_manager,
            node_public_key: node_public_key,

        }
    }

    /// Get the node ID
    pub fn node_public_key(&self) -> &Vec<u8> {
        &self.node_public_key
    }

    /// Generate a setup token using the existing node TLS key
    pub fn generate_setup_token(&mut self) -> Result<SetupToken> {
        // Use the existing node public key that was generated during initialization
        let node_public_key = self.node_public_key.clone();
        let subject = format!("node:{}", hex::encode(&node_public_key));
        
        // Create CSR for the node TLS key
        let tls_key_id = format!("node_tls_{}", hex::encode(&node_public_key));
        let tls_csr = self.key_manager.create_csr(&subject, &tls_key_id)?;
        
        // Ensure node has an encryption key pair for secure communication
        let node_encryption_public_key = if let Some(key) = self.key_manager.get_encryption_key("node_encryption") {
            key.public_key().to_vec()
        } else {
            // Generate a new encryption key pair if one doesn't exist
            self.key_manager.generate_encryption_key("node_encryption")?
        };

        // Create a setup token
        let token = SetupToken {
            token_id: uuid::Uuid::new_v4().to_string(),
            node_public_key,
            node_encryption_public_key,
            tls_csr,
            ttl: 3600, // 1 hour
        };

        Ok(token)
    }

    /// Decrypt an encrypted certificate envelope
    /// 
    /// This method decrypts a certificate that was encrypted specifically for this node.
    pub fn decrypt_certificate_envelope(&self, envelope: &Envelope) -> Result<Certificate> {
        // Get the node's encryption key pair
        let node_encryption_key = self.key_manager.get_encryption_key("node_encryption")
            .ok_or_else(|| KeyError::KeyNotFound("Node encryption key not found".to_string()))?;
        
        // Decrypt the envelope
        let decrypted_bytes = envelope.decrypt(node_encryption_key)?;
        
        // Deserialize the certificate using bincode for binary deserialization
        let certificate: Certificate = bincode::deserialize(&decrypted_bytes)
            .map_err(|e| KeyError::SerializationError(e.to_string()))?;
        
        Ok(certificate)
    }

    /// Process a signed certificate from mobile
    pub fn process_signed_certificate(&mut self, certificate: Certificate) -> Result<()> {
        // Extract the CA public key from the issuer field
        // The issuer field should have format "ca:{public_key_hex}"
        if !certificate.issuer.starts_with("ca:") {
            return Err(KeyError::InvalidKeyFormat(
                "Certificate issuer does not start with 'ca:'".to_string(),
            ));
        }
        
        // Verify that the certificate subject matches the expected format
        // The subject should be "node:{node_public_key_hex}"
        let expected_subject = format!("node:{}", hex::encode(self.node_public_key()));
        if certificate.subject != expected_subject {
            return Err(KeyError::InvalidKeyFormat(
                format!("Certificate subject '{}' does not match expected '{}'", 
                       certificate.subject, expected_subject)
            ));
        }
        
        // Extract the public key hex from the issuer
        let ca_pubkey_hex = &certificate.issuer[3..]; // Skip the "ca:" prefix
        
        // Decode the public key
        let ca_pubkey_bytes = hex::decode(ca_pubkey_hex)
            .map_err(|_| KeyError::InvalidKeyFormat("Invalid CA public key format".to_string()))?;
        
        // Validate the certificate directly using the extracted public key
        // Convert the byte slice to a fixed-size array for VerifyingKey::from_bytes
        let ca_pubkey_array: [u8; 32] = ca_pubkey_bytes[..32].try_into()
            .map_err(|_| KeyError::InvalidKeyFormat("CA public key is not 32 bytes".to_string()))?;
            
        let ca_verifying_key = VerifyingKey::from_bytes(&ca_pubkey_array)
            .map_err(|_| KeyError::InvalidKeyFormat("Invalid CA public key".to_string()))?;
        
        // Validate the certificate using the extracted verifying key
        certificate.validate(&ca_verifying_key)?;
        
        // Store the certificate using the new store_certificate method
        // that doesn't attempt to re-validate it
        self.key_manager_mut().store_certificate(certificate)?;
        
        Ok(())
    }

    /// Process an encrypted certificate envelope from mobile
    /// 
    /// This method decrypts the envelope, extracts the certificate, validates it,
    /// and stores it if valid.
    pub fn process_encrypted_certificate(&mut self, envelope: &Envelope) -> Result<()> {
        // Decrypt the envelope to get the certificate
        let certificate = self.decrypt_certificate_envelope(envelope)?;
        
        // Process the decrypted certificate
        self.process_signed_certificate(certificate)
    }

    /// Store a network key
    pub fn store_network_key(
        &mut self,
        network_public_key: &[u8],
        network_private_key: Vec<u8>,
    ) -> Result<()> {
        let key_id = format!("network_data_{}", hex::encode(network_public_key));
        let mut private_key_array = [0u8; 32];
        if network_private_key.len() == 32 {
            private_key_array.copy_from_slice(&network_private_key);

            let network_key_pair = EncryptionKeyPair::from_secret(&private_key_array);

            self.key_manager
                .add_encryption_key(&key_id, network_key_pair);

            Ok(())
        } else {
            Err(KeyError::KeyNotFound(format!(
                "Network private key is not 32 bytes long"
            )))
        }
    }

    /// Decrypt data using the network key
    pub fn decrypt_with_network_key(
        &self,
        network_public_key: &[u8],
        envelope: &Envelope,
    ) -> Result<Vec<u8>> {
        let network_key_id = format!("network_data_{}", hex::encode(network_public_key));
        let network_encryption_key = self
            .key_manager
            .get_encryption_key(&network_key_id)
            .ok_or_else(|| {
                KeyError::KeyNotFound(format!("Network key not found: {}", network_key_id))
            })?;

        // The recipient ID must match exactly what was used in encrypt_for_network_and_profile
        envelope.decrypt(network_encryption_key)
    }

    /// Get the underlying key manager
    pub fn key_manager(&self) -> &KeyManager {
        &self.key_manager
    }

    /// Get the underlying key manager mutably
    pub fn key_manager_mut(&mut self) -> &mut KeyManager {
        &mut self.key_manager
    }

    /// Get the node's certificate
    pub fn get_node_certificate(&self) -> Result<&Certificate> {
        let node_pk_str = hex::encode(self.node_public_key());
        let subject = format!("node:{}", node_pk_str);
        self.key_manager
            .get_certificate(&subject)
            .ok_or_else(|| KeyError::KeyNotFound("Node certificate not found".to_string()))
    }
}
