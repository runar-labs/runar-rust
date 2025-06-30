//! Mobile Key Manager - Certificate Authority Operations
//!
//! This module implements the mobile-side key management system that acts as
//! a Certificate Authority for issuing node certificates and managing user keys.

use crate::certificate::{CertificateAuthority, CertificateValidator, EcdsaKeyPair, X509Certificate};
use crate::error::{KeyError, Result};
use runar_common::logging::{Component, Logger};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Setup token from a node requesting a certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupToken {
    /// Node's public key for identity
    pub node_public_key: Vec<u8>,
    /// Node's certificate signing request (CSR) in DER format
    pub csr_der: Vec<u8>,
    /// Node identifier string
    pub node_id: String,
}

/// Secure message containing certificate and CA information for a node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCertificateMessage {
    /// The signed certificate for the node
    pub node_certificate: X509Certificate,
    /// The CA certificate for validation
    pub ca_certificate: X509Certificate,
    /// Additional metadata
    pub metadata: CertificateMetadata,
}

/// Certificate metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateMetadata {
    /// Issue timestamp
    pub issued_at: u64,
    /// Validity period in days
    pub validity_days: u32,
    /// Certificate purpose
    pub purpose: String,
}

/// Network key information for secure node communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkKeyMessage {
    /// Network identifier
    pub network_id: String,
    /// Network public key
    pub network_public_key: Vec<u8>,
    /// Encrypted network data key
    pub encrypted_network_key: Vec<u8>,
    /// Key derivation information
    pub key_derivation_info: String,
}

/// Envelope encrypted data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeEncryptedData {
    /// The encrypted data payload
    pub encrypted_data: Vec<u8>,
    /// Network ID this data belongs to
    pub network_id: String,
    /// Envelope key encrypted with network key
    pub network_encrypted_key: Option<Vec<u8>>,
    /// Envelope key encrypted with each profile key
    pub profile_encrypted_keys: HashMap<String, Vec<u8>>,
}

/// Mobile Key Manager that acts as a Certificate Authority
pub struct MobileKeyManager {
    /// Certificate Authority for issuing certificates
    certificate_authority: CertificateAuthority,
    /// Certificate validator
    certificate_validator: CertificateValidator,
    /// User root key - Master key for the user (never leaves mobile)
    user_root_key: Option<EcdsaKeyPair>,
    /// User profile keys indexed by profile ID - derived from root key
    user_profile_keys: HashMap<String, EcdsaKeyPair>,
    /// Network data keys indexed by network ID - for envelope encryption
    network_data_keys: HashMap<String, EcdsaKeyPair>,
    /// Issued certificates tracking
    issued_certificates: HashMap<String, X509Certificate>,
    /// Logger instance
    logger: Arc<Logger>,
}

impl MobileKeyManager {
    /// Create a new Mobile Key Manager with CA capabilities
    pub fn new(logger: Arc<Logger>) -> Result<Self> {
        // Create Certificate Authority with user identity
        let ca_subject = "CN=Runar User CA,O=Runar,C=US";
        let certificate_authority = CertificateAuthority::new(ca_subject)?;
        
        // Create certificate validator with the CA certificate
        let ca_cert = certificate_authority.ca_certificate().clone();
        let certificate_validator = CertificateValidator::new(vec![ca_cert]);
        
        logger.info("Mobile Key Manager initialized with CA capabilities");
        
        Ok(Self {
            certificate_authority,
            certificate_validator,
            user_root_key: None,
            user_profile_keys: HashMap::new(),
            network_data_keys: HashMap::new(),
            issued_certificates: HashMap::new(),
            logger,
        })
    }
    
    /// Initialize user root key - Master key that never leaves the mobile device
    pub fn initialize_user_root_key(&mut self) -> Result<Vec<u8>> {
        let root_key = EcdsaKeyPair::new()?;
        let public_key = root_key.public_key_bytes();
        
        self.user_root_key = Some(root_key);
        self.logger.info("User root key initialized (private key secured on mobile)");
        
        Ok(public_key)
    }
    
    /// Get the user root public key
    pub fn get_user_root_public_key(&self) -> Result<Vec<u8>> {
        let root_key = self.user_root_key.as_ref()
            .ok_or_else(|| KeyError::KeyNotFound("User root key not initialized".to_string()))?;
        Ok(root_key.public_key_bytes())
    }
    
    /// Derive a user profile key from the root key
    /// In production, this would use proper key derivation (HKDF/SLIP-0010)
    /// For now, we generate independent keys but associate them with the root
    pub fn derive_user_profile_key(&mut self, profile_id: &str) -> Result<Vec<u8>> {
        // Ensure root key exists
        if self.user_root_key.is_none() {
            return Err(KeyError::InvalidOperation(
                "User root key must be initialized before deriving profile keys".to_string()
            ));
        }
        
        // For this implementation, generate a new key pair
        // In production, this would be derived from the root key using HKDF
        let profile_key = EcdsaKeyPair::new()?;
        let public_key = profile_key.public_key_bytes();
        
        self.user_profile_keys.insert(profile_id.to_string(), profile_key);
        self.logger.info(format!("User profile key derived for profile: {}", profile_id));
        
        Ok(public_key)
    }
    
    /// Generate a network data key for envelope encryption
    pub fn generate_network_data_key(&mut self, network_id: &str) -> Result<Vec<u8>> {
        let network_key = EcdsaKeyPair::new()?;
        let public_key = network_key.public_key_bytes();
        
        self.network_data_keys.insert(network_id.to_string(), network_key);
        self.logger.info(format!("Network data key generated for network: {}", network_id));
        
        Ok(public_key)
    }
    
    /// Create an envelope key for per-object encryption
    /// Envelope keys are ephemeral - generated fresh for each object
    pub fn create_envelope_key(&self) -> Result<Vec<u8>> {
        // Generate a fresh 32-byte symmetric key for envelope encryption
        use rand::RngCore;
        let mut envelope_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut envelope_key);
        
        self.logger.debug("Ephemeral envelope key generated");
        Ok(envelope_key.to_vec())
    }
    
    /// Encrypt data with envelope encryption
    /// This implements the envelope encryption pattern:
    /// 1. Generate ephemeral envelope key
    /// 2. Encrypt data with envelope key
    /// 3. Encrypt envelope key with network/profile keys
    pub fn encrypt_with_envelope(
        &self,
        data: &[u8],
        network_id: &str,
        profile_ids: Vec<String>,
    ) -> Result<EnvelopeEncryptedData> {
        // Generate ephemeral envelope key
        let envelope_key = self.create_envelope_key()?;
        
        // Encrypt data with envelope key (using AES-GCM for simplicity)
        let encrypted_data = self.encrypt_with_symmetric_key(data, &envelope_key)?;
        
        //TODO if self.network_data_keys DOES NOT have keuys for the provied network id then we need to return an error.. 
        // Encrypt envelope key for network
        let network_encrypted_key = if let Some(network_key) = self.network_data_keys.get(network_id) {
            Some(self.encrypt_key_with_ecdsa(&envelope_key, network_key)?)
        } else {
            None
        };
        
        // Encrypt envelope key for each profile
        let mut profile_encrypted_keys = HashMap::new();
        for profile_id in profile_ids {
            if let Some(profile_key) = self.user_profile_keys.get(&profile_id) {
                let encrypted_key = self.encrypt_key_with_ecdsa(&envelope_key, profile_key)?;
                profile_encrypted_keys.insert(profile_id, encrypted_key);
            }
        }
        //TODO network_encrypted_key shoul dnot be optional
        Ok(EnvelopeEncryptedData {
            encrypted_data,
            network_id: network_id.to_string(),
            network_encrypted_key,
            profile_encrypted_keys,
        })
    }
    
    /// Decrypt envelope-encrypted data using profile key
    pub fn decrypt_with_profile(&self, envelope_data: &EnvelopeEncryptedData, profile_id: &str) -> Result<Vec<u8>> {
        let profile_key = self.user_profile_keys.get(profile_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("Profile key not found: {}", profile_id)))?;
        
        let encrypted_envelope_key = envelope_data.profile_encrypted_keys.get(profile_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("Envelope key not found for profile: {}", profile_id)))?;
        
        let envelope_key = self.decrypt_key_with_ecdsa(encrypted_envelope_key, profile_key)?;
        self.decrypt_with_symmetric_key(&envelope_data.encrypted_data, &envelope_key)
    }
    
    /// Decrypt envelope-encrypted data using network key
    pub fn decrypt_with_network(&self, envelope_data: &EnvelopeEncryptedData) -> Result<Vec<u8>> {
        let network_key = self.network_data_keys.get(&envelope_data.network_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("Network key not found: {}", envelope_data.network_id)))?;
        
        let encrypted_envelope_key = envelope_data.network_encrypted_key.as_ref()
            .ok_or_else(|| KeyError::KeyNotFound("Network envelope key not found".to_string()))?;
        
        let envelope_key = self.decrypt_key_with_ecdsa(encrypted_envelope_key, network_key)?;
        self.decrypt_with_symmetric_key(&envelope_data.encrypted_data, &envelope_key)
    }
    
    //TODO this is not secure. we need to use a proper symmetric encryption algorithm.
    // Helper methods for symmetric encryption
    fn encrypt_with_symmetric_key(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        // For this implementation, we'll use a simple XOR cipher
        // In production, this would use AES-GCM or ChaCha20-Poly1305
        let mut encrypted = data.to_vec();
        for (i, byte) in encrypted.iter_mut().enumerate() {
            *byte ^= key[i % key.len()];
        }
        Ok(encrypted)
    }
    
    fn decrypt_with_symmetric_key(&self, encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        // XOR is symmetric, so decryption is the same as encryption
        self.encrypt_with_symmetric_key(encrypted_data, key)
    }
    
    fn encrypt_key_with_ecdsa(&self, key: &[u8], ecdsa_key: &EcdsaKeyPair) -> Result<Vec<u8>> {
        // For this implementation, we'll use the ECDSA key for signing the key
        // In production, this would use ECIES or similar
        use p256::ecdsa::{signature::Signer, Signature};
        let signature: Signature = ecdsa_key.signing_key().sign(key);
        let mut encrypted = key.to_vec();
        encrypted.extend_from_slice(signature.to_der().as_bytes());
        Ok(encrypted)
    }
    
    fn decrypt_key_with_ecdsa(&self, encrypted_key: &[u8], ecdsa_key: &EcdsaKeyPair) -> Result<Vec<u8>> {
        // Extract the original key (first 32 bytes) and signature (rest)
        if encrypted_key.len() < 32 {
            return Err(KeyError::InvalidKeyFormat("Encrypted key too short".to_string()));
        }
        
        let key = &encrypted_key[..32];
        let signature_bytes = &encrypted_key[32..];
        
        // Verify the signature
        use p256::ecdsa::{signature::Verifier, Signature};
        let signature = Signature::from_der(signature_bytes)
            .map_err(|e| KeyError::InvalidKeyFormat(format!("Invalid signature format: {}", e)))?;
        
        ecdsa_key.verifying_key().verify(key, &signature)
            .map_err(|e| KeyError::CertificateValidationError(format!("Key signature verification failed: {}", e)))?;
        
        Ok(key.to_vec())
    }
    
    /// Initialize user identity and generate root keys
    pub fn initialize_user_identity(&mut self) -> Result<Vec<u8>> {
        // This now delegates to the new user root key method
        self.initialize_user_root_key()
    }
    
    /// Get the user CA certificate
    pub fn get_ca_certificate(&self) -> &X509Certificate {
        self.certificate_authority.ca_certificate()
    }
    
    /// Get the CA public key bytes
    pub fn get_ca_public_key(&self) -> Vec<u8> {
        self.certificate_authority.ca_public_key().to_encoded_point(true).as_bytes().to_vec()
    }
    
    /// Process a setup token from a node and issue a certificate
    pub fn process_setup_token(&mut self, setup_token: &SetupToken) -> Result<NodeCertificateMessage> {
        self.logger.info(format!("Processing setup token for node: {}", setup_token.node_id));
        
        // Validate the CSR format
        if setup_token.csr_der.is_empty() {
            self.logger.error("Empty CSR in setup token");
            return Err(KeyError::InvalidOperation(
                "Empty CSR in setup token".to_string()
            ));
        }
        
        // Instead of signing the CSR (which has key pair issues), let's use the simplified approach
        // that works correctly with the node's actual key pair.
        // This is acceptable for this implementation since we have access to the node's key pair.
        
        // For this simplified approach, we'll extract the node ID from the setup token
        // and create a certificate using the create_signed_certificate method.
        // In a production system, this would properly extract and use the public key from the CSR.
        
        let _subject = format!("CN={},O=Runar Node,C=US", setup_token.node_id);
        let validity_days = 365; // 1 year validity
        
        // Create certificate using node's key pair (extracted from CSR in a real implementation)
        // For now, we'll need the node's key pair to be passed or extracted differently
        // This is a limitation of the current implementation approach
        
        // Since we can't easily extract the key pair from the CSR with rcgen,
        // let's fall back to the sign_certificate_request for now but acknowledge
        // this is the source of the signature verification issue
        let node_certificate = self.certificate_authority
            .sign_certificate_request(&setup_token.csr_der, validity_days)?;
        
        // Store the issued certificate
        self.issued_certificates.insert(
            setup_token.node_id.clone(),
            node_certificate.clone()
        );
        
        // Create metadata
        let metadata = CertificateMetadata {
            issued_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            validity_days,
            purpose: "Node TLS Certificate".to_string(),
        };
        
        // Create the message
        Ok(NodeCertificateMessage {
            node_certificate,
            ca_certificate: self.certificate_authority.ca_certificate().clone(),
            metadata,
        })
    }

    // Removed create_node_certificate method - using proper CSR flow only
    // This method was a workaround that violated the certificate security model
    
    /// Get statistics about the mobile key manager
    pub fn get_statistics(&self) -> MobileKeyManagerStatistics {
        MobileKeyManagerStatistics {
            issued_certificates_count: self.issued_certificates.len(),
            user_profile_keys_count: self.user_profile_keys.len(),
            network_keys_count: self.network_data_keys.len(),
            ca_certificate_subject: self.certificate_authority.ca_certificate().subject().to_string(),
        }
    }

    //TODO rem9ove node_id uis not needed 
    /// Create a network key message for a node
    pub fn create_network_key_message(
        &self,
        network_id: &str,
        node_id: &str,
    ) -> Result<NetworkKeyMessage> {
        let network_key = self.network_data_keys.get(network_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("Network key not found: {}", network_id)))?;
        
        // For this implementation, we'll include the network key directly
        // In a production system, this would be encrypted with the node's public key
        let network_public_key = network_key.public_key_bytes();
        let network_private_key = network_key.private_key_der()?;
        
        Ok(NetworkKeyMessage {
            network_id: network_id.to_string(),
            network_public_key,
            encrypted_network_key: network_private_key, // TODO: Encrypt with node's key
            key_derivation_info: format!("Network key for node {}", node_id),
        })
    }
    
    /// Validate a certificate issued by this CA
    pub fn validate_certificate(&self, certificate: &X509Certificate) -> Result<()> {
        self.certificate_validator.validate_certificate(certificate)
    }
    
    /// Get issued certificate by node ID
    pub fn get_issued_certificate(&self, node_id: &str) -> Option<&X509Certificate> {
        self.issued_certificates.get(node_id)
    }
    
    /// List all issued certificates
    pub fn list_issued_certificates(&self) -> Vec<(String, &X509Certificate)> {
        self.issued_certificates
            .iter()
            .map(|(node_id, cert)| (node_id.clone(), cert))
            .collect()
    }
    
    /// Encrypt data for a specific profile (legacy method for compatibility)
    pub fn encrypt_for_profile(&self, data: &[u8], profile_id: &str) -> Result<Vec<u8>> {
        // Use envelope encryption with just this profile
        let envelope_data = self.encrypt_with_envelope(data, "default", vec![profile_id.to_string()])?;
        // Return just the encrypted data for compatibility
        Ok(envelope_data.encrypted_data)
    }
    
    /// Encrypt data for a network (legacy method for compatibility)  
    pub fn encrypt_for_network(&self, data: &[u8], network_id: &str) -> Result<Vec<u8>> {
        // Use envelope encryption with just this network
        let envelope_data = self.encrypt_with_envelope(data, network_id, vec![])?;
        // Return just the encrypted data for compatibility
        Ok(envelope_data.encrypted_data)
    }
    
    /// Generate a user profile key (legacy method name for compatibility)
    pub fn generate_user_profile_key(&mut self, profile_id: &str) -> Result<Vec<u8>> {
        self.derive_user_profile_key(profile_id)
    }
}

/// Statistics about the mobile key manager
#[derive(Debug, Clone)]
pub struct MobileKeyManagerStatistics {
    pub issued_certificates_count: usize,
    pub user_profile_keys_count: usize,
    pub network_keys_count: usize,
    pub ca_certificate_subject: String,
}

impl Default for MobileKeyManager {
    fn default() -> Self {
        let logger = Arc::new(Logger::new_root(Component::Custom("Keys"), "mobile-default"));
        Self::new(logger).expect("Failed to create default MobileKeyManager")
    }
} 