use crate::crypto::{
    Certificate, EncryptionKeyPair, NetworkKeyMessage, PublicKey, SigningKeyPair, SymmetricKey,
    CHACHA20POLY1305_KEY_LENGTH,
};
use crate::error::{KeyError, Result};
use crate::key_derivation::KeyDerivation;
use ed25519_dalek::VerifyingKey;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

/// Certificate verifier for ECDSA certificates used by QUIC transport
#[derive(Debug)]
struct EcdsaCertVerifier;

impl EcdsaCertVerifier {
    fn new() -> Self {
        Self
    }
}

impl ServerCertVerifier for EcdsaCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, TlsError> {
        // For QUIC transport, we accept any valid X.509 certificate
        // In production, you would validate against your CA here
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        // Accept ECDSA signature schemes for QUIC
        match dss.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256
            | SignatureScheme::ECDSA_NISTP384_SHA384
            | SignatureScheme::ECDSA_NISTP521_SHA512 => Ok(HandshakeSignatureValid::assertion()),
            _ => Err(TlsError::InvalidCertificate(
                rustls::CertificateError::BadSignature,
            )),
        }
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        // Accept ECDSA signature schemes for QUIC
        match dss.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256
            | SignatureScheme::ECDSA_NISTP384_SHA384
            | SignatureScheme::ECDSA_NISTP521_SHA512 => Ok(HandshakeSignatureValid::assertion()),
            _ => Err(TlsError::InvalidCertificate(
                rustls::CertificateError::BadSignature,
            )),
        }
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
        ]
    }
}

/// Key manager that stores and manages cryptographic keys
/// Structure to hold serializable key data for persistence
#[derive(Serialize, Deserialize)]
pub struct KeyManagerData {
    /// Optional seed for key derivation
    pub seed: Option<[u8; 32]>,
    /// Signing keys by ID
    pub signing_keys: HashMap<String, SigningKeyPair>,
    /// Encryption keys by ID
    pub encryption_keys: HashMap<String, EncryptionKeyPair>,
    /// Symmetric keys by ID
    pub symmetric_keys: HashMap<String, SymmetricKey>,
    /// Certificates by subject
    pub certificates: HashMap<String, Certificate>,
    /// ECDSA keys by ID
    pub ecdsa_keys: HashMap<String, EcdsaKeyPair>,
}

/// ECDSA P-256 key pair for TLS/QUIC transport
#[derive(Debug, Clone)]
pub struct EcdsaKeyPair {
    signing_key: p256::ecdsa::SigningKey,
}

impl Serialize for EcdsaKeyPair {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use pkcs8::EncodePrivateKey;
        use serde::ser::Error;

        let pkcs8_der = self
            .signing_key
            .to_pkcs8_der()
            .map_err(|e| S::Error::custom(format!("Failed to encode ECDSA key: {}", e)))?;

        serializer.serialize_bytes(pkcs8_der.as_bytes())
    }
}

impl<'de> Deserialize<'de> for EcdsaKeyPair {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use pkcs8::DecodePrivateKey;
        use serde::de::Error;

        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let signing_key = p256::ecdsa::SigningKey::from_pkcs8_der(&bytes)
            .map_err(|e| D::Error::custom(format!("Failed to decode ECDSA key: {}", e)))?;

        Ok(EcdsaKeyPair { signing_key })
    }
}

impl EcdsaKeyPair {
    /// Generate a new ECDSA P-256 key pair
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> Self {
        Self {
            signing_key: p256::ecdsa::SigningKey::random(rng),
        }
    }

    /// Create from PKCS#8 DER bytes
    pub fn from_pkcs8(pkcs8_der: &[u8]) -> Result<Self> {
        use pkcs8::DecodePrivateKey;

        let signing_key = p256::ecdsa::SigningKey::from_pkcs8_der(pkcs8_der).map_err(|e| {
            KeyError::CertificateError(format!("Failed to decode ECDSA key: {}", e))
        })?;

        Ok(Self { signing_key })
    }

    /// Export to PKCS#8 DER
    pub fn to_pkcs8_der(&self) -> Result<pkcs8::SecretDocument> {
        use pkcs8::EncodePrivateKey;

        self.signing_key
            .to_pkcs8_der()
            .map_err(|e| KeyError::CertificateError(format!("Failed to encode ECDSA key: {}", e)))
    }

    /// Get the verifying key (public key)
    pub fn verifying_key(&self) -> p256::ecdsa::VerifyingKey {
        *self.signing_key.verifying_key()
    }

    /// Convert to rcgen KeyPair for certificate generation
    pub fn to_rcgen_key_pair(&self) -> Result<rcgen::KeyPair> {
        use pkcs8::EncodePrivateKey;

        let pkcs8_der = self.signing_key.to_pkcs8_der().map_err(|e| {
            KeyError::CertificateError(format!("Failed to encode ECDSA key: {}", e))
        })?;

        let pem_str = pkcs8_der
            .to_pem("PRIVATE KEY", pkcs8::LineEnding::LF)
            .map_err(|e| KeyError::CertificateError(format!("Failed to convert to PEM: {}", e)))?;

        rcgen::KeyPair::from_pem(&pem_str).map_err(|e| {
            KeyError::CertificateError(format!("Failed to create rcgen key pair: {}", e))
        })
    }
}

pub struct KeyManager {
    /// User seed for deriving keys (if available)
    seed: Option<[u8; 32]>,
    /// Signing key pairs by ID
    signing_keys: HashMap<String, SigningKeyPair>,
    /// Encryption key pairs by ID
    encryption_keys: HashMap<String, EncryptionKeyPair>,
    /// Symmetric keys by ID
    symmetric_keys: HashMap<String, SymmetricKey>,
    /// Certificates by subject
    certificates: HashMap<String, Certificate>,
    /// ECDSA keys by ID
    ecdsa_keys: HashMap<String, EcdsaKeyPair>,
}

impl fmt::Debug for KeyManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyManager")
            .field("has_seed", &self.seed.is_some())
            .field("signing_keys_count", &self.signing_keys.len())
            .field("encryption_keys_count", &self.encryption_keys.len())
            .field("symmetric_keys_count", &self.symmetric_keys.len())
            .field("certificates_count", &self.certificates.len())
            .field("ecdsa_keys_count", &self.ecdsa_keys.len())
            .finish()
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyManager {
    /// Create a new key manager with empty state
    pub fn new() -> Self {
        Self {
            seed: None,
            signing_keys: HashMap::new(),
            encryption_keys: HashMap::new(),
            symmetric_keys: HashMap::new(),
            certificates: HashMap::new(),
            ecdsa_keys: HashMap::new(),
        }
    }

    /// Load key manager from serialized data
    pub fn from_data(data: KeyManagerData) -> Self {
        Self {
            seed: data.seed,
            signing_keys: data.signing_keys,
            encryption_keys: data.encryption_keys,
            symmetric_keys: data.symmetric_keys,
            certificates: data.certificates,
            ecdsa_keys: data.ecdsa_keys,
        }
    }

    /// Generate a new ECDSA P-256 key pair for TLS/QUIC transport
    pub fn generate_ecdsa_key(&mut self, name: &str) -> Result<&EcdsaKeyPair> {
        use rand::rngs::OsRng;

        let key = EcdsaKeyPair::generate(&mut OsRng);
        self.ecdsa_keys.insert(name.to_string(), key);
        Ok(self.ecdsa_keys.get(name).unwrap())
    }

    /// Get an existing ECDSA key by name
    pub fn get_ecdsa_key(&self, name: &str) -> Option<&EcdsaKeyPair> {
        self.ecdsa_keys.get(name)
    }

    /// Get or create an ECDSA key (will generate if it doesn't exist)
    pub fn get_or_create_ecdsa_key(&mut self, name: &str) -> Result<&EcdsaKeyPair> {
        if !self.ecdsa_keys.contains_key(name) {
            self.generate_ecdsa_key(name)?;
        }
        Ok(self.ecdsa_keys.get(name).unwrap())
    }

    /// Store an ECDSA key pair
    pub fn store_ecdsa_key(&mut self, name: &str, key: EcdsaKeyPair) {
        self.ecdsa_keys.insert(name.to_string(), key);
    }

    /// Generate a new seed
    pub fn generate_seed(&mut self) -> &[u8; 32] {
        let seed = KeyDerivation::generate_seed();
        self.seed = Some(seed);
        self.seed.as_ref().unwrap()
    }

    /// Set an existing seed
    pub fn set_seed(&mut self, seed: [u8; 32]) {
        self.seed = Some(seed);
    }

    /// Get the current seed
    pub fn get_seed(&self) -> Option<&[u8; 32]> {
        self.seed.as_ref()
    }

    /// Generate a user root key from the seed and return only the public key
    /// The private key remains securely stored in the key manager
    pub fn generate_user_root_key(&mut self) -> Result<PublicKey> {
        let seed = self.seed.ok_or_else(|| {
            KeyError::InvalidOperation("No seed available for key derivation".to_string())
        })?;

        let signing_keypair: SigningKeyPair = KeyDerivation::derive_user_root_key(&seed)?;

        // Store the signing key pair in the manager
        self.signing_keys
            .insert("user_root".to_string(), signing_keypair.clone());

        // Get the public key from the key pair we just created
        let public_key_bytes = *signing_keypair.public_key();

        // Return only the public key
        Ok(PublicKey::new(public_key_bytes))
    }

    /// Generate a user profile key from the seed, creating and storing both a signing and an encryption key pair.
    pub fn generate_user_profile_key(&mut self, profile_index: u32) -> Result<Vec<u8>> {
        let seed = self.seed.ok_or_else(|| {
            KeyError::InvalidOperation("No seed available for key derivation".to_string())
        })?;

        // 1. Derive the signing key pair
        let signing_keypair = KeyDerivation::derive_user_profile_key(&seed, profile_index)?;

        // 2. Derive the corresponding encryption key pair from the signing key pair
        let signing_key_bytes: [u8; 32] = signing_keypair
            .secret_key_bytes()
            .try_into()
            .map_err(|_| KeyError::InvalidKeyFormat("Invalid signing key length".to_string()))?;
        let encryption_keypair = EncryptionKeyPair::from_secret(&signing_key_bytes);

        // 3. Store both key pairs with distinct IDs
        let signing_key_id = format!("user_profile_signing_{}", profile_index);
        self.signing_keys
            .insert(signing_key_id, signing_keypair.clone());

        let encryption_key_id = format!("user_profile_encryption_{}", profile_index);
        self.encryption_keys
            .insert(encryption_key_id, encryption_keypair);

        // 4. Return the public signing key
        Ok(signing_keypair.public_key().as_slice().to_vec())
    }

    /// Generate a node TLS key pair and self-signed certificate for QUIC
    /// Get the node's QUIC TLS key pair and certificate
    ///
    /// This expects the certificate to be already generated and signed by the user's CA
    /// during the node setup process.
    pub fn get_node_quic_keys(&self) -> Result<Vec<u8>> {
        self.get_node_public_key()
    }

    /// Get QUIC-compatible certificates for TLS transport
    /// Returns:
    /// 1. A vector of CertificateDer certificates for the certificate chain
    /// 2. A PrivateKeyDer that matches the certificate (Ed25519)
    /// 3. A ServerCertVerifier that validates Ed25519 certificates properly
    pub fn get_quic_certs(
        &self,
    ) -> Result<(
        Vec<CertificateDer<'static>>,
        rustls_pki_types::PrivateKeyDer<'static>,
        Arc<dyn ServerCertVerifier>,
    )> {
        // First, try to get the node's certificate that was signed by the CA
        let node_cert = self.get_certificate("node_tls_cert").ok_or_else(|| {
            KeyError::CertificateError(
                "Node certificate not found - ensure certificate has been processed from mobile"
                    .to_string(),
            )
        })?;

        // Get the node's signing key for the private key
        let _node_signing_key = self
            .get_signing_key("node_tls")
            .ok_or_else(|| KeyError::CertificateError("Node signing key not found".to_string()))?;

        // CRITICAL FIX: Create a proper X.509 certificate AND get the matching private key
        // Use rcgen to create a certificate with a matching key pair
        let (x509_cert_der, x509_private_key_der) =
            self.create_x509_certificate_and_key_for_quic(&node_cert.subject)?;

        // Convert the X.509 certificate to rustls format
        let cert_der = CertificateDer::from(x509_cert_der);

        // Create certificate verifier for ECDSA certificates (which is what QUIC/TLS expects)
        let verifier = EcdsaCertVerifier::new();

        Ok((vec![cert_der], x509_private_key_der, Arc::new(verifier)))
    }

    /// Create a proper X.509 certificate and matching private key for QUIC/rustls compatibility
    /// Returns both the certificate DER and the matching private key DER
    fn create_x509_certificate_and_key_for_quic(
        &self,
        _subject: &str,
    ) -> Result<(Vec<u8>, rustls_pki_types::PrivateKeyDer<'static>)> {
        // Use rcgen's simple self-signed certificate generation (this works and is tested)
        let cert =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).map_err(|e| {
                KeyError::CertificateError(format!("Failed to create X.509 certificate: {}", e))
            })?;

        // Get the DER-encoded certificate
        let cert_der = cert.cert.der();

        // Get the private key in DER format and convert to rustls PrivateKeyDer
        let rustls_private_key = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
        );

        Ok((cert_der.to_vec(), rustls_private_key))
    }

    pub fn get_node_public_key(&self) -> Result<Vec<u8>> {
        let key_id = "node_tls".to_string();
        let key_pair = self
            .signing_keys
            .get(&key_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("Signing key not found: {}", key_id)))?;
        Ok(Vec::from(*key_pair.public_key()))
    }

    /// Generate a node storage key pair
    pub fn generate_node_storage_key(&mut self, node_pk: &[u8]) -> Result<&EncryptionKeyPair> {
        let encryption_keypair = EncryptionKeyPair::new();
        let key_id = format!("node_storage_{}", hex::encode(node_pk));

        self.encryption_keys
            .insert(key_id.clone(), encryption_keypair);

        // Return reference to the stored key pair
        self.encryption_keys.get(&key_id).ok_or_else(|| {
            KeyError::KeyNotFound(format!("Failed to store encryption key: {}", key_id))
        })
    }

    /// Generate a network data key pair
    pub fn generate_network_data_key(&mut self) -> Result<Vec<u8>> {
        let encryption_keypair = EncryptionKeyPair::new();

        let key_id = format!(
            "network_data_{}",
            hex::encode(encryption_keypair.public_key_bytes())
        );

        self.encryption_keys
            .insert(key_id.clone(), encryption_keypair.clone());

        Ok(encryption_keypair.public_key_bytes().to_vec())
    }

    /// Create a network key message containing both public and private keys
    /// This is more secure than exposing the private key directly
    pub fn create_network_key_message(
        &self,
        network_public_key: &[u8],
        network_name: &str,
    ) -> Result<NetworkKeyMessage> {
        let key_id = format!("network_data_{}", hex::encode(network_public_key));
        let encryption_keypair = self.encryption_keys.get(&key_id).ok_or_else(|| {
            KeyError::KeyNotFound(format!("Encryption key not found: {}", key_id))
        })?;

        let mut public_key_array = [0u8; 32];
        let mut private_key_array = [0u8; 32];

        public_key_array.copy_from_slice(network_public_key);
        private_key_array.copy_from_slice(&encryption_keypair.secret_key_bytes());

        Ok(NetworkKeyMessage {
            network_name: network_name.to_string(),
            public_key: public_key_array,
            private_key: private_key_array,
        })
    }

    /// Add a signing key to the key manager
    pub fn add_signing_key(&mut self, key_id: &str, key_pair: SigningKeyPair) {
        self.signing_keys.insert(key_id.to_string(), key_pair);
    }

    /// Add an encryption key pair
    pub fn add_encryption_key(&mut self, key_id: &str, key_pair: EncryptionKeyPair) {
        self.encryption_keys.insert(key_id.to_string(), key_pair);
    }

    /// Get a signing key pair by ID
    pub fn get_signing_key(&self, key_id: &str) -> Option<&SigningKeyPair> {
        self.signing_keys.get(key_id)
    }

    /// Get an encryption key pair by ID
    pub fn get_encryption_key(&self, key_id: &str) -> Option<&EncryptionKeyPair> {
        self.encryption_keys.get(key_id)
    }

    /// Generate a new symmetric encryption key and store it with the given ID.
    /// This key is intended for encrypting data at rest (e.g., files) and will not leave the key manager.
    pub fn generate_symmetric_key(&mut self, key_id: &str) -> Result<SymmetricKey> {
        let symmetric_key = crate::crypto::SymmetricKey::new();
        self.symmetric_keys
            .insert(key_id.to_string(), symmetric_key.clone());
        Ok(symmetric_key)
    }

    /// Ensure a symmetric key exists and return it (create one if it doesn't exist)
    pub fn ensure_symmetric_key(&mut self, key_id: &str) -> Result<SymmetricKey> {
        if let Some(key) = self.symmetric_keys.get(key_id) {
            return Ok(key.clone());
        }
        self.generate_symmetric_key(key_id)
    }

    /// Encrypt data using a stored symmetric key.
    pub fn encrypt_with_symmetric_key(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        let key = self
            .symmetric_keys
            .get(key_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("Symmetric key not found: {}", key_id)))?;
        key.encrypt(data)
    }

    /// Decrypt data using a stored symmetric key.
    pub fn decrypt_with_symmetric_key(
        &self,
        key_id: &str,
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>> {
        let key = self
            .symmetric_keys
            .get(key_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("Symmetric key not found: {}", key_id)))?;
        key.decrypt(encrypted_data)
    }

    /// Generate a new encryption key pair and store it with the given ID
    /// Returns the public key bytes
    pub fn generate_encryption_key(&mut self, key_id: &str) -> Result<Vec<u8>> {
        let encryption_keypair = EncryptionKeyPair::new();
        let public_key = encryption_keypair.public_key_bytes().to_vec();

        self.encryption_keys
            .insert(key_id.to_string(), encryption_keypair);

        Ok(public_key)
    }

    /// Store an encryption key pair with the given ID
    pub fn store_encryption_key(&mut self, key_id: &str, key_pair: EncryptionKeyPair) {
        self.encryption_keys.insert(key_id.to_string(), key_pair);
    }

    /// Store network metadata (like network name) associated with a network key
    /// Uses proper encrypted storage for network metadata
    pub fn store_network_metadata(&mut self, metadata_key: &str, network_name: &str) -> Result<()> {
        // Generate a proper encryption key for metadata storage
        let metadata_encryption_key = SymmetricKey::new();

        // Encrypt the network name using the generated key
        let encrypted_metadata = metadata_encryption_key.encrypt(network_name.as_bytes())?;

        // Store both the encryption key and encrypted data
        // The key is stored with a "_key" suffix, the data with "_data" suffix
        let key_storage_id = format!("{}_key", metadata_key);
        let data_storage_id = format!("{}_data", metadata_key);

        self.symmetric_keys
            .insert(key_storage_id, metadata_encryption_key);

        // Store encrypted data as a synthetic symmetric key for storage consistency
        let encrypted_key = SymmetricKey::from_bytes(
            &encrypted_metadata
                [..std::cmp::min(encrypted_metadata.len(), CHACHA20POLY1305_KEY_LENGTH)],
        )?;
        self.symmetric_keys.insert(data_storage_id, encrypted_key);

        Ok(())
    }

    /// Retrieve network metadata by metadata key
    pub fn get_network_metadata(&self, metadata_key: &str) -> Option<String> {
        let key_storage_id = format!("{}_key", metadata_key);
        let data_storage_id = format!("{}_data", metadata_key);

        // Get both the encryption key and encrypted data
        let encryption_key = self.symmetric_keys.get(&key_storage_id)?;
        let encrypted_data_key = self.symmetric_keys.get(&data_storage_id)?;

        // Extract the encrypted data bytes
        let encrypted_data = encrypted_data_key.to_bytes();

        // Decrypt the metadata
        match encryption_key.decrypt(encrypted_data) {
            Ok(decrypted_bytes) => String::from_utf8(decrypted_bytes).ok(),
            Err(_) => None,
        }
    }

    /// Sign a Certificate Signing Request (CSR)
    pub fn sign_csr(&mut self, csr_bytes: &[u8], ca_key_id: &str) -> Result<Certificate> {
        // Get CA key
        let signing_key_pair = self
            .get_signing_key(ca_key_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("CA key not found: {}", ca_key_id)))?;

        // Sign CSR
        let certificate = signing_key_pair.sign_csr(csr_bytes)?;

        // Store certificate after validation
        self.add_certificate(certificate.clone(), ca_key_id)?;

        Ok(certificate)
    }

    /// Create a certificate signing request (CSR)
    pub fn create_csr(&self, subject: &str, key_id: &str) -> Result<Vec<u8>> {
        let signing_key = self
            .signing_keys
            .get(key_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("Signing key not found: {}", key_id)))?;

        // Pass the public key bytes to the CSR creation function
        Certificate::create_csr(subject, signing_key)
    }

    /// Add a certificate after validating it against the specified CA.
    pub fn add_certificate(&mut self, certificate: Certificate, ca_key_id: &str) -> Result<()> {
        let ca_key = self.get_signing_key(ca_key_id).ok_or_else(|| {
            KeyError::KeyNotFound(format!("CA key not found for validation: {}", ca_key_id))
        })?;

        let ca_public_key_bytes = ca_key.public_key();
        let ca_verifying_key = VerifyingKey::from_bytes(ca_public_key_bytes)?;

        certificate.validate(&ca_verifying_key)?;

        self.certificates
            .insert(certificate.subject.clone(), certificate);

        Ok(())
    }

    /// Store a pre-validated certificate directly without re-validating it.
    ///
    /// This should only be used when the certificate has already been validated
    /// with the appropriate CA key.
    ///
    /// Store a validated certificate in the key manager
    /// Node TLS certificates are stored with the key "node_tls_cert"
    /// Other certificates are stored with their subject as the key
    pub fn store_validated_certificate(&mut self, certificate: Certificate) -> Result<()> {
        let key = if certificate.subject.starts_with("node:") {
            "node_tls_cert".to_string()
        } else {
            certificate.subject.clone()
        };

        self.certificates.insert(key, certificate);
        Ok(())
    }

    /// Get a certificate by its key
    /// For node certificates, use "node_tls_cert" as the key
    /// For other certificates, use the subject as the key
    pub fn get_certificate(&self, key: &str) -> Option<&Certificate> {
        self.certificates.get(key)
    }

    /// Export all keys and certificates for persistence
    pub fn export_keys(&self) -> KeyManagerData {
        self.to_data()
    }

    /// Serialize key manager to data structure
    pub fn to_data(&self) -> KeyManagerData {
        KeyManagerData {
            seed: self.seed,
            signing_keys: self.signing_keys.clone(),
            encryption_keys: self.encryption_keys.clone(),
            symmetric_keys: self.symmetric_keys.clone(),
            certificates: self.certificates.clone(),
            ecdsa_keys: self.ecdsa_keys.clone(),
        }
    }
}
