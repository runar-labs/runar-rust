use crate::error::{KeyError, Result};
use aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hex;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::convert::TryInto;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

/// The length of an Ed25519 public key in bytes
pub const ED25519_PUBLIC_KEY_LENGTH: usize = 32;

/// The length of an Ed25519 secret key in bytes
pub const ED25519_SECRET_KEY_LENGTH: usize = 32;

/// The length of a ChaCha20Poly1305 key in bytes
pub const CHACHA20POLY1305_KEY_LENGTH: usize = 32;

/// The length of a ChaCha20Poly1305 nonce in bytes
pub const CHACHA20POLY1305_NONCE_LENGTH: usize = 12;

/// Represents a public key that can be safely returned from key manager methods
/// This follows the principle that manager methods should not expose private keys
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// The raw bytes of the public key
    bytes: [u8; 32],
}

impl PublicKey {
    /// Create a new PublicKey from raw bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }
    
    /// Get the raw bytes of the public key
    pub fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// Represents a key pair for signing
#[derive(Clone)]
pub struct SigningKeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl SigningKeyPair {
    /// Generate a new signing key pair
    pub fn new() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        Self { signing_key, verifying_key }
    }

    /// Create a signing key pair from a secret key
    pub fn from_secret(secret: &[u8]) -> Self {
        let secret_key_bytes: [u8; 32] = secret[..32].try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&secret_key_bytes);
        let verifying_key = signing_key.verifying_key();
        Self { signing_key, verifying_key }
    }

    /// Get the public key
    pub fn public_key(&self) -> &[u8; 32] {
        self.verifying_key.as_bytes()
    }

    /// Get the secret key bytes
    pub fn secret_key_bytes(&self) -> &[u8] {
        self.signing_key.as_bytes()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    pub fn sign_csr(&self, csr_bytes: &[u8]) -> Result<Certificate> {
        let csr = Certificate::parse_csr(csr_bytes)?;
        let subject = csr.subject;
        let public_key = csr.public_key;
        let issuer = format!("ca:{}", hex::encode(self.public_key()));

        let mut certificate = Certificate::new(&subject, &issuer, &public_key)?;

        let data_to_sign = certificate.get_signed_data()?;
        let signature = self.sign(&data_to_sign);
        certificate.signature = signature.to_vec();

        Ok(certificate)
    }
}

/// Represents a key pair for encryption
#[derive(Clone)]
pub struct EncryptionKeyPair {
    secret_key: X25519StaticSecret,
    public_key: X25519PublicKey,
}

impl EncryptionKeyPair {
    /// Generate a new encryption key pair
    pub fn new() -> Self {
        let secret_key = X25519StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public_key = X25519PublicKey::from(&secret_key);
        Self { secret_key, public_key }
    }

    /// Create an encryption key pair from a secret key
    pub fn from_secret(secret: &[u8]) -> Self {
        let secret_bytes: [u8; 32] = secret[..32].try_into().unwrap();
        let secret_key = X25519StaticSecret::from(secret_bytes);
        let public_key = X25519PublicKey::from(&secret_key);
        Self { secret_key, public_key }
    }

    /// Create an encryption key pair from just a public key
    /// 
    /// This can only be used for encryption, not decryption, since the private key is zeroed.
    /// Useful when you need to encrypt data for a recipient whose public key you know.
    pub fn from_public_key(public_key_bytes: &[u8]) -> Result<Self> {
        if public_key_bytes.len() != 32 {
            return Err(KeyError::InvalidKeyFormat("Public key must be 32 bytes".to_string()));
        }
        
        // Create a zeroed secret key - this key pair can only be used for encryption
        let secret_key = X25519StaticSecret::from([0u8; 32]);
        
        // Convert the provided bytes to an X25519PublicKey
        let mut public_key_array = [0u8; 32];
        public_key_array.copy_from_slice(&public_key_bytes[..32]);
        let public_key = X25519PublicKey::from(public_key_array);
        
        Ok(Self {
            secret_key,
            public_key,
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> &[u8; 32] {
        self.public_key.as_bytes()
    }

    /// Get the secret key
    pub fn secret_key(&self) -> &[u8] {
        self.secret_key.as_bytes()
    }

    /// Encrypt data for a recipient
    pub fn encrypt(&self, data: &[u8], recipient_public_key: &[u8]) -> Result<Vec<u8>> {
        let recipient_pk_bytes: [u8; 32] = recipient_public_key[..32].try_into().map_err(|_| {
            KeyError::InvalidKeyFormat("Recipient public key must be 32 bytes".to_string())
        })?;
        let recipient_pk = X25519PublicKey::from(recipient_pk_bytes);

        let shared_secret = self.secret_key.diffie_hellman(&recipient_pk);

        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut okm = [0u8; CHACHA20POLY1305_KEY_LENGTH];
        hk.expand(&[], &mut okm)?;

        let cipher = ChaCha20Poly1305::new(&okm.into());
        let mut nonce_bytes = [0u8; CHACHA20POLY1305_NONCE_LENGTH];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, data).map_err(|e| KeyError::CryptoError(e.to_string()))?;

        let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data from a sender
    pub fn decrypt(&self, encrypted_data: &[u8], sender_public_key: &[u8]) -> Result<Vec<u8>> {
        let sender_pk_bytes: [u8; 32] = sender_public_key[..32].try_into().map_err(|_| {
            KeyError::InvalidKeyFormat("Sender public key must be 32 bytes".to_string())
        })?;
        let sender_pk = X25519PublicKey::from(sender_pk_bytes);

        let shared_secret = self.secret_key.diffie_hellman(&sender_pk);

        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut okm = [0u8; CHACHA20POLY1305_KEY_LENGTH];
        hk.expand(&[], &mut okm)?;

        let cipher = ChaCha20Poly1305::new(&okm.into());

        let (nonce_bytes, ciphertext) = encrypted_data.split_at(CHACHA20POLY1305_NONCE_LENGTH);
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher.decrypt(nonce, ciphertext).map_err(|e| KeyError::CryptoError(e.to_string()))
    }
}

/// Certificate Signing Request
#[derive(Debug)]
pub struct CSR {
    pub subject: String,
    pub public_key: Vec<u8>,
}

/// Certificate related operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub subject: String,
    pub issuer: String,
    pub public_key: Vec<u8>,
    #[serde(default)]
    pub signature: Vec<u8>,
    pub valid_from: u64,
    pub valid_until: u64,
}

impl Certificate {
    fn get_signed_data(&self) -> Result<Vec<u8>> {
        // Create a temporary struct with the same data but empty signature
        // This ensures consistent serialization for both signing and verification
        let data_to_sign = (
            &self.subject,
            &self.issuer,
            &self.public_key,
            &self.valid_from,
            &self.valid_until
        );
        
        bincode::serialize(&data_to_sign).map_err(|e| KeyError::SerializationError(e.to_string()))
    }

    /// Parse a CSR from bytes
    pub fn parse_csr(csr_bytes: &[u8]) -> Result<CSR> {
        //TODO FIX this.. we DO NOT WANT SHORCUTS LIKE THIS.. we are after a real implementation
        let csr_str = String::from_utf8(csr_bytes.to_vec())
            .map_err(|_| KeyError::InvalidKeyFormat("Invalid CSR format".to_string()))?;
        
        // First, verify that the string starts with "csr:"
        if !csr_str.starts_with("csr:") {
            return Err(KeyError::InvalidKeyFormat("Invalid CSR format: missing csr: prefix".to_string()));
        }
        
        // Remove the "csr:" prefix
        let without_prefix = &csr_str[4..];
        
        // Find the last colon which separates the subject from the public key
        let last_colon_pos = without_prefix.rfind(':').ok_or_else(|| {
            KeyError::InvalidKeyFormat("Invalid CSR format: missing public key".to_string())
        })?;
        
        // Extract the subject and the public key hex
        let subject = &without_prefix[..last_colon_pos];
        let pk_hex = &without_prefix[last_colon_pos + 1..];
        
        // Decode the public key hex
        let public_key = hex::decode(pk_hex)
            .map_err(|_| KeyError::InvalidKeyFormat("Invalid public key in CSR".to_string()))?;

        Ok(CSR {
            subject: subject.to_string(),
            public_key,
        })
    }

    /// Create a CSR
    pub fn create_csr(subject: &str, public_key: &[u8]) -> Result<Vec<u8>> {
        let pk_hex = hex::encode(public_key);
        let csr_str = format!("csr:{}:{}", subject, pk_hex);
        Ok(csr_str.into_bytes())
    }

    /// Create a new certificate
    pub fn new(subject: &str, issuer: &str, public_key: &[u8]) -> Result<Self> {
        let valid_from = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let valid_until = valid_from + 31536000; // 1 year

        Ok(Certificate {
            subject: subject.to_string(),
            issuer: issuer.to_string(),
            public_key: public_key.to_vec(),
            signature: Vec::new(), // Signature is added later
            valid_from,
            valid_until,
        })
    }

    /// Validate the certificate against a CA's public key.
    pub fn validate(&self, ca_public_key: &VerifyingKey) -> Result<()> {
        // 1. Verify the signature
        let signature_bytes: [u8; 64] = self.signature.as_slice().try_into()?;
        let signature = Signature::from_bytes(&signature_bytes);
        let data_to_verify = self.get_signed_data()?;
        if ca_public_key.verify(&data_to_verify, &signature).is_err() {
            return Err(KeyError::SignatureError("Certificate signature verification failed".to_string()));
        }

        // 2. Check the validity period
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        if current_time < self.valid_from {
            return Err(KeyError::InvalidOperation("Certificate is not yet valid".to_string()));
        }

        if current_time > self.valid_until {
            return Err(KeyError::InvalidOperation("Certificate has expired".to_string()));
        }

        Ok(())
    }

    /// Check if the certificate is currently valid
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now >= self.valid_from && now <= self.valid_until
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::VerifyingKey;

    #[test]
    fn test_certificate_serialization_consistency() {
        let cert = Certificate {
            subject: "test_subject".to_string(),
            issuer: "test_issuer".to_string(),
            public_key: vec![1, 2, 3],
            signature: vec![],
            valid_from: 100,
            valid_until: 200,
        };

        let serialized1 = cert.get_signed_data().unwrap();
        let serialized2 = cert.get_signed_data().unwrap();

        assert_eq!(
            serialized1,
            serialized2,
            "Serialization should be deterministic"
        );
    }

    #[test]
    fn test_certificate_validation_edge_cases() {
        // 1. Setup CA and subject keys
        let ca_keypair = SigningKeyPair::new();
        let subject_keypair = SigningKeyPair::new();
        let ca_verifying_key = VerifyingKey::from_bytes(ca_keypair.public_key()).unwrap();

        // --- Test Case: Valid Certificate ---
        let mut valid_cert = Certificate::new("subject", "ca", subject_keypair.public_key()).unwrap();
        let data_to_sign = valid_cert.get_signed_data().unwrap();
        valid_cert.signature = ca_keypair.sign(&data_to_sign).to_bytes().to_vec();

        assert!(valid_cert.validate(&ca_verifying_key).is_ok());
        assert!(valid_cert.is_valid());

        // --- Test Case: Expired Certificate ---
        let mut expired_cert = Certificate::new("subject", "ca", subject_keypair.public_key()).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        expired_cert.valid_from = now - 1000;
        expired_cert.valid_until = now - 1; // Expired 1 second ago
        let data_to_sign = expired_cert.get_signed_data().unwrap();
        expired_cert.signature = ca_keypair.sign(&data_to_sign).to_bytes().to_vec();

        let validation_result = expired_cert.validate(&ca_verifying_key);
        assert!(validation_result.is_err());
        match validation_result.unwrap_err() {
            KeyError::InvalidOperation(msg) => assert_eq!(msg, "Certificate has expired"),
            _ => panic!("Expected InvalidOperation error for expired certificate"),
        }
        assert!(!expired_cert.is_valid());

        // --- Test Case: Not-Yet-Valid Certificate ---
        let mut future_cert = Certificate::new("subject", "ca", subject_keypair.public_key()).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        future_cert.valid_from = now + 1000; // Valid in the future
        future_cert.valid_until = now + 2000;
        let data_to_sign = future_cert.get_signed_data().unwrap();
        future_cert.signature = ca_keypair.sign(&data_to_sign).to_bytes().to_vec();

        let validation_result = future_cert.validate(&ca_verifying_key);
        assert!(validation_result.is_err());
        match validation_result.unwrap_err() {
            KeyError::InvalidOperation(msg) => assert_eq!(msg, "Certificate is not yet valid"),
            _ => panic!("Expected InvalidOperation error for future certificate"),
        }
        assert!(!future_cert.is_valid());

        // --- Test Case: Invalid Signature ---
        let impostor_ca_keypair = SigningKeyPair::new();
        let mut cert_with_bad_sig =
            Certificate::new("subject", "ca", subject_keypair.public_key()).unwrap();
        let data_to_sign = cert_with_bad_sig.get_signed_data().unwrap();
        // Sign with the wrong CA
        cert_with_bad_sig.signature = impostor_ca_keypair.sign(&data_to_sign).to_bytes().to_vec();

        // Validate with the correct CA's public key
        let validation_result = cert_with_bad_sig.validate(&ca_verifying_key);
        assert!(validation_result.is_err());
        match validation_result.unwrap_err() {
            KeyError::SignatureError(_) => {
                /* Expected */
            }
            _ => panic!("Expected SignatureError for invalid signature"),
        }
    }
}
