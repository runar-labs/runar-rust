use crate::error::{KeyError, Result};
use aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce}; // Note: Nonce is from aead, but often re-exported
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hex;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use rand::RngCore;
use sha2::Sha256;
use std::convert::TryInto;
use std::time::{SystemTime, UNIX_EPOCH};

/// The length of an Ed25519 public key in bytes
pub const ED25519_PUBLIC_KEY_LENGTH: usize = 32;
/// The length of an Ed25519 private key in bytes
pub const ED25519_SECRET_KEY_LENGTH: usize = 32;
/// The length of an Ed25519 signature in bytes
pub const ED25519_SIGNATURE_LENGTH: usize = 64;
/// The length of an X25519 public key in bytes
pub const X25519_PUBLIC_KEY_LENGTH: usize = 32;
/// The length of an X25519 private key in bytes
pub const X25519_SECRET_KEY_LENGTH: usize = 32;
/// The length of a symmetric encryption key in bytes
pub const SYMMETRIC_KEY_LENGTH: usize = 32;
/// The length of a nonce for AES-GCM in bytes
pub const NONCE_LENGTH: usize = 12;
/// The length of a salt for HKDF in bytes
pub const SALT_LENGTH: usize = 32;

/// Represents a signing key pair (Ed25519)
#[derive(Clone)]
pub struct SigningKeyPair {
    signing_key: SigningKey,
    public_key: Vec<u8>,
}

impl SigningKeyPair {
    /// Generate a new random signing key pair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            public_key: verifying_key.to_bytes().to_vec(),
        }
    }

    /// Create a key pair from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ED25519_SECRET_KEY_LENGTH * 2 {
            return Err(KeyError::InvalidKeyLength);
        }

        let secret_bytes: [u8; ED25519_SECRET_KEY_LENGTH] = bytes[..ED25519_SECRET_KEY_LENGTH]
            .try_into()
            .map_err(|_| KeyError::InvalidKeyLength)?;

        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        let public_key = verifying_key.to_bytes().to_vec();

        Ok(Self {
            signing_key,
            public_key,
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Get a reference to the signing key
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Get the secret key as bytes
    pub fn secret_key_bytes(&self) -> [u8; ED25519_SECRET_KEY_LENGTH] {
        self.signing_key.to_bytes()
    }

    /// Sign a message with the private key
    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        Ok(self.signing_key.sign(message))
    }

    /// Sign a CSR (Certificate Signing Request)
    pub fn sign_csr(&self, csr_data: &[u8]) -> Result<Certificate> {
        Certificate::sign_csr(self, csr_data)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.signing_key
            .verifying_key()
            .verify(message, signature)
            .map_err(|e| KeyError::SignatureError(format!("Signature verification failed: {}", e)))
    }
}

/// Represents an encryption key pair (X25519 for ECDH)
#[derive(Clone)]
pub struct EncryptionKeyPair {
    secret: X25519StaticSecret,
    public: X25519PublicKey,
}

impl EncryptionKeyPair {
    /// Generate a new random X25519 key pair for encryption.
    pub fn generate() -> Self {
        let secret = X25519StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Create an X25519 key pair from a 32-byte secret.
    pub fn from_secret(secret_bytes: &[u8; 32]) -> Self {
        let secret = X25519StaticSecret::from(*secret_bytes);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Convert an Ed25519 signing key pair to an X25519 key agreement key pair.
    /// This is the standard method for deriving a Curve25519 key from an Ed25519 key.
    pub fn from_key_pair(key_pair: &SigningKeyPair) -> Self {
        let secret = X25519StaticSecret::from(key_pair.signing_key().to_bytes());
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Get the public key.
    pub fn public_key(&self) -> &X25519PublicKey {
        &self.public
    }

    /// Get the secret key as bytes.
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Derive a shared secret using ECDH (X25519).
    pub fn derive_shared_secret(&self, peer_public_key: &X25519PublicKey) -> [u8; 32] {
        self.secret.diffie_hellman(peer_public_key).to_bytes()
    }

    /// Generate a symmetric key from a shared secret using HKDF-SHA256.
    /// This is a robust way to get a cryptographically strong key for symmetric encryption.
    pub fn generate_symmetric_key(shared_secret: &[u8]) -> Result<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(None, shared_secret);
        let mut okm = [0u8; 32]; // Output Key Material
        hk.expand(&[], &mut okm)
            .map_err(|e| KeyError::CryptoError(format!("HKDF expand failed: {}", e)))?;
        Ok(okm)
    }
}

/// Symmetric encryption operations using ChaCha20-Poly1305
pub struct SymmetricEncryption;

impl SymmetricEncryption {
    /// Generate a random symmetric key
    pub fn generate_key() -> [u8; SYMMETRIC_KEY_LENGTH] {
        let mut key = [0u8; SYMMETRIC_KEY_LENGTH];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Generate a random nonce
    pub fn generate_nonce() -> Result<[u8; NONCE_LENGTH]> {
        let mut nonce = [0u8; NONCE_LENGTH];
        OsRng.fill_bytes(&mut nonce);
        Ok(nonce)
    }

    /// Encrypt data using a symmetric key with ChaCha20-Poly1305.
    pub fn encrypt(key: &[u8; 32], data: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_LENGTH])> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce_bytes = Self::generate_nonce()?;
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(&nonce, data.as_ref())
            .map_err(|e| KeyError::EncryptionError(e.to_string()))?;
        Ok((ciphertext, nonce_bytes))
    }

    /// Decrypt data using a symmetric key with ChaCha20-Poly1305.
    pub fn decrypt(
        key: &[u8; 32],
        ciphertext: &[u8],
        nonce: &[u8; NONCE_LENGTH],
    ) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|e| KeyError::CryptoError(format!("Decryption failed: {}", e)))?;

        Ok(plaintext)
    }
}

/// Certificate signing request (CSR)
pub struct CSR {
    /// Subject of the CSR
    pub subject: String,
    /// Public key of the subject
    pub public_key: Vec<u8>,
    /// CSR data
    pub data: String,
}

/// Certificate related operations
#[derive(Clone)]
pub struct Certificate {
    pub subject: String,
    pub issuer: String,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub valid_from: u64,
    pub valid_until: u64,
    pub data: String,
}

impl Certificate {
    /// Parse a CSR from bytes
    pub fn parse_csr(csr_bytes: &[u8]) -> Result<CSR> {
        //TODO FIX this.. we DO NOT WANT SHORCUTS LIKE THIS.. we are after a real implementation
        //replace this simplified approach with a proper robust imnplementaion parsing the CSR properly

        // Extract subject and public key from CSR
        // In a real implementation, this would parse the CSR properly
        if csr_bytes.len() < 32 {
            return Err(KeyError::CryptoError("Invalid CSR format".to_string()));
        }

        // Find the first null byte or end of string to determine subject length
        let mut subject_end = 0;
        for (i, &byte) in csr_bytes.iter().enumerate() {
            if byte == 0 || i >= 32 {
                subject_end = i;
                break;
            }
        }

        let subject = String::from_utf8_lossy(&csr_bytes[0..subject_end]).to_string();

        // The public key is the rest of the data
        let public_key = if subject_end < csr_bytes.len() {
            csr_bytes[subject_end..].to_vec()
        } else {
            // If there's no public key data, use an empty vector
            Vec::new()
        };

        // Create CSR data
        let data = format!("{}.{}", subject, hex::encode(&public_key));

        Ok(CSR {
            subject,
            public_key,
            data,
        })
    }

    /// Create a certificate signing request (CSR)
    pub fn create_csr(subject: &str, public_key: &[u8]) -> Result<Vec<u8>> {
        // For now, just combine the subject and public key
        //TODO shoudl the CST contain more things ?
        let mut csr = Vec::new();
        csr.extend_from_slice(subject.as_bytes());
        csr.extend_from_slice(public_key);

        Ok(csr)
    }

    /// Sign a CSR
    pub fn sign_csr(signing_key_pair: &SigningKeyPair, csr_data: &[u8]) -> Result<Certificate> {
        // Parse the CSR data
        let csr = Certificate::parse_csr(csr_data)?;

        // Sign the CSR data
        let signature = signing_key_pair.sign(csr_data.as_ref())?;

        // The issuer is the CA that signed the certificate
        let issuer = format!("ca:{}", hex::encode(signing_key_pair.public_key()));

        Ok(Certificate {
            subject: csr.subject,
            issuer,
            public_key: csr.public_key,
            signature: signature.to_bytes().to_vec(),
            valid_from: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            valid_until: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 31536000, // 1 year
            data: csr.data,
        })
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        if signature.len() != 64 {
            return Err(KeyError::SignatureError(
                "Invalid signature length".to_string(),
            ));
        }

        // Convert signature bytes to Signature
        let signature_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| KeyError::SignatureError("Failed to convert signature".to_string()))?;

        // In ed25519-dalek 2.x, from_bytes returns a Signature directly, not a Result
        let signature = Signature::from_bytes(&signature_bytes);

        // Convert public key bytes to VerifyingKey
        let public_key_bytes: [u8; 32] = self.public_key[..32]
            .try_into()
            .map_err(|_| KeyError::CryptoError("Failed to convert public key bytes".to_string()))?;

        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|e| KeyError::CryptoError(format!("Invalid public key: {}", e)))?;

        // Verify signature
        match verifying_key.verify(message, &signature) {
            Ok(_) => Ok(true),
            Err(e) => Err(KeyError::SignatureError(format!(
                "Signature verification failed: {}",
                e
            ))),
        }
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
