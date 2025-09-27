use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    certificate::EcdsaKeyPair,
    error::{KeyError, Result},
};

/// Enrollment token body containing the token metadata and permissions
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EnrollmentTokenBody {
    /// 16 random bytes hex
    pub token_id: String,
    /// compact_id of owner network
    pub network_id: String,
    /// Optional subject hint for the enrollment
    pub subject_hint: Option<String>,
    /// UNIX seconds - token valid from
    pub not_before: u64,
    /// UNIX seconds - token expires at
    pub expires_at: u64,
    /// Anti-replay nonce
    pub nonce: [u8; 16],
    /// Permissions granted by this token
    pub permissions: Vec<String>, // ["enroll"], future: ["renew"]
}

/// Signed enrollment token envelope
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EnrollmentToken {
    /// The token body
    pub body: EnrollmentTokenBody,
    /// ECDSA P-256 DER signature
    pub signature: Vec<u8>,
    /// compact_id of EA public key
    pub signer_id: String,
}

impl EnrollmentTokenBody {
    /// Create a new enrollment token body
    pub fn new(
        token_id: String,
        network_id: String,
        subject_hint: Option<String>,
        not_before: u64,
        expires_at: u64,
        nonce: [u8; 16],
        permissions: Vec<String>,
    ) -> Self {
        Self {
            token_id,
            network_id,
            subject_hint,
            not_before,
            expires_at,
            nonce,
            permissions,
        }
    }

    /// Check if the token is currently valid based on time
    pub fn is_valid_now(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now >= self.not_before && now <= self.expires_at
    }

    /// Check if the token has the required permission
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(&permission.to_string())
    }
}

impl EnrollmentToken {
    /// Generate a new enrollment token signed by the enrollment authority
    pub fn generate(ea_key: &EcdsaKeyPair, body: EnrollmentTokenBody) -> Result<Self> {
        // Serialize the body to CBOR
        let body_bytes = serde_cbor::to_vec(&body)
            .map_err(|e| KeyError::EncodingError(format!("Failed to serialize token body: {e}")))?;

        // Sign the body bytes
        let signature = ea_key.sign(&body_bytes)?;

        // Get the signer ID (compact_id of the EA public key)
        let ea_public_key_bytes = ea_key.public_key().as_bytes().to_vec();
        let signer_id = runar_common::compact_ids::compact_id(&ea_public_key_bytes);
        

        Ok(Self {
            body,
            signature,
            signer_id,
        })
    }

    /// Verify the enrollment token signature using the enrollment authority public key
    pub fn verify(&self, ea_public_key: &[u8]) -> Result<()> {
        // Serialize the body to CBOR
        let body_bytes = serde_cbor::to_vec(&self.body)
            .map_err(|e| KeyError::EncodingError(format!("Failed to serialize token body: {e}")))?;

        // Create a verifying key from the public key for verification
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        use p256::EncodedPoint;

        let verifying_key =
            VerifyingKey::from_encoded_point(&EncodedPoint::from_bytes(ea_public_key).map_err(
                |e| KeyError::InvalidKeyFormat(format!("Invalid public key format: {e}")),
            )?)
            .map_err(|e| KeyError::InvalidKeyFormat(format!("Invalid public key: {e}")))?;

        let sig = Signature::from_der(&self.signature)
            .map_err(|e| KeyError::SigningError(format!("Invalid signature format: {e}")))?;

        verifying_key
            .verify(&body_bytes, &sig)
            .map_err(|e| KeyError::SigningError(format!("Signature verification failed: {e}")))?;

        Ok(())
    }

    /// Validate the token for enrollment use
    pub fn validate_for_enrollment(&self, network_id: &str) -> Result<()> {
        // Check network ID matches
        if self.body.network_id != network_id {
            return Err(KeyError::ValidationError(format!(
                "Token network_id {} does not match expected {}",
                self.body.network_id, network_id
            )));
        }

        // Check token is valid now
        if !self.body.is_valid_now() {
            return Err(KeyError::ValidationError(
                "Token is not valid at current time".to_string(),
            ));
        }

        // Check token has enroll permission
        if !self.body.has_permission("enroll") {
            return Err(KeyError::ValidationError(
                "Token does not have enroll permission".to_string(),
            ));
        }

        Ok(())
    }
}
