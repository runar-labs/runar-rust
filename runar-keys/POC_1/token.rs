use crate::{
    error::KeyError,
    types::{current_unix_timestamp, NetworkId, NetworkKey, PeerId},
    Result,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

/// Defines capabilities that can be granted by an access token.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    Read,
    Write,
    Admin,
    // Add more specific capabilities as needed
    Custom(String),
}

/// Represents the data payload of an access token before signing.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct AccessTokenData {
    peer_id: PeerId,
    network_id: NetworkId,
    expiration: u64, // Unix timestamp
    capabilities: Vec<Capability>,
}

/// Represents a cryptographically signed access token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] // Added Serialize/Deserialize for the whole token
pub struct AccessToken {
    pub peer_id: PeerId,
    pub network_id: NetworkId,
    pub expiration: u64,
    pub capabilities: Vec<Capability>,
    pub signature_hex: String, // Added signature_hex field
                               // Signature is not part of the struct for direct serialization of the token itself,
                               // but handled during the sign/verify process where the token data is serialized to JSON for signing.
}

impl AccessToken {
    /// Creates a new `AccessToken`.
    pub fn new(
        peer_id: PeerId,
        network_id: NetworkId,
        expiration: u64, // Unix timestamp for expiration
        capabilities: Vec<Capability>,
    ) -> Self {
        AccessToken {
            peer_id,
            network_id,
            expiration,
            capabilities,
            signature_hex: String::new(), // Initialize signature_hex field
        }
    }

    /// Serializes the token data to a JSON string and signs it with the given `NetworkKey`.
    /// Returns the base64 encoded signature.
    pub fn sign(&self, network_key: &NetworkKey) -> Result<String> {
        if self.network_id != *network_key.id() {
            return Err(KeyError::InvalidOperation(
                "Token network_id does not match signing key's network_id".to_string(),
            ));
        }

        let data_to_sign = AccessTokenData {
            peer_id: self.peer_id.clone(),
            network_id: self.network_id.clone(),
            expiration: self.expiration,
            capabilities: self.capabilities.clone(),
        };

        let json_payload = serde_json::to_string(&data_to_sign).map_err(|e| {
            KeyError::SerializationError(format!("Failed to serialize token data: {}", e))
        })?;

        let signature = network_key.sign(json_payload.as_bytes());
        Ok(hex::encode(signature.to_bytes())) // Using hex for signature representation
    }

    /// Verifies a signed token string.
    /// The `signed_token_string` is expected to be a JSON representation of `SignedAccessToken` (token + signature_hex).
    /// Alternatively, if we pass token and signature separately:
    /// Verifies the token against a given hex-encoded signature and the `NetworkId` (public key).
    pub fn verify(
        token_json_str: &str,
        signature_hex: &str,
        verifying_network_id: &NetworkId,
    ) -> Result<Self> {
        // Deserialize the token part first
        let token: AccessToken = serde_json::from_str(token_json_str).map_err(|e| {
            KeyError::DeserializationError(format!("Failed to deserialize token from JSON: {}", e))
        })?;

        // Check if the token's network_id matches the one we are verifying against
        if token.network_id != *verifying_network_id {
            return Err(KeyError::InvalidToken(
                "Token network_id does not match verifying network_id".to_string(),
            ));
        }

        // Check expiration
        if current_unix_timestamp() > token.expiration {
            return Err(KeyError::TokenExpired);
        }

        // Reconstruct the data that was signed
        let data_that_was_signed = AccessTokenData {
            peer_id: token.peer_id.clone(),
            network_id: token.network_id.clone(),
            expiration: token.expiration,
            capabilities: token.capabilities.clone(),
        };
        let original_json_payload = serde_json::to_string(&data_that_was_signed).map_err(|e| {
            KeyError::SerializationError(format!(
                "Failed to re-serialize token data for verification: {}",
                e
            ))
        })?;

        // Decode signature from hex
        let signature_bytes_vec = hex::decode(signature_hex)
            .map_err(|e| KeyError::InvalidToken(format!("Invalid signature hex: {}", e)))?;

        let signature_bytes_array: [u8; 64] =
            signature_bytes_vec.as_slice().try_into().map_err(|e| {
                KeyError::InvalidSignatureFormat(format!("Signature bytes length incorrect: {}", e))
            })?;

        let signature = Signature::from_bytes(&signature_bytes_array);

        // Convert NetworkId to VerifyingKey for verification
        let network_public_key = VerifyingKey::from_bytes(verifying_network_id.as_bytes())
            .map_err(|e| {
                KeyError::InvalidPublicKey(format!(
                    "Failed to create VerifyingKey from NetworkId: {}",
                    e
                ))
            })?;

        // Verify the signature against the reconstructed payload and the public key
        network_public_key
            .verify_strict(original_json_payload.as_bytes(), &signature)
            .map_err(|e| KeyError::InvalidToken(format!("Signature verification failed: {}", e)))?;

        Ok(token)
    }

    /// A convenience method to create a JSON string of the token itself (not the signed payload).
    pub fn to_json_string(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| {
            KeyError::SerializationError(format!("Failed to serialize token to JSON: {}", e))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hd::derive_network_key;
    use crate::types::UserMasterKey;

    fn setup_test_keys() -> (UserMasterKey, NetworkKey, PeerId) {
        let master_key = UserMasterKey::generate();
        let network_key = derive_network_key(&master_key, 0).unwrap();
        let peer_id_bytes = [3u8; 32]; // Example PeerId bytes
        let peer_id = PeerId::from_bytes(&peer_id_bytes).unwrap();
        (master_key, network_key, peer_id)
    }

    #[test]
    fn test_access_token_creation_and_signing() {
        let (_master_key, network_key, peer_id) = setup_test_keys();
        let network_id = network_key.id().clone();

        let expiration = current_unix_timestamp() + 3600; // Expires in 1 hour
        let capabilities = vec![Capability::Read, Capability::Write];

        let token = AccessToken::new(
            peer_id.clone(),
            network_id.clone(),
            expiration,
            capabilities.clone(),
        );

        let signed_token_hex_result = token.sign(&network_key);
        assert!(signed_token_hex_result.is_ok());
        let signed_token_hex = signed_token_hex_result.unwrap();
        assert!(!signed_token_hex.is_empty());

        // For verification, we need the token data (as JSON) and the signature hex
        let token_json_str = token.to_json_string().unwrap();
        let verified_token_result =
            AccessToken::verify(&token_json_str, &signed_token_hex, &network_id);

        assert!(verified_token_result.is_ok());
        let verified_token = verified_token_result.unwrap();

        assert_eq!(verified_token.peer_id, peer_id);
        assert_eq!(verified_token.network_id, network_id);
        assert_eq!(verified_token.expiration, expiration);
        assert_eq!(verified_token.capabilities, capabilities);
    }

    #[test]
    fn test_token_verification_failure_wrong_key() {
        let (_master_key, network_key, peer_id) = setup_test_keys();
        let network_id = network_key.id().clone();

        // Create another network key for verification failure test
        let other_master_key = UserMasterKey::generate();
        let other_network_key = derive_network_key(&other_master_key, 1).unwrap();
        let other_network_id = other_network_key.id().clone();
        assert_ne!(network_id, other_network_id);

        let token = AccessToken::new(
            peer_id.clone(),
            network_id.clone(), // Token is for the original network_id
            current_unix_timestamp() + 3600,
            vec![Capability::Read],
        );

        let signature_hex = token.sign(&network_key).unwrap(); // Signed with original key
        let token_json_str = token.to_json_string().unwrap();

        // Try to verify with the wrong network_id
        let verification_result =
            AccessToken::verify(&token_json_str, &signature_hex, &other_network_id);
        assert!(verification_result.is_err());
        match verification_result.unwrap_err() {
            KeyError::InvalidToken(msg) => assert!(
                msg.contains("Token network_id does not match verifying network_id")
                    || msg.contains("Signature verification failed")
            ),
            _ => panic!("Expected InvalidToken error for wrong network_id verification"),
        }
    }

    #[test]
    fn test_token_expiration() {
        let (_master_key, network_key, peer_id) = setup_test_keys();
        let network_id = network_key.id().clone();

        let past_expiration = current_unix_timestamp() - 1; // Already expired
        let token = AccessToken::new(
            peer_id.clone(),
            network_id.clone(),
            past_expiration,
            vec![Capability::Read],
        );

        let signature_hex = token.sign(&network_key).unwrap();
        let token_json_str = token.to_json_string().unwrap();

        let verification_result = AccessToken::verify(&token_json_str, &signature_hex, &network_id);
        assert!(verification_result.is_err());
        assert_eq!(verification_result.unwrap_err(), KeyError::TokenExpired);
    }

    #[test]
    fn test_token_tampered_payload() {
        let (_master_key, network_key, peer_id) = setup_test_keys();
        let network_id = network_key.id().clone();

        let token = AccessToken::new(
            peer_id.clone(),
            network_id.clone(),
            current_unix_timestamp() + 3600,
            vec![Capability::Read],
        );
        let signature_hex = token.sign(&network_key).unwrap();
        // Original token_json_str for verification
        // let original_token_json_str = token.to_json_string().unwrap();

        // Create a tampered token JSON string
        let mut tampered_token_data = token.clone();
        tampered_token_data.capabilities = vec![Capability::Admin]; // Change capabilities
        let tampered_token_json_str = tampered_token_data.to_json_string().unwrap();

        let verification_result =
            AccessToken::verify(&tampered_token_json_str, &signature_hex, &network_id);
        assert!(verification_result.is_err());
        match verification_result.unwrap_err() {
            KeyError::InvalidToken(msg) => assert!(msg.contains("Signature verification failed")),
            e => panic!("Expected InvalidToken for tampered payload, got {:?}", e),
        }
    }

    #[test]
    fn test_sign_with_mismatched_network_key() {
        let (_master_key, network_key_orig, peer_id) = setup_test_keys();
        let network_id_orig = network_key_orig.id().clone();

        // Create another network key
        let other_master_key = UserMasterKey::generate();
        let network_key_other = derive_network_key(&other_master_key, 1).unwrap();
        // network_id_other is not used for signing, but network_key_other is.

        // Token is for the original network_id
        let token = AccessToken::new(
            peer_id.clone(),
            network_id_orig.clone(),
            current_unix_timestamp() + 3600,
            vec![Capability::Read],
        );

        // Attempt to sign with a key whose ID does not match token's network_id
        let sign_result = token.sign(&network_key_other);
        assert!(sign_result.is_err());
        match sign_result.unwrap_err() {
            KeyError::InvalidOperation(msg) => {
                assert!(msg.contains("Token network_id does not match signing key's network_id"))
            }
            _ => panic!("Expected InvalidOperation error for mismatched signing key"),
        }
    }
}
