use crate::error::KeyError;
use crate::Result;
use ed25519_dalek::{
    Signature, Signer, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub const USER_MASTER_KEY_SEED_LENGTH: usize = SECRET_KEY_LENGTH; // 32 bytes for Ed25519 secret key

/// Represents the user's master seed, from which all other keys are derived.
#[derive(Clone, Debug)] // Added Debug
pub struct UserMasterKey {
    seed: [u8; USER_MASTER_KEY_SEED_LENGTH],
}

impl UserMasterKey {
    pub fn new(seed_bytes: [u8; USER_MASTER_KEY_SEED_LENGTH]) -> Self {
        UserMasterKey { seed: seed_bytes }
    }

    pub fn from_bytes(seed_bytes: &[u8]) -> Result<Self> {
        if seed_bytes.len() != USER_MASTER_KEY_SEED_LENGTH {
            return Err(KeyError::InvalidSeed(format!(
                "Invalid seed length: expected {}, got {}",
                USER_MASTER_KEY_SEED_LENGTH,
                seed_bytes.len()
            )));
        }
        let mut seed = [0u8; USER_MASTER_KEY_SEED_LENGTH];
        seed.copy_from_slice(seed_bytes);
        Ok(UserMasterKey { seed })
    }

    pub fn generate() -> Self {
        let mut seed = [0u8; USER_MASTER_KEY_SEED_LENGTH];
        OsRng.fill_bytes(&mut seed); // RngCore trait provides this
        UserMasterKey { seed }
    }

    pub fn as_bytes(&self) -> &[u8; USER_MASTER_KEY_SEED_LENGTH] {
        &self.seed
    }
}

/// Represents a Network Identifier, which is the public key of a NetworkKey.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)] // Added Hash for KeyManager
pub struct NetworkId([u8; PUBLIC_KEY_LENGTH]);

impl NetworkId {
    pub fn new(bytes: [u8; PUBLIC_KEY_LENGTH]) -> Self {
        NetworkId(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(KeyError::DeserializationError(format!(
                "Invalid NetworkId length: expected {}, got {}",
                PUBLIC_KEY_LENGTH,
                bytes.len()
            )));
        }
        let mut arr = [0u8; PUBLIC_KEY_LENGTH];
        arr.copy_from_slice(bytes);
        Ok(NetworkId(arr))
    }

    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }
}

/// Represents an Ed25519 key pair used for a Network.
#[derive(Clone)] // Removed Debug to avoid exposing secret key details easily
pub struct NetworkKey {
    pub(crate) keypair: SigningKey,
    id: NetworkId,
}

impl NetworkKey {
    pub fn new_random() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key(); // Method call
        let id = NetworkId::new(*public_key.as_bytes());
        NetworkKey {
            keypair: signing_key,
            id,
        }
    }

    pub fn new(signing_key: SigningKey) -> Self {
        let public_key = signing_key.verifying_key(); // Method call
        let id = NetworkId::new(*public_key.as_bytes());
        NetworkKey {
            keypair: signing_key,
            id,
        }
    }

    pub fn id(&self) -> &NetworkId {
        &self.id
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.keypair.verifying_key() // Method call
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.keypair.sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.keypair
            .verifying_key() // Method call
            .verify_strict(message, signature)
            .map_err(|e| KeyError::CryptoError(format!("Signature verification failed: {}", e)))
    }
}

/// Represents an Ed25519 key pair used for QUIC connections, derived from a NetworkKey.
#[derive(Clone)] // Removed Debug
pub struct QuicKey {
    pub(crate) keypair: SigningKey,
}

impl QuicKey {
    pub fn new_random() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        QuicKey {
            keypair: signing_key,
        }
    }

    pub fn new(signing_key: SigningKey) -> Self {
        QuicKey {
            keypair: signing_key,
        }
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.keypair.verifying_key() // Method call
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.keypair.verifying_key().as_bytes()) // Method call
    }

    // Add sign/verify or other methods if QUIC keys are used for more than just TLS certs
}

/// Represents a Peer Identifier, which is the SHA-256 hash of a NodeKey's public key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)] // Added Hash for KeyManager
pub struct PeerId([u8; 32]); // SHA-256 hash length

impl PeerId {
    pub fn from_public_key(public_key: &VerifyingKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(public_key.as_bytes());
        let hash_result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash_result.as_slice());
        PeerId(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(KeyError::DeserializationError(format!(
                "Invalid PeerId length: expected 32, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(PeerId(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }
}

/// Represents an Ed25519 key pair for a Node/Peer.
#[derive(Clone)] // Removed Debug
pub struct NodeKey {
    pub(crate) keypair: SigningKey,
    peer_id: PeerId,
}

impl NodeKey {
    pub fn new_random() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key(); // Method call
        let peer_id = PeerId::from_public_key(&public_key);
        NodeKey {
            keypair: signing_key,
            peer_id,
        }
    }

    pub fn new(signing_key: SigningKey) -> Self {
        let public_key = signing_key.verifying_key(); // Method call
        let peer_id = PeerId::from_public_key(&public_key);
        NodeKey {
            keypair: signing_key,
            peer_id,
        }
    }

    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.keypair.verifying_key() // Method call
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.keypair.sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.keypair
            .verifying_key() // Method call
            .verify_strict(message, signature)
            .map_err(|e| KeyError::CryptoError(format!("Signature verification failed: {}", e)))
    }
}

/// Returns the current Unix timestamp in seconds.
pub fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_master_key_generation_and_bytes_conversion() {
        let master_key1 = UserMasterKey::generate();
        let master_key2 = UserMasterKey::generate();
        assert_ne!(master_key1.as_bytes(), master_key2.as_bytes());

        let seed_bytes = *master_key1.as_bytes();
        let master_key_from_bytes = UserMasterKey::from_bytes(&seed_bytes).unwrap();
        assert_eq!(master_key1.as_bytes(), master_key_from_bytes.as_bytes());

        let invalid_seed = vec![0u8; 31];
        assert!(UserMasterKey::from_bytes(&invalid_seed).is_err());
    }

    #[test]
    fn test_network_id_conversion() {
        let public_key_bytes = [1u8; PUBLIC_KEY_LENGTH];
        let network_id = NetworkId::new(public_key_bytes);
        assert_eq!(network_id.as_bytes(), &public_key_bytes);

        let hex_str = network_id.to_hex();
        let network_id_from_hex = NetworkId::from_hex(&hex_str).unwrap();
        assert_eq!(network_id, network_id_from_hex);

        assert!(NetworkId::from_bytes(&[0u8; 31]).is_err());
        assert!(NetworkId::from_hex("invalidhex").is_err());
    }

    #[test]
    fn test_network_key_creation_and_signing() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let network_key = NetworkKey::new(signing_key);

        let expected_network_id = NetworkId::new(*network_key.keypair.verifying_key().as_bytes());
        assert_eq!(network_key.id(), &expected_network_id);

        let message = b"hello world";
        let signature = network_key.sign(message);
        assert!(network_key.verify(message, &signature).is_ok());

        let wrong_message = b"hello mars";
        assert!(network_key.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_peer_id_creation_and_conversion() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key();
        let peer_id = PeerId::from_public_key(&public_key);

        let mut hasher = Sha256::new();
        hasher.update(public_key.as_bytes());
        let expected_hash_bytes: [u8; 32] = hasher.finalize().into();

        assert_eq!(peer_id.as_bytes(), &expected_hash_bytes);

        let hex_str = peer_id.to_hex();
        let peer_id_from_hex = PeerId::from_hex(&hex_str).unwrap();
        assert_eq!(peer_id, peer_id_from_hex);

        assert!(PeerId::from_bytes(&[0u8; 31]).is_err());
        assert!(PeerId::from_hex("invalidhex").is_err());
    }

    #[test]
    fn test_quic_key_creation() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let quic_key = QuicKey::new(signing_key.clone());
        // Ensure the public key can be retrieved and is valid
        let public_key_bytes = quic_key.public_key().to_bytes();
        assert_eq!(public_key_bytes.len(), PUBLIC_KEY_LENGTH);
        // Test hex conversion
        let public_key_hex = quic_key.public_key_hex();
        assert_eq!(public_key_hex.len(), PUBLIC_KEY_LENGTH * 2);
        let decoded_bytes = hex::decode(&public_key_hex).unwrap();
        assert_eq!(decoded_bytes, public_key_bytes);
    }

    #[test]
    fn test_node_key_creation_and_signing() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let node_key = NodeKey::new(signing_key);

        let expected_peer_id = PeerId::from_public_key(&node_key.keypair.verifying_key());
        assert_eq!(node_key.peer_id(), &expected_peer_id);

        let message = b"super secret node data";
        let signature = node_key.sign(message);
        assert!(node_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_current_unix_timestamp() {
        let ts1 = current_unix_timestamp();
        std::thread::sleep(std::time::Duration::from_secs(1));
        let ts2 = current_unix_timestamp();
        assert!(ts2 > ts1, "Timestamp should advance");
        assert!(ts2 > ts1, "Timestamp should advance by at least 1 second");
    }
}
