use anyhow::Result;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use getrandom;
use hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub struct PeerId(pub [u8; 32]);

impl FromStr for PeerId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = base64::decode(s)
            .map_err(|e| anyhow::anyhow!("Failed to decode base64 peer ID: {}", e))?;

        if bytes.len() != 32 {
            return Err(anyhow::anyhow!(
                "Invalid peer ID length: expected 32 bytes, got {}",
                bytes.len()
            ));
        }

        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(PeerId(array))
    }
}

impl From<&str> for PeerId {
    fn from(s: &str) -> Self {
        PeerId::from_str(s).expect("Invalid PeerId string")
    }
}

impl PeerId {
    pub fn from_public_key(pubkey: &PublicKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(pubkey.to_bytes());
        PeerId(hasher.finalize().into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub struct NetworkId(pub [u8; 32]);

impl NetworkId {
    pub fn from_public_key(pubkey: &PublicKey) -> Self {
        NetworkId(pubkey.to_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

// Implement Display for NetworkId
impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Convert to a base64 string for display
        write!(f, "{}", base64::encode(&self.0))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccessToken {
    pub peer_id: PeerId,
    pub network_id: NetworkId,
    pub expiration: Option<u64>,
    pub signature: Vec<u8>,
}

pub struct Crypto {
    master_key: Keypair,
}

impl Crypto {
    pub fn new(seed: &[u8]) -> Self {
        let secret = SecretKey::from_bytes(&Sha256::digest(seed)).unwrap();
        let public = PublicKey::from(&secret);
        Self {
            master_key: Keypair { secret, public },
        }
    }

    pub fn get_public_key(&self) -> &PublicKey {
        &self.master_key.public
    }

    pub fn derive_network_key(&self, index: u32) -> Keypair {
        let path = format!("m/44'/0'/{}'", index);

        // The ed25519_hd_key::derive_from_path returns a tuple directly, not a Result
        // It returns a tuple of ([u8; 32], [u8; 32]) as (key, chain_code)
        let result = ed25519_hd_key::derive_from_path(&path, &self.master_key.secret.to_bytes());

        // Pattern match to extract the key
        let (key, _chain_code) = result;

        let secret = SecretKey::from_bytes(&key).unwrap();
        let public = PublicKey::from(&secret);
        Keypair { secret, public }
    }

    pub fn issue_token(
        &self,
        peer_id: PeerId,
        network_id: NetworkId,
        expiration: Option<u64>,
    ) -> AccessToken {
        let mut token = AccessToken {
            peer_id,
            network_id,
            expiration,
            signature: Vec::new(),
        };
        let serialized =
            bincode::serialize(&(&token.peer_id, &token.network_id, &token.expiration)).unwrap();
        token.signature = self.master_key.sign(&serialized).to_bytes().to_vec();
        token
    }

    pub fn verify_token(&self, token: &AccessToken, network_pubkey: &PublicKey) -> Result<bool> {
        let serialized =
            bincode::serialize(&(&token.peer_id, &token.network_id, &token.expiration))?;
        let signature = Signature::from_bytes(&token.signature)?;
        Ok(network_pubkey.verify(&serialized, &signature).is_ok())
    }

    /// Utility function to generate a keypair with the correct rand version
    pub fn generate_keypair() -> Keypair {
        // Use a custom implementation to bridge the version mismatch between
        // rand/rand_core used by ed25519-dalek (0.5) and our crate (0.8)
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("Failed to generate random seed");
        let secret = SecretKey::from_bytes(&seed).unwrap();
        let public = PublicKey::from(&secret);
        Keypair { secret, public }
    }
}
