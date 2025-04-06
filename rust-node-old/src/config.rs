use anyhow::{anyhow, Result};
use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::path::PathBuf;

// Define a custom struct for serializing and deserializing the keypair
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub node_name: String,
    #[serde(
        serialize_with = "serialize_keypair",
        deserialize_with = "deserialize_keypair"
    )]
    pub private_key: Keypair,
    #[serde(skip)]
    pub config_dir: PathBuf,
    pub web_ui_port: u16,
}

// Serialize the keypair to bytes
fn serialize_keypair<S>(key: &Keypair, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let bytes = key.to_bytes();
    serializer.serialize_bytes(&bytes)
}

// Deserialize bytes to a keypair
fn deserialize_keypair<'de, D>(deserializer: D) -> Result<Keypair, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    Keypair::from_bytes(&bytes).map_err(|e| Error::custom(format!("Invalid keypair: {}", e)))
}

impl NodeConfig {
    pub fn new(
        node_name: String,
        private_key: Vec<u8>,
        config_dir: PathBuf,
        web_ui_port: u16,
    ) -> Result<Self> {
        let private_key = Keypair::from_bytes(&private_key)?;
        Ok(Self {
            node_name,
            private_key,
            config_dir,
            web_ui_port,
        })
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.private_key.public.to_bytes().to_vec()
    }

    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.private_key.to_bytes().to_vec()
    }

    // Generate a new keypair
    pub fn generate_keypair() -> Result<Keypair> {
        // For now, use a non-cryptographic RNG during testing
        // In production, we should use a proper cryptographic RNG
        let mut seed = [0u8; 32];
        rand::thread_rng().fill(&mut seed);

        let secret = SecretKey::from_bytes(&seed)
            .map_err(|e| anyhow!("Failed to create secret key: {}", e))?;
        let public = PublicKey::from(&secret);

        Ok(Keypair { secret, public })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_management::KeyManager;
    use serde_json;

    #[test]
    fn test_node_config_serialization() -> Result<()> {
        // Generate a test keypair
        let keypair = KeyManager::generate_keypair()?;
        let config_dir = PathBuf::from("/tmp/test_config");

        // Create a NodeConfig
        let config = NodeConfig {
            node_name: "test_node".to_string(),
            private_key: keypair,
            config_dir: config_dir.clone(),
            web_ui_port: 8383,
        };

        // Serialize to JSON
        let json = serde_json::to_string(&config)?;

        // Deserialize from JSON
        let deserialized_config: NodeConfig = serde_json::from_str(&json)?;

        // Check that the values match
        assert_eq!(config.node_name, deserialized_config.node_name);
        assert_eq!(config.web_ui_port, deserialized_config.web_ui_port);

        // Since PathBuf is skipped during serialization, config_dir should be empty
        assert_ne!(config.config_dir, deserialized_config.config_dir);

        // Check that public key bytes match (this indicates the keypair was serialized correctly)
        assert_eq!(
            config.public_key_bytes(),
            deserialized_config.public_key_bytes()
        );

        Ok(())
    }

    #[test]
    fn test_node_config_methods() -> Result<()> {
        // Generate a test keypair
        let keypair = KeyManager::generate_keypair()?;
        let keypair_bytes = keypair.to_bytes();
        let config_dir = PathBuf::from("/tmp/test_config");

        // Create a NodeConfig using the new method
        let config = NodeConfig::new(
            "test_node".to_string(),
            keypair_bytes.to_vec(),
            config_dir.clone(),
            8383,
        )?;

        // Check that the values match
        assert_eq!(config.node_name, "test_node");
        assert_eq!(config.web_ui_port, 8383);
        assert_eq!(config.config_dir, config_dir);

        // Check public_key_bytes
        let public_key_bytes = config.public_key_bytes();
        assert_eq!(public_key_bytes.len(), 32);

        // Check private_key_bytes
        let private_key_bytes = config.private_key_bytes();
        assert_eq!(private_key_bytes.len(), 64);

        Ok(())
    }
}
