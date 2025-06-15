//! Access Token implementation.

use crate::error::{KeyError, Result};
use crate::types::{current_unix_timestamp, NetworkId, PeerId};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Capability {
    Read,
    Write,
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenData {
    pub peer_id: PeerId,
    pub network_id: NetworkId,
    pub expiration: Option<u64>,
    pub capabilities: Option<Vec<Capability>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    pub data: AccessTokenData,
    pub signature: Signature,
}

impl AccessToken {
    pub fn new(
        peer_id: PeerId,
        network_id: NetworkId,
        expiration: Option<u64>,
        capabilities: Option<Vec<Capability>>,
        signer: &impl Signer<Signature>,
    ) -> Self {
        let data = AccessTokenData {
            peer_id,
            network_id,
            expiration,
            capabilities,
        };
        let signature = signer.sign(serde_json::to_string(&data).unwrap().as_bytes());
        Self { data, signature }
    }

    fn data_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.data).expect("serialize")
    }

    pub fn verify(&self) -> Result<bool> {
        // check expiration
        if let Some(exp) = self.data.expiration {
            if exp < current_unix_timestamp() {
                return Ok(false);
            }
        }
        // verify sig using network id (public key)
        let vk = self.data.network_id.verifying_key()?; // convert
        vk.verify_strict(&self.data_bytes(), &self.signature)
            .map_err(|e| KeyError::Signature(e))?;
        Ok(true)
    }
}
