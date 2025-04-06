use crate::p2p::crypto::PeerId as CryptoPeerId;
use libp2p::PeerId as LibP2pPeerId;
use std::convert::TryFrom;
use std::str::FromStr;
use anyhow::{Result, anyhow};

/// Trait for converting from libp2p::PeerId to our custom PeerId
pub trait LibP2pToCryptoPeerId {
    fn to_crypto_peer_id(&self) -> Result<CryptoPeerId>;
}

/// Trait for converting from our custom PeerId to libp2p::PeerId
pub trait CryptoToLibP2pPeerId {
    fn to_libp2p_peer_id(&self) -> Result<LibP2pPeerId>;
}

impl LibP2pToCryptoPeerId for LibP2pPeerId {
    fn to_crypto_peer_id(&self) -> Result<CryptoPeerId> {
        // Convert libp2p::PeerId to our custom PeerId
        // First convert to bytes, then take first 32 bytes or pad if necessary
        let bytes = self.to_bytes();
        let mut peer_id_bytes = [0u8; 32];
        
        // Copy bytes, handling the case where bytes might be shorter or longer than 32
        let len = std::cmp::min(bytes.len(), 32);
        peer_id_bytes[..len].copy_from_slice(&bytes[..len]);
        
        Ok(CryptoPeerId(peer_id_bytes))
    }
}

impl CryptoToLibP2pPeerId for CryptoPeerId {
    fn to_libp2p_peer_id(&self) -> Result<LibP2pPeerId> {
        // Since the conversion might be lossy, we'll use a simple strategy
        // Convert to a string in a reliable format and parse back
        let hex_str = hex::encode(self.0);
        
        // Try to parse as a multibase string
        LibP2pPeerId::from_str(&hex_str)
            .map_err(|e| anyhow!("Failed to convert to libp2p::PeerId: {}", e))
    }
}

// Optional: Implement From traits for simpler conversion
impl TryFrom<LibP2pPeerId> for CryptoPeerId {
    type Error = anyhow::Error;
    
    fn try_from(peer_id: LibP2pPeerId) -> Result<Self, Self::Error> {
        peer_id.to_crypto_peer_id()
    }
}

impl TryFrom<CryptoPeerId> for LibP2pPeerId {
    type Error = anyhow::Error;
    
    fn try_from(peer_id: CryptoPeerId) -> Result<Self, Self::Error> {
        peer_id.to_libp2p_peer_id()
    }
} 