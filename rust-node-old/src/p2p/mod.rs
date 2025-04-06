pub mod crypto;
pub mod dht;
pub mod discovery;
pub mod peer;
pub mod qr;
pub mod service;
pub mod stun;
pub mod transport;
pub mod peer_id_convert;

// Re-export types and modules for public use
pub use crypto::{AccessToken, Crypto, NetworkId, PeerId};
pub use qr::{generate_network_qr, generate_peer_qr, generate_token_qr, parse_qr};
pub use service::P2PRemoteServiceDelegate;
pub use stun::{get_public_endpoint, start_stun_like_server};
pub use transport::{P2PTransport, P2PMessage};
pub use peer_id_convert::{LibP2pToCryptoPeerId, CryptoToLibP2pPeerId};

pub async fn init() -> anyhow::Result<transport::P2PTransport> {
    let config = transport::TransportConfig {
        network_id: "default".to_string(),
        state_path: ".".to_string(),
        bootstrap_nodes: None,
        listen_addr: None,
    };
    transport::P2PTransport::new(config, None).await
}

// Tests
#[cfg(test)]
mod tests;
