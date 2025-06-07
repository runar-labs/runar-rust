use crate::{
    types::{NetworkKey, NodeKey, QuicKey, UserMasterKey},
    Result,
};
use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};
use ed25519_hd_key;

// HD Path constants as per keys-management.md and common practice
const BIP44_PURPOSE: u32 = 44;
// const BIP44_COIN_TYPE_ED25519: u32 = 0; // Example, not strictly defined for Ed25519 like BTC/ETH
// For Runar, let's use a custom coin type or a generic one if not specified by a standard.
// Using 0' for NetworkKey as per original spec `m/44'/0'/n'`
// Using 1' for NodeKey as per original spec `m/44'/1'/p'`

const RUNAR_NETWORK_KEY_COIN_TYPE: u32 = 0;
const RUNAR_NODE_KEY_COIN_TYPE: u32 = 1;

// QUIC keys are derived from the NetworkKey's *secret*, not from the master key directly via an HD path from root.
// The path m/0'/0 is relative to the NetworkKey's secret key being treated as a new master seed for this sub-derivation.
const QUIC_KEY_ACCOUNT: u32 = 0;
const QUIC_KEY_INDEX: u32 = 0;

/// Derives a NetworkKey from the UserMasterKey using the HD path m/44'/0'/network_index'.
pub fn derive_network_key(master_key: &UserMasterKey, network_index: u32) -> Result<NetworkKey> {
    let path_str = format!(
        "m/{:?}'/{:?}'/{:?}'",
        BIP44_PURPOSE, RUNAR_NETWORK_KEY_COIN_TYPE, network_index
    );

    // ed25519_hd_key::derive_from_path is expected to panic on fundamentally invalid path strings.
    // It returns ([u8; 32], [u8; 32]) for (key, chain_code)
    let (key_bytes, _chain_code) =
        ed25519_hd_key::derive_from_path(&path_str, master_key.as_bytes());

    let signing_key = SigningKey::from_bytes(&key_bytes);
    Ok(NetworkKey::new(signing_key))
}

/// Derives a QuicKey from a NetworkKey's secret using the HD path m/0'/0 (relative to NetworkKey secret).
pub fn derive_quic_key_from_network_key(network_key: &NetworkKey) -> Result<QuicKey> {
    // Use the NetworkKey's secret key as the seed for this QUIC key derivation.
    let seed_for_quic = &network_key.keypair.to_keypair_bytes()[..SECRET_KEY_LENGTH];

    let path_str = format!("m/{:?}'/{:?}'", QUIC_KEY_ACCOUNT, QUIC_KEY_INDEX);

    let (key_bytes, _chain_code) = ed25519_hd_key::derive_from_path(&path_str, seed_for_quic);

    let signing_key = SigningKey::from_bytes(&key_bytes);
    Ok(QuicKey::new(signing_key))
}

/// Derives a NodeKey (Peer Key) from the UserMasterKey using the HD path m/44'/1'/peer_index'.
pub fn derive_node_key_from_master_key(
    master_key: &UserMasterKey,
    peer_index: u32,
) -> Result<NodeKey> {
    let path_str = format!(
        "m/{:?}'/{:?}'/{:?}'",
        BIP44_PURPOSE, RUNAR_NODE_KEY_COIN_TYPE, peer_index
    );

    let (key_bytes, _chain_code) =
        ed25519_hd_key::derive_from_path(&path_str, master_key.as_bytes());

    let signing_key = SigningKey::from_bytes(&key_bytes);
    Ok(NodeKey::new(signing_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::PUBLIC_KEY_LENGTH;

    #[test]
    fn test_derive_network_key_success() {
        let master_key = UserMasterKey::generate();
        let network_index = 0;
        let network_key_result = derive_network_key(&master_key, network_index);
        assert!(network_key_result.is_ok());

        let network_key = network_key_result.unwrap();
        // Check that the public key (NetworkId) is valid
        assert_eq!(network_key.id().as_bytes().len(), PUBLIC_KEY_LENGTH);

        // Derive again with same params, should be the same key
        let network_key_again = derive_network_key(&master_key, network_index).unwrap();
        assert_eq!(network_key.id(), network_key_again.id());
        assert_eq!(
            network_key.keypair.to_bytes(),
            network_key_again.keypair.to_bytes()
        );

        // Derive with different index, should be a different key
        let network_key_different_index = derive_network_key(&master_key, 1).unwrap();
        assert_ne!(network_key.id(), network_key_different_index.id());

        // Derive with different master key, should be a different key
        let master_key2 = UserMasterKey::generate();
        let network_key_different_master = derive_network_key(&master_key2, network_index).unwrap();
        assert_ne!(network_key.id(), network_key_different_master.id());
    }

    #[test]
    fn test_derive_quic_key_from_network_key_success() {
        let master_key = UserMasterKey::generate();
        let network_key = derive_network_key(&master_key, 0).unwrap();

        let quic_key_result = derive_quic_key_from_network_key(&network_key);
        assert!(quic_key_result.is_ok());
        let quic_key = quic_key_result.unwrap();
        assert_eq!(quic_key.public_key().as_bytes().len(), PUBLIC_KEY_LENGTH);

        // Derive again, should be the same QUIC key for the same NetworkKey
        let quic_key_again = derive_quic_key_from_network_key(&network_key).unwrap();
        assert_eq!(
            quic_key.public_key().as_bytes(),
            quic_key_again.public_key().as_bytes()
        );
        assert_eq!(
            quic_key.keypair.to_bytes(),
            quic_key_again.keypair.to_bytes()
        );

        // Derive QUIC key from a different NetworkKey, should be different
        let network_key_2 = derive_network_key(&master_key, 1).unwrap(); // Different network index
        let quic_key_different_network = derive_quic_key_from_network_key(&network_key_2).unwrap();
        assert_ne!(
            quic_key.public_key().as_bytes(),
            quic_key_different_network.public_key().as_bytes()
        );
    }

    #[test]
    fn test_derive_node_key_from_master_key_success() {
        let master_key = UserMasterKey::generate();
        let peer_index = 0;
        let node_key_result = derive_node_key_from_master_key(&master_key, peer_index);
        assert!(node_key_result.is_ok());
        let node_key = node_key_result.unwrap();
        assert_eq!(node_key.public_key().as_bytes().len(), PUBLIC_KEY_LENGTH);
        assert_eq!(node_key.peer_id().as_bytes().len(), 32); // SHA-256 hash length

        // Derive again with same params, should be the same key
        let node_key_again = derive_node_key_from_master_key(&master_key, peer_index).unwrap();
        assert_eq!(node_key.peer_id(), node_key_again.peer_id());
        assert_eq!(
            node_key.keypair.to_bytes(),
            node_key_again.keypair.to_bytes()
        );

        // Derive with different index, should be a different key
        let node_key_different_index = derive_node_key_from_master_key(&master_key, 1).unwrap();
        assert_ne!(node_key.peer_id(), node_key_different_index.peer_id());

        // Derive with different master key, should be a different key
        let master_key2 = UserMasterKey::generate();
        let node_key_different_master =
            derive_node_key_from_master_key(&master_key2, peer_index).unwrap();
        assert_ne!(node_key.peer_id(), node_key_different_master.peer_id());
    }

    #[test]
    fn test_derivation_paths_are_distinct_enough() {
        // This test ensures that keys derived for different purposes but same index don't collide
        let master_key = UserMasterKey::generate();
        let index = 0;

        let network_key = derive_network_key(&master_key, index).unwrap();
        let node_key = derive_node_key_from_master_key(&master_key, index).unwrap();

        // NetworkKey and NodeKey derived from the same master key and same index but different coin_types
        // should have different public keys.
        assert_ne!(
            network_key.public_key().as_bytes(),
            node_key.public_key().as_bytes(),
            "NetworkKey and NodeKey with same index should have different public keys due to different derivation paths (coin_type)"
        );

        // QUIC key is derived from NetworkKey's secret, so it's inherently different.
        let quic_key = derive_quic_key_from_network_key(&network_key).unwrap();
        assert_ne!(
            network_key.public_key().as_bytes(),
            quic_key.public_key().as_bytes(),
            "NetworkKey and its derived QuicKey should have different public keys"
        );
        assert_ne!(
            node_key.public_key().as_bytes(),
            quic_key.public_key().as_bytes(),
            "NodeKey and QuicKey (derived from a NetworkKey) should have different public keys"
        );
    }

    #[test]
    #[should_panic] // ed25519_hd_key::derive_from_path panics on invalid path format
    fn test_invalid_derivation_path_string_panics() {
        let master_key = UserMasterKey::generate();
        // This path is invalid because 'invalid' is not a number.
        // ed25519_hd_key::derive_from_path is expected to panic.
        let _ = ed25519_hd_key::derive_from_path("m/44'/invalid'/0'", master_key.as_bytes());
    }
}
