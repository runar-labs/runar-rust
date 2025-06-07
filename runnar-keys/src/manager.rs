use crate::{
    hd::{derive_network_key, derive_node_key_from_master_key, derive_quic_key_from_network_key},
    types::{NetworkId, NetworkKey, NodeKey, PeerId, QuicKey, UserMasterKey},
    Result,
};
use std::collections::HashMap;

/// Manages cryptographic keys in memory.
///
/// The `KeyManager` is initialized with a `UserMasterKey` and can derive and store
/// `NetworkKey`s, `NodeKey`s (Peer Keys), and `QuicKey`s on demand.
pub struct KeyManager {
    master_key: UserMasterKey,
    network_keys: HashMap<u32, NetworkKey>, // Indexed by network_index
    node_keys: HashMap<u32, NodeKey>,       // Indexed by peer_index
    quic_keys: HashMap<NetworkId, QuicKey>, // Indexed by the NetworkId of the parent NetworkKey
}

impl KeyManager {
    /// Creates a new `KeyManager` from a given `UserMasterKey`.
    pub fn new(master_key: UserMasterKey) -> Self {
        KeyManager {
            master_key,
            network_keys: HashMap::new(),
            node_keys: HashMap::new(),
            quic_keys: HashMap::new(),
        }
    }

    /// Creates a new `KeyManager` by generating a new `UserMasterKey`.
    pub fn new_random() -> Self {
        Self::new(UserMasterKey::generate())
    }

    /// Returns a reference to the `UserMasterKey`.
    pub fn master_key(&self) -> &UserMasterKey {
        &self.master_key
    }

    /// Gets an existing `NetworkKey` for the given index, or derives and stores it if not present.
    pub fn get_or_create_network_key(&mut self, network_index: u32) -> Result<&NetworkKey> {
        if !self.network_keys.contains_key(&network_index) {
            let network_key = derive_network_key(&self.master_key, network_index)?;
            self.network_keys.insert(network_index, network_key);
        }
        // We can unwrap here because we've just ensured the key exists.
        Ok(self.network_keys.get(&network_index).unwrap())
    }

    /// Retrieves a `NetworkKey` by its `NetworkId` if it has been previously derived.
    pub fn get_network_key_by_id(&self, network_id: &NetworkId) -> Option<&NetworkKey> {
        self.network_keys
            .values()
            .find(|nk| *nk.id() == *network_id)
    }

    /// Gets an existing `NodeKey` for the given peer index, or derives and stores it if not present.
    pub fn get_or_create_node_key(&mut self, peer_index: u32) -> Result<&NodeKey> {
        if !self.node_keys.contains_key(&peer_index) {
            let node_key = derive_node_key_from_master_key(&self.master_key, peer_index)?;
            self.node_keys.insert(peer_index, node_key);
        }
        // We can unwrap here because we've just ensured the key exists.
        Ok(self.node_keys.get(&peer_index).unwrap())
    }

    /// Retrieves a `NodeKey` by its `PeerId` if it has been previously derived.
    pub fn get_node_key_by_peer_id(&self, peer_id: &PeerId) -> Option<&NodeKey> {
        self.node_keys.values().find(|nk| *nk.peer_id() == *peer_id)
    }

    /// Gets an existing `QuicKey` for the network identified by `network_index`,
    /// or derives and stores it if not present. This will also derive the `NetworkKey` if needed.
    pub fn get_or_create_quic_key(&mut self, network_index: u32) -> Result<&QuicKey> {
        // Ensure the parent NetworkKey exists
        let network_key_id_for_quic_map =
            self.get_or_create_network_key(network_index)?.id().clone();

        if !self.quic_keys.contains_key(&network_key_id_for_quic_map) {
            // Must get a fresh reference to network_key as self.network_keys might have been mutated
            // if the network_key was just created.
            let current_network_key = self.network_keys.get(&network_index).unwrap();
            let quic_key = derive_quic_key_from_network_key(current_network_key)?;
            self.quic_keys
                .insert(network_key_id_for_quic_map.clone(), quic_key);
        }
        // We can unwrap here because we've just ensured the key exists.
        Ok(self.quic_keys.get(&network_key_id_for_quic_map).unwrap())
    }

    /// Retrieves a `QuicKey` by its parent `NetworkId` if it has been previously derived.
    pub fn get_quic_key_by_network_id(&self, network_id: &NetworkId) -> Option<&QuicKey> {
        self.quic_keys.get(network_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_manager_creation() {
        let master_key = UserMasterKey::generate();
        let manager = KeyManager::new(master_key.clone());
        assert_eq!(manager.master_key().as_bytes(), master_key.as_bytes());

        let _random_manager = KeyManager::new_random(); // Just check it doesn't panic
    }

    #[test]
    fn test_get_or_create_network_key() {
        let mut manager = KeyManager::new_random();
        let network_index = 0;

        let key1_result = manager.get_or_create_network_key(network_index);
        assert!(key1_result.is_ok());
        let key1_id = key1_result.unwrap().id().clone();

        // Calling again should return the same key
        let key2 = manager.get_or_create_network_key(network_index).unwrap();
        assert_eq!(key1_id, *key2.id());
        assert_eq!(manager.network_keys.len(), 1);

        // Retrieve by ID
        let retrieved_key = manager.get_network_key_by_id(&key1_id);
        assert!(retrieved_key.is_some());
        assert_eq!(retrieved_key.unwrap().id(), &key1_id);

        // Different index should produce a different key
        let key_diff_index = manager.get_or_create_network_key(1).unwrap();
        assert_ne!(key1_id, *key_diff_index.id());
        assert_eq!(manager.network_keys.len(), 2);
    }

    #[test]
    fn test_get_or_create_node_key() {
        let mut manager = KeyManager::new_random();
        let peer_index = 0;

        let key1_result = manager.get_or_create_node_key(peer_index);
        assert!(key1_result.is_ok());
        let key1_peer_id = key1_result.unwrap().peer_id().clone();

        let key2 = manager.get_or_create_node_key(peer_index).unwrap();
        assert_eq!(key1_peer_id, *key2.peer_id());
        assert_eq!(manager.node_keys.len(), 1);

        // Retrieve by PeerId
        let retrieved_key = manager.get_node_key_by_peer_id(&key1_peer_id);
        assert!(retrieved_key.is_some());
        assert_eq!(retrieved_key.unwrap().peer_id(), &key1_peer_id);

        let key_diff_index = manager.get_or_create_node_key(1).unwrap();
        assert_ne!(key1_peer_id, *key_diff_index.peer_id());
        assert_eq!(manager.node_keys.len(), 2);
    }

    #[test]
    fn test_get_or_create_quic_key() {
        let mut manager = KeyManager::new_random();
        let network_index = 0;

        // First, get the network key to know its ID
        let network_id = manager
            .get_or_create_network_key(network_index)
            .unwrap()
            .id()
            .clone();

        let quic_key1_pk_hex = manager
            .get_or_create_quic_key(network_index)
            .unwrap()
            .public_key_hex();

        let quic_key2_pk_hex = manager
            .get_or_create_quic_key(network_index)
            .unwrap()
            .public_key_hex();
        assert_eq!(quic_key1_pk_hex, quic_key2_pk_hex);
        assert_eq!(manager.quic_keys.len(), 1);

        // Retrieve by NetworkId
        let retrieved_key_pk_hex = manager
            .get_quic_key_by_network_id(&network_id)
            .unwrap()
            .public_key_hex();
        assert_eq!(retrieved_key_pk_hex, quic_key1_pk_hex);

        // QUIC key for a different network
        let network_index_2 = 1;
        let network_id_2 = manager
            .get_or_create_network_key(network_index_2)
            .unwrap()
            .id()
            .clone();

        let quic_key_diff_network_pk_hex = manager
            .get_or_create_quic_key(network_index_2)
            .unwrap()
            .public_key_hex();
        assert_ne!(quic_key1_pk_hex, quic_key_diff_network_pk_hex);
        assert_eq!(manager.quic_keys.len(), 2);
        assert!(manager.quic_keys.contains_key(&network_id));
        assert!(manager.quic_keys.contains_key(&network_id_2));
    }

    #[test]
    fn test_keys_are_distinct() {
        let mut manager = KeyManager::new_random();
        let index = 0;

        let nk_pk_bytes_vec = manager
            .get_or_create_network_key(index)
            .unwrap()
            .public_key()
            .as_bytes()
            .to_vec();
        let node_pk_bytes_vec = manager
            .get_or_create_node_key(index)
            .unwrap()
            .public_key()
            .as_bytes()
            .to_vec();
        let quic_pk_bytes_vec = manager
            .get_or_create_quic_key(index)
            .unwrap()
            .public_key()
            .as_bytes()
            .to_vec();

        assert_ne!(
            nk_pk_bytes_vec, node_pk_bytes_vec,
            "Network key and Node key public keys should be different"
        );
        assert_ne!(
            nk_pk_bytes_vec, quic_pk_bytes_vec,
            "Network key and QUIC key public keys should be different"
        );
        assert_ne!(
            node_pk_bytes_vec, quic_pk_bytes_vec,
            "Node key and QUIC key public keys should be different"
        );
    }
}
