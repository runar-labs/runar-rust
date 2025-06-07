// Peer Registry Component
//
// INTENTION: Maintain a registry of known peers in the network,
// track their status, and provide lookup capabilities to find specific
// peers based on identifiers or network.

use anyhow::Result;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

use super::PeerId;
use crate::network::discovery::multicast_discovery::PeerInfo;

/// Status of a peer in the registry
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerStatus {
    /// Peer is known but not connected
    Discovered,
    /// Connection to peer is being established
    Connecting,
    /// Peer is connected and ready for communication
    Connected,
    /// Connection to peer is being closed
    Disconnecting,
    /// Peer was previously connected but is now disconnected
    Disconnected,
}

/// Information about a peer, including its connection status and networks it participates in
#[derive(Debug, Clone)]
pub struct PeerEntry {
    /// Basic node information
    pub peer_info: PeerInfo,
    pub last_seen: SystemTime,
    /// Current status of the peer
    pub status: PeerStatus,
    /// Last status change timestamp
    pub status_changed: SystemTime,
    /// Connection attempts if in Connecting state
    pub connection_attempts: u32,
    /// Additional metadata about the peer (arbitrary key-value pairs)
    pub metadata: HashMap<String, String>,
}

impl PeerEntry {
    /// Create a new peer entry from node information and network ID
    pub fn new(peer_info: PeerInfo) -> Self {
        Self {
            peer_info,
            last_seen: SystemTime::now(),
            status: PeerStatus::Discovered,
            status_changed: SystemTime::now(),
            connection_attempts: 0,
            metadata: HashMap::new(),
        }
    }

    /// Update the peer's status
    pub fn set_status(&mut self, status: PeerStatus) {
        self.status = status;
        self.status_changed = SystemTime::now();
    }

    /// Add or update metadata for this peer
    pub fn set_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
}

/// Options for the peer registry
#[derive(Debug, Clone)]
pub struct PeerRegistryOptions {
    /// Maximum number of peers to track per network
    pub max_peers_per_network: usize,
    /// How long to keep peers in the registry without activity
    pub peer_ttl: Duration,
    /// How often to run cleanup of stale peers
    pub cleanup_interval: Duration,
}

impl Default for PeerRegistryOptions {
    fn default() -> Self {
        Self {
            max_peers_per_network: 100,
            peer_ttl: Duration::from_secs(3600),        // 1 hour
            cleanup_interval: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Registry of known peers in the network
pub struct PeerRegistry {
    /// Peers indexed by their peer_public_key
    peers: RwLock<HashMap<String, PeerEntry>>,
    /// Configuration options
    options: PeerRegistryOptions,
}

impl Default for PeerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerRegistry {
    /// Create a new peer registry with default options
    pub fn new() -> Self {
        Self::with_options(PeerRegistryOptions::default())
    }

    /// Create a new peer registry with custom options
    pub fn with_options(options: PeerRegistryOptions) -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            // network_index: RwLock::new(HashMap::new()),
            options,
        }
    }

    /// Add a peer to the registry
    pub fn add_peer(&self, discovery_msg: PeerInfo) -> Result<()> {
        // Use public key from the peer_id as the unique identifier
        let peer_public_key = discovery_msg.public_key.clone();

        // If we've passed the limit checks, now we can modify the data structures
        let mut peers = self.peers.write().unwrap();

        // Add or update peer
        if let Some(existing_peer) = peers.get_mut(&peer_public_key) {
            // Update existing peer
            existing_peer.last_seen = SystemTime::now();
            existing_peer.peer_info = discovery_msg;
        } else {
            // Create new peer entry with all its networks
            let peer_entry = PeerEntry::new(discovery_msg);
            peers.insert(peer_public_key, peer_entry);
        }

        Ok(())
    }

    /// Update a peer's status
    pub fn update_peer_status(&self, peer_id: &PeerId, status: PeerStatus) -> Result<()> {
        let mut peers = self.peers.write().unwrap();

        if let Some(peer) = peers.get_mut(&peer_id.public_key) {
            peer.set_status(status);
            Ok(())
        } else {
            anyhow::bail!("Peer not found: {}", peer_id)
        }
    }

    /// Update a peer's last seen time and other information
    pub fn update_peer(&self, peer_info: PeerInfo) -> Result<()> {
        let peer_public_key = peer_info.public_key.clone();

        let mut peers = self.peers.write().unwrap();
        if let Some(entry) = peers.get_mut(&peer_public_key) {
            // Update peer
            entry.last_seen = SystemTime::now();
            entry.peer_info = peer_info;
            Ok(())
        } else {
            anyhow::bail!("Peer not found for update: {}", peer_public_key)
        }
    }

    /// Find a peer by its node identifier and optional public key
    pub fn find_peer(&self, peer_public_key: String) -> Option<PeerEntry> {
        let peers = self.peers.read().unwrap();
        peers.get(&peer_public_key).cloned()
    }

    /// Find all peers with a specific status
    pub fn find_peers_by_status(&self, status: PeerStatus) -> Vec<PeerEntry> {
        let peers = self.peers.read().unwrap();
        peers
            .values()
            .filter(|p| p.status == status)
            .cloned()
            .collect()
    }

    /// Get all known peers
    pub fn get_all_peers(&self) -> Vec<PeerEntry> {
        let peers = self.peers.read().unwrap();
        peers.values().cloned().collect()
    }

    /// Remove a peer from the registry
    pub fn remove_peer(&self, id: &PeerId) -> Result<()> {
        let mut peers = self.peers.write().unwrap();

        // Remove peer
        if peers.remove(&id.public_key).is_some() {
            Ok(())
        } else {
            anyhow::bail!("Peer not found: {}", id.public_key)
        }
    }

    /// Clean up stale peers that haven't been seen recently
    pub fn cleanup_stale_peers(&self) -> usize {
        let mut removed_count = 0;

        // Identify stale peers
        let stale_keys: Vec<String> = {
            let peers = self.peers.read().unwrap();

            peers
                .iter()
                .filter(|(_, peer)| {
                    // Check if the peer has been seen within TTL
                    match peer.last_seen.elapsed() {
                        Ok(elapsed) => elapsed > self.options.peer_ttl,
                        Err(_) => false, // Future timestamp, keep it
                    }
                })
                .map(|(key, _)| key.clone())
                .collect()
        };

        // Remove them
        if !stale_keys.is_empty() {
            let mut peers = self.peers.write().unwrap();

            for key in stale_keys {
                // Remove peer
                peers.remove(&key);
                removed_count += 1;
            }
        }

        removed_count
    }
}
