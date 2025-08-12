//! ConnectionPool - Manages active QUIC peer connections
//!
//! INTENTION: Handles lifecycle, lookup, and management of all peer connections for QUIC transport.

use crate::network::transport::{NetworkError, PeerState};
use dashmap::DashMap;
use runar_common::logging::Logger;
use runar_macros_common::log_debug;
use std::sync::Arc;

/// ConnectionPool - Manages active connections
///
/// INTENTION: This component manages active connections, handles connection reuse,
/// and implements connection cleanup.
///
/// ARCHITECTURAL BOUNDARIES:
/// - Only accessed by QuicTransportImpl
/// - Handles connection lifecycle across all peers
///
/// ConnectionPool - Manages active peer connections using a concurrent map
///
/// INTENTION: Use DashMap for concurrent peer map access; PeerState is now granularly locked.
pub struct ConnectionPool {
    peers: DashMap<String, Arc<PeerState>>,
    logger: Arc<Logger>,
}

impl ConnectionPool {
    /// Create a new ConnectionPool
    ///
    /// INTENTION: Initialize a pool for managing peer connections.
    pub fn new(logger: Arc<Logger>) -> Self {
        Self {
            peers: DashMap::new(),
            logger,
        }
    }
    /// Get or create a peer state for the given peer ID and address
    ///
    /// INTENTION: Ensure we have a PeerState object for each peer we interact with.
    pub fn get_or_create_peer(
        &self,
        peer_node_id: String,
        address: String,
        max_idle_streams: usize,
        logger: Arc<Logger>,
    ) -> Arc<PeerState> {
        if let Some(existing) = self.peers.get(&peer_node_id) {
            existing.clone()
        } else {
            let peer_state = Arc::new(PeerState::new(
                peer_node_id.clone(),
                address,
                max_idle_streams,
                logger,
            ));
            self.peers.insert(peer_node_id.clone(), peer_state.clone());
            peer_state
        }
    }

    /// Get an existing peer state if it exists
    ///
    /// INTENTION: Retrieve the state for a specific peer connection.
    pub fn get_peer(&self, peer_node_id: &str) -> Option<Arc<PeerState>> {
        self.peers.get(peer_node_id).map(|entry| entry.clone())
    }

    /// Remove a peer from the connection pool
    ///
    /// INTENTION: Clean up resources when a peer is disconnected.
    pub async fn remove_peer(&self, peer_node_id: &str) -> Result<(), NetworkError> {
        if let Some((_, peer_state)) = self.peers.remove(peer_node_id) {
            let _ = peer_state.take_connection().await;
        }
        Ok(())
    }

    /// Check if a peer is connected
    ///
    /// INTENTION: Determine if we have an active connection to a specific peer.
    pub async fn is_peer_connected(&self, peer_node_id: &str) -> bool {
        if let Some(peer_state) = self.get_peer(peer_node_id) {
            peer_state.is_connected().await
        } else {
            false
        }
    }

    /// Get all connected peers
    ///
    /// INTENTION: Provide information about all currently connected peers.
    pub async fn get_connected_peers(&self) -> Vec<String> {
        let mut connected_peers = Vec::new();
        for entry in self.peers.iter() {
            let peer = entry.value();
            if peer.has_connection().await {
                connected_peers.push(entry.key().clone());
            }
        }
        log_debug!(
            self.logger,
            "get_connected_peers -> {}",
            connected_peers.len()
        );
        connected_peers
    }
}

impl std::fmt::Debug for ConnectionPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionPool").finish()
    }
}
