//! PeerState - Manages the state of a connection to a remote peer
//!
//! INTENTION: Tracks state, manages stream pools, and handles connection health for a single peer.

use crate::network::discovery::NodeInfo;
use crate::network::transport::{NetworkError, PeerId, StreamPool};
use runar_common::logging::Logger;
use std::fmt;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::sync::{mpsc, Mutex};

/// PeerState - Manages the state of a connection to a remote peer
///
/// INTENTION: This component tracks the state of individual peer connections,
/// manages stream pools, and handles connection health.
///
/// ARCHITECTURAL BOUNDARIES:
/// - Only accessed by ConnectionPool and QuicTransportImpl
/// - Manages its own StreamPool instance
/// - Handles connection lifecycle for a single peer
///
/// PeerState - Manages the state of a connection to a remote peer
///
/// INTENTION: This component tracks the state of individual peer connections,
/// manages stream pools, and handles connection health. Only mutable fields are
/// protected by granular locks for reduced contention.
pub struct PeerState {
    pub peer_id: PeerId,
    pub address: String,
    pub stream_pool: StreamPool,
    pub connection: Mutex<Option<quinn::Connection>>,
    pub last_activity: Mutex<std::time::Instant>,
    pub logger: Arc<Logger>,
    pub status_tx: mpsc::Sender<bool>,
    pub status_rx: Mutex<mpsc::Receiver<bool>>,
    /// Optional node information received during handshake
    pub node_info: RwLock<Option<NodeInfo>>,
}

impl PeerState {
    /// Create a new PeerState with the specified peer ID and address
    ///
    /// INTENTION: Initialize a new peer state with the given parameters.
    pub fn new(
        peer_id: PeerId,
        address: String,
        max_idle_streams: usize,
        logger: Arc<Logger>,
    ) -> Self {
        let (status_tx, status_rx) = mpsc::channel(10);
        Self {
            peer_id,
            address,
            stream_pool: StreamPool::new(max_idle_streams, logger.clone()),
            connection: Mutex::new(None),
            last_activity: Mutex::new(std::time::Instant::now()),
            logger,
            status_tx,
            status_rx: Mutex::new(status_rx),
            node_info: RwLock::new(None),
        }
    }

    /// Set the node info for this peer
    ///
    /// INTENTION: Store the node information received during handshake.
    pub async fn set_node_info(&self, node_info: NodeInfo) {
        let mut info = self.node_info.write().await;
        *info = Some(node_info);
        self.logger.info(format!(
            "Node info set for peer {peer_id}",
            peer_id = self.peer_id
        ));
    }
    /// Set the connection for this peer
    ///
    /// INTENTION: Establish a connection to the peer and update the state.
    pub async fn set_connection(&self, connection: quinn::Connection) {
        self.logger.info(format!(
            "🔗 [PeerState] Setting connection for peer {} - Remote: {}",
            self.peer_id,
            connection.remote_address()
        ));

        let mut conn_guard = self.connection.lock().await;
        *conn_guard = Some(connection);
        let mut last = self.last_activity.lock().await;
        *last = std::time::Instant::now();
        let _ = self.status_tx.send(true).await;
        self.logger.info(format!(
            "✅ [PeerState] Connection established with peer {} at {}",
            self.peer_id,
            std::time::Instant::now().elapsed().as_millis()
        ));
    }

    /// Check if peer is connected
    ///
    /// INTENTION: Determine if there's an active connection to the peer.
    pub async fn is_connected(&self) -> bool {
        let conn_guard = self.connection.lock().await;
        let connected = conn_guard.is_some();

        self.logger.debug(format!(
            "🔍 [PeerState] Connection check for peer {} - Connected: {}",
            self.peer_id, connected
        ));

        // If we have a connection, also check if it's still alive
        if connected {
            if let Some(conn) = conn_guard.as_ref() {
                let close_reason = conn.close_reason();
                if close_reason.is_some() {
                    self.logger.warn(format!(
                        "⚠️ [PeerState] Connection to peer {} is closed - Reason: {:?}",
                        self.peer_id, close_reason
                    ));
                    return false;
                }
            }
        }

        connected
    }

    /// Get a stream for sending messages to this peer
    ///
    /// INTENTION: Obtain a QUIC stream for sending data to this peer.
    pub async fn get_send_stream(&self) -> Result<quinn::SendStream, NetworkError> {
        self.logger.debug(format!(
            "🔄 [PeerState] Checking for idle stream for peer {}",
            self.peer_id
        ));

        if let Some(stream) = self.stream_pool.get_idle_stream().await {
            self.logger.debug(format!(
                "✅ [PeerState] Found idle stream for peer {}",
                self.peer_id
            ));
            return Ok(stream);
        }

        self.logger.debug(format!(
            "🆕 [PeerState] No idle stream available - creating new stream for peer {}",
            self.peer_id
        ));

        let mut conn_guard = self.connection.lock().await;
        if let Some(conn) = conn_guard.as_mut() {
            self.logger.debug(format!(
                "✅ [PeerState] Connection available for peer {} - opening new stream",
                self.peer_id
            ));

            match conn.open_bi().await {
                Ok((send_stream, _recv_stream)) => {
                    self.logger.info(format!(
                        "✅ [PeerState] Opened new bidirectional stream to peer {}",
                        self.peer_id
                    ));
                    Ok(send_stream)
                }
                Err(e) => {
                    self.logger.error(format!(
                        "❌ [PeerState] Failed to open stream to peer {}: {}",
                        self.peer_id, e
                    ));

                    // Log additional connection state information
                    self.logger.error(format!(
                        "🔍 [PeerState] Connection diagnostics for peer {} - Error details: {:?}",
                        self.peer_id, e
                    ));

                    Err(NetworkError::ConnectionError(format!(
                        "Failed to open stream: {e}"
                    )))
                }
            }
        } else {
            self.logger.error(format!(
                "❌ [PeerState] No connection available for peer {} - cannot create stream",
                self.peer_id
            ));
            Err(NetworkError::ConnectionError(
                "Not connected to peer".to_string(),
            ))
        }
    }

    /// Return a stream to the pool for reuse
    ///
    /// INTENTION: Recycle streams to avoid the overhead of creating new ones.
    pub async fn return_stream(&self, stream: quinn::SendStream) -> Result<(), NetworkError> {
        self.stream_pool.return_stream(stream).await
    }

    /// Get a clone of the connection for direct use
    ///
    /// INTENTION: Provide access to the connection for operations that need it directly
    pub async fn get_connection(&self) -> Option<quinn::Connection> {
        let conn_guard = self.connection.lock().await;
        conn_guard.clone()
    }

    /// Update the last activity timestamp
    ///
    /// INTENTION: Track when the peer was last active for connection management.
    pub async fn update_activity(&self) {
        let mut last = self.last_activity.lock().await;
        *last = std::time::Instant::now();
    }

    /// Close the connection to this peer
    ///
    /// INTENTION: Properly clean up resources when disconnecting from a peer.
    pub async fn close_connection(&self) -> Result<(), NetworkError> {
        let mut conn_guard = self.connection.lock().await;
        if let Some(conn) = conn_guard.take() {
            conn.close(0u32.into(), b"Connection closed by peer");
            let _ = self.status_tx.send(false).await;
            self.logger
                .info(format!("Connection closed with peer {}", self.peer_id));
        }
        let _ = self.stream_pool.clear().await;
        Ok(())
    }
}

impl fmt::Debug for PeerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerState")
            .field("peer_id", &self.peer_id)
            .field("address", &self.address)
            .finish()
    }
}
