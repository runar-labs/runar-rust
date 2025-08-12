//! StreamPool - Manages the reuse of QUIC streams
//!
//! INTENTION: Handles stream reuse, lifecycle, and timeouts for QUIC transport.

use std::sync::Arc;

use crate::network::transport::NetworkError;
use runar_common::logging::Logger;
use runar_macros_common::log_debug;
use tokio::sync::RwLock;

/// StreamPool - Manages the reuse of QUIC streams
///
/// INTENTION: This component manages stream reuse, implements stream lifecycle,
/// and handles stream timeouts.
///
/// ARCHITECTURAL BOUNDARIES:
/// - Only accessed by PeerState
/// - Manages creation, reuse, and cleanup of streams
pub struct StreamPool {
    pub idle_streams: RwLock<Vec<quinn::SendStream>>,
    pub max_idle_streams: usize,
    pub logger: Arc<Logger>,
}

impl StreamPool {
    /// Create a new StreamPool with the specified maximum idle streams
    ///
    /// INTENTION: Initialize a stream pool with a capacity for idle streams reuse.
    pub fn new(max_idle_streams: usize, logger: Arc<Logger>) -> Self {
        Self {
            idle_streams: RwLock::new(Vec::with_capacity(max_idle_streams)),
            max_idle_streams,
            logger,
        }
    }
    /// Get an idle stream from the pool if available
    ///
    /// INTENTION: Reuse existing streams to avoid the overhead of creating new ones.
    pub async fn get_idle_stream(&self) -> Option<quinn::SendStream> {
        let mut streams = self.idle_streams.write().await;
        streams.pop()
    }

    /// Return a stream to the pool for future reuse
    ///
    /// INTENTION: Efficiently manage QUIC stream resources.
    pub async fn return_stream(&self, stream: quinn::SendStream) -> Result<(), NetworkError> {
        let mut streams = self.idle_streams.write().await;
        if streams.len() < self.max_idle_streams {
            streams.push(stream);
            Ok(())
        } else {
            log_debug!(self.logger, "Dropping stream: pool is full");
            Ok(())
        }
    }

    /// Clear all idle streams in the pool
    ///
    /// INTENTION: Clean up resources when shutting down or disconnecting.
    pub async fn clear(&self) -> Result<(), NetworkError> {
        let mut streams = self.idle_streams.write().await;
        streams.clear();
        Ok(())
    }
}

impl std::fmt::Debug for StreamPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamPool").finish()
    }
}
