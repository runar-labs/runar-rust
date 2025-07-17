use std::sync::Arc;
use tokio::sync::RwLock;

use runar_keys::mobile::EnvelopeEncryptedData;
use runar_keys::NodeKeyManager;
use runar_keys::{EnvelopeCrypto, Result};

/// Read-only proxy to expose a `NodeKeyManager` as a generic `EnvelopeCrypto` implementation.
///
/// Transports only need read access to the key-manager (envelope encryption &
/// decryption).  By wrapping the manager in an `Arc<RwLock<_>>` we avoid extra
/// runtime locks inside the transport layer while still respecting the single
/// writer semantics enforced elsewhere (the Keys Service owns the only write
/// path).
pub struct KeystoreReadProxy {
    inner: Arc<RwLock<NodeKeyManager>>, // Shared read-only access
}

impl KeystoreReadProxy {
    /// Create a new read-only proxy from the shared `NodeKeyManager` instance
    pub fn new(inner: Arc<RwLock<NodeKeyManager>>) -> Self {
        Self { inner }
    }
}

impl EnvelopeCrypto for KeystoreReadProxy {
    fn encrypt_with_envelope(
        &self,
        data: &[u8],
        network_id: &str,
        profile_ids: Vec<String>,
    ) -> Result<EnvelopeEncryptedData> {
        // Synchronous read – transports operate in non-async contexts.
        #[allow(clippy::expect_used)]
        let guard = self.inner.blocking_read();
        guard.encrypt_with_envelope(data, network_id, profile_ids)
    }

    fn decrypt_envelope_data(&self, env: &EnvelopeEncryptedData) -> Result<Vec<u8>> {
        #[allow(clippy::expect_used)]
        let guard = self.inner.blocking_read();
        guard.decrypt_envelope_data(env)
    }
}
