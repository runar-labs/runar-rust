// Full impl for Keys
use napi::bindgen_prelude::*;
// Removed: ThreadsafeFunction not used in polling-based implementation
use napi_derive::napi;
use once_cell::sync::Lazy;
// Removed: DashMap and Uuid not needed in current implementation

// Error code constants - matching FFI API
pub const RN_ERROR_NULL_ARGUMENT: i32 = 1;
pub const RN_ERROR_INVALID_HANDLE: i32 = 2;
pub const RN_ERROR_NOT_INITIALIZED: i32 = 3;
pub const RN_ERROR_WRONG_MANAGER_TYPE: i32 = 4;
pub const RN_ERROR_OPERATION_FAILED: i32 = 5;
pub const RN_ERROR_SERIALIZATION_FAILED: i32 = 6;
pub const RN_ERROR_KEYSTORE_FAILED: i32 = 7;
pub const RN_ERROR_MEMORY_ALLOCATION: i32 = 12;
pub const RN_ERROR_LOCK_ERROR: i32 = 9;
pub const RN_ERROR_INVALID_UTF8: i32 = 10;
pub const RN_ERROR_INVALID_ARGUMENT: i32 = 11;

// New error codes for CA operations (Phase 2)
pub const RN_ERROR_CA_NODE_NOT_INITIALIZED: i32 = 1001;
pub const RN_ERROR_CA_SERVER_NOT_RUNNING: i32 = 1002;
pub const RN_ERROR_CA_CLIENT_CONNECTION_FAILED: i32 = 1003;
pub const RN_ERROR_CERTIFICATE_VALIDATION_FAILED: i32 = 1004;
pub const RN_ERROR_PROFILE_KEY_NOT_FOUND: i32 = 1005;
pub const RN_ERROR_ENROLLMENT_TOKEN_INVALID: i32 = 1006;
pub const RN_ERROR_RATE_LIMIT_EXCEEDED: i32 = 1007;
pub const RN_ERROR_ADMIN_NOT_AUTHORIZED: i32 = 1008;
pub const RN_ERROR_CERTIFICATE_CREATION_FAILED: i32 = 1009;
pub const RN_ERROR_CERTIFICATE_SKI_EXTRACTION_FAILED: i32 = 1010;
pub const RN_ERROR_CERTIFICATE_SERIAL_EXTRACTION_FAILED: i32 = 1011;
pub const RN_ERROR_ENROLLMENT_TOKEN_GENERATION_FAILED: i32 = 1012;
pub const RN_ERROR_MOBILE_RESPONSE_CONVERSION_FAILED: i32 = 1013;
pub const RN_ERROR_PROFILE_KEY_ENCRYPTION_FAILED: i32 = 1014;
pub const RN_ERROR_PROFILE_KEY_DECRYPTION_FAILED: i32 = 1015;
pub const RN_ERROR_CA_CLIENT_CONFIGURATION_FAILED: i32 = 1016;
pub const RN_ERROR_CRL_GENERATION_FAILED: i32 = 1017;

// Callback type definitions for Transport
pub type RequestCallback = Box<
    dyn Fn(
            TransportRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<TransportResponse, String>>
                    + Send
                    + 'static,
            >,
        > + Send
        + Sync,
>;
pub type EventCallback = Box<
    dyn Fn(
            TransportEvent,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'static>,
        > + Send
        + Sync,
>;
pub type PeerConnectedCallback = Box<
    dyn Fn(
            String,
            runar_schemas::NodeInfo,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>
        + Send
        + Sync,
>;
pub type PeerDisconnectedCallback = Box<
    dyn Fn(String) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>
        + Send
        + Sync,
>;

// Transport callback data structures
#[napi(object)]
pub struct TransportRequest {
    pub path: String,
    pub correlation_id: String,
    pub payload: Uint8Array,
    pub source_node_id: String,
    pub destination_node_id: String,
    pub profile_public_keys: Vec<Uint8Array>,
    pub network_public_key: Option<Uint8Array>,
}

#[napi(object)]
pub struct TransportResponse {
    pub payload: Uint8Array,
    pub correlation_id: String,
}

#[napi(object)]
pub struct TransportEvent {
    pub path: String,
    pub correlation_id: String,
    pub payload: Uint8Array,
    pub source_node_id: String,
    pub destination_node_id: String,
    pub profile_public_keys: Vec<Uint8Array>,
    pub network_public_key: Option<Uint8Array>,
}

// NodeInfo is defined in runar_schemas, we'll use that directly

// Envelope types for ThreadsafeFunction - only simple fields
#[napi(object)]
pub struct RequestEnvelope {
    pub request_id: String,
    pub path: String,
    pub correlation_id: String,
    pub payload: Uint8Array,
    pub source_node_id: String,
    pub destination_node_id: String,
    pub profile_public_keys: Vec<Uint8Array>,
    pub network_public_key: Option<Uint8Array>,
}

#[napi(object)]
pub struct EventEnvelope {
    pub path: String,
    pub correlation_id: String,
    pub payload: Uint8Array,
    pub source_node_id: String,
    pub destination_node_id: String,
    pub profile_public_keys: Vec<Uint8Array>,
    pub network_public_key: Option<Uint8Array>,
}

#[napi(object)]
pub struct PeerConnectedEnvelope {
    pub peer_id: String,
    pub node_public_key: Uint8Array,
    pub network_ids: Vec<String>,
    pub addresses: Vec<String>,
    pub version: u32,
    pub node_metadata: String, // JSON string for simplicity
}

#[napi(object)]
pub struct PeerDisconnectedEnvelope {
    pub peer_id: String,
}

// Note: Using polling pattern instead of ThreadsafeFunction
// Events are serialized to CBOR and sent via mpsc channels

#[napi(object)]
pub struct TransportOptions {
    #[napi(js_name = "bindAddr")]
    pub bind_addr: Option<String>,
    #[napi(js_name = "connectionIdleTimeout")]
    pub connection_idle_timeout: Option<u32>,
    #[napi(js_name = "keepAliveInterval")]
    pub keep_alive_interval: Option<u32>,
    #[napi(js_name = "maxMessageSize")]
    pub max_message_size: Option<u32>,
    #[napi(js_name = "enableRequestCallbacks")]
    pub enable_request_callbacks: Option<bool>,
    #[napi(js_name = "enableEventCallbacks")]
    pub enable_event_callbacks: Option<bool>,
    #[napi(js_name = "enablePeerCallbacks")]
    pub enable_peer_callbacks: Option<bool>,
}

// Enhanced error handling system
pub trait ErrorCodeMapping {
    fn to_error_code(&self) -> i32;
}

impl ErrorCodeMapping for runar_keys::KeyError {
    fn to_error_code(&self) -> i32 {
        match self {
            runar_keys::KeyError::ValidationError(_) => RN_ERROR_CERTIFICATE_VALIDATION_FAILED,
            runar_keys::KeyError::AuthorizationError(_) => RN_ERROR_ADMIN_NOT_AUTHORIZED,
            runar_keys::KeyError::CertificateError(_) => RN_ERROR_CERTIFICATE_CREATION_FAILED,
            runar_keys::KeyError::CertificateValidationError(_) => {
                RN_ERROR_CERTIFICATE_VALIDATION_FAILED
            }
            runar_keys::KeyError::InvalidKeyFormat(_) => RN_ERROR_INVALID_ARGUMENT,
            runar_keys::KeyError::SigningError(_) => RN_ERROR_OPERATION_FAILED,
            runar_keys::KeyError::EncodingError(_) => RN_ERROR_SERIALIZATION_FAILED,
            runar_keys::KeyError::DecryptionError(_) => RN_ERROR_PROFILE_KEY_DECRYPTION_FAILED,
            runar_keys::KeyError::NetworkError(_) => RN_ERROR_CA_CLIENT_CONNECTION_FAILED,
            runar_keys::KeyError::RateLimitError(_) => RN_ERROR_RATE_LIMIT_EXCEEDED,
            runar_keys::KeyError::KeyNotFound(_) => RN_ERROR_PROFILE_KEY_NOT_FOUND,
            runar_keys::KeyError::CertificateNotFound(_) => RN_ERROR_CERTIFICATE_CREATION_FAILED,
            runar_keys::KeyError::EncryptionError(_) => RN_ERROR_PROFILE_KEY_ENCRYPTION_FAILED,
            runar_keys::KeyError::InvalidOperation(_) => RN_ERROR_INVALID_ARGUMENT,
            runar_keys::KeyError::UnsupportedAlgorithm(_) => RN_ERROR_INVALID_ARGUMENT,
            runar_keys::KeyError::KeyDerivationError(_) => RN_ERROR_OPERATION_FAILED,
            runar_keys::KeyError::EcdhError(_) => RN_ERROR_OPERATION_FAILED,
            runar_keys::KeyError::SymmetricCipherError(_) => RN_ERROR_OPERATION_FAILED,
            runar_keys::KeyError::KeyAlreadyInitialized(_) => RN_ERROR_INVALID_ARGUMENT,
            runar_keys::KeyError::ChainValidationError(_) => RN_ERROR_CERTIFICATE_VALIDATION_FAILED,
            runar_keys::KeyError::X509ParserError(_) => RN_ERROR_CERTIFICATE_CREATION_FAILED,
            runar_keys::KeyError::IoError(_) => RN_ERROR_OPERATION_FAILED,
            runar_keys::KeyError::Pkcs8Error(_) => RN_ERROR_INVALID_ARGUMENT,
            runar_keys::KeyError::EcdsaError(_) => RN_ERROR_OPERATION_FAILED,
        }
    }
}

impl ErrorCodeMapping for runar_transporter::transport::NetworkError {
    fn to_error_code(&self) -> i32 {
        match self {
            runar_transporter::transport::NetworkError::ConnectionError(_) => {
                RN_ERROR_CA_CLIENT_CONNECTION_FAILED
            }
            runar_transporter::transport::NetworkError::MessageError(_) => {
                RN_ERROR_SERIALIZATION_FAILED
            }
            runar_transporter::transport::NetworkError::DiscoveryError(_) => {
                RN_ERROR_OPERATION_FAILED
            }
            runar_transporter::transport::NetworkError::TransportError(_) => {
                RN_ERROR_CA_CLIENT_CONNECTION_FAILED
            }
            runar_transporter::transport::NetworkError::ConfigurationError(_) => {
                RN_ERROR_CA_CLIENT_CONFIGURATION_FAILED
            }
        }
    }
}

// Helper function to create NAPI errors with proper error codes
pub fn create_napi_error_with_code(_code: i32, message: &str) -> napi::Error {
    let mut error = napi::Error::new(napi::Status::GenericFailure, message);
    error.status = napi::Status::GenericFailure;
    error
}

// Helper function to convert any error to NAPI error with appropriate code
pub fn to_napi_error_with_code<E: ErrorCodeMapping + std::fmt::Display>(error: E) -> napi::Error {
    let code = error.to_error_code();
    let message = format!("Error {code}: {error}");
    create_napi_error_with_code(code, &message)
}

use hex;
use once_cell::sync::OnceCell;
use runar_keys::{
    CANode, CertificateValidator, CsrEnrollRequest, EnrollmentToken as KeysEnrollmentToken,
    EnrollmentTokenBody, EnvelopeCrypto, MobileKeyManager, NodeKeyManager, RenewRequest,
    RevokeRequest,
};
use runar_logging::{Component, LogLevel, Logger, LoggingConfig};
use runar_schemas::NodeInfo;

// Global logger for NodeJS API (following FFI pattern)
static GLOBAL_LOGGER: OnceCell<Arc<Logger>> = OnceCell::new();

// Get or create global root logger
fn get_global_logger() -> Arc<Logger> {
    GLOBAL_LOGGER
        .get_or_init(|| Arc::new(Logger::new_root(Component::Custom("NodejsApi"))))
        .clone()
}

use runar_transporter::discovery::DiscoveryOptions;
use runar_transporter::transport::{NetworkTransport, QuicTransport, QuicTransportOptions};
use runar_transporter::{
    CaClient as TransporterCaClient, CaClientConfig, CaServer as TransporterCaServer,
    CaServerConfig, NodeDiscovery,
};
// use runar_transporter::transport::{NetworkMessage, NetworkMessagePayloadItem};
// use runar_ffi::{
//     TransportRequestParams, TransportCompleteRequestParams, TransportPublishParams,
// };
use serde::{Deserialize, Serialize};
use serde_cbor as cbor;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};

// Configuration types for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodejsCaServerConfig {
    pub bootstrap_bind: String,
    pub authenticated_bind: String,
    pub network_id: String,
    pub rate_limit_per_minute: u32,
    pub rate_limit_per_hour: u32,
    pub admin_skis: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodejsCaClientConfig {
    pub bootstrap_server: String,
    pub authenticated_server: String,
    pub network_id: String,
    pub request_timeout_seconds: u32,
    pub max_retries: u32,
    pub root_ca_der: Vec<u8>,
    pub issuing_ca_der: Vec<u8>,
}

static RT: Lazy<Runtime> = Lazy::new(|| Runtime::new().unwrap());

#[napi(object)]
pub struct DeviceKeystoreCaps {
    pub version: u32,
    pub flags: u32,
}

#[napi]
pub struct Keys {
    inner: Arc<Mutex<KeysInner>>,
}

struct KeysInner {
    node_key_manager: Option<Arc<RwLock<NodeKeyManager>>>,
    mobile_key_manager: Option<Arc<RwLock<MobileKeyManager>>>,
    persistence_dir: Option<String>,
    auto_persist: bool,
    logger: Arc<Logger>,

    local_node_info: Arc<Mutex<Option<NodeInfo>>>,
}

#[napi]
impl Keys {
    #[napi(constructor)]
    pub fn new() -> Self {
        let logger = Arc::new(get_global_logger().with_component(Component::Keys));
        Keys {
            inner: Arc::new(Mutex::new(KeysInner {
                node_key_manager: None,
                mobile_key_manager: None,
                persistence_dir: None,
                auto_persist: true,
                logger,

                local_node_info: Arc::new(Mutex::new(None)),
            })),
        }
    }

    /// Initialize this instance as a mobile manager
    /// Returns error if already initialized with different type
    #[napi]
    pub fn init_as_mobile(&self) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();

        // Check if already initialized as node
        if inner.node_key_manager.is_some() {
            return Err(Error::from_reason("Already initialized as node manager"));
        }

        // Initialize mobile manager if not already present
        if inner.mobile_key_manager.is_none() {
            let mobile = MobileKeyManager::new(inner.logger.clone())
                .map_err(|e| Error::from_reason(e.to_string()))?;
            inner.mobile_key_manager = Some(Arc::new(RwLock::new(mobile)));
        }

        Ok(())
    }

    /// Initialize this instance as a node manager
    /// Returns error if already initialized with different type
    /// CORRECTED: Only creates the key manager, nothing else
    #[napi]
    pub fn init_as_node(&self) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();

        // Check if already initialized as mobile
        if inner.mobile_key_manager.is_some() {
            return Err(Error::from_reason("Already initialized as mobile manager"));
        }

        // Initialize node manager if not already present
        if inner.node_key_manager.is_none() {
            let node = NodeKeyManager::new(inner.logger.clone())
                .map_err(|e| Error::from_reason(e.to_string()))?;

            inner.node_key_manager = Some(Arc::new(RwLock::new(node)));
        }

        Ok(())
    }

    #[napi]
    pub fn set_persistence_dir(&self, dir: String) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.persistence_dir = Some(dir.clone());
        if let Some(mut n) = inner
            .node_key_manager
            .as_ref()
            .map(|mgr| mgr.write().unwrap())
        {
            n.set_persistence_dir(dir.clone().into());
        }
        if let Some(mut m) = inner
            .mobile_key_manager
            .as_ref()
            .map(|mgr| mgr.write().unwrap())
        {
            m.set_persistence_dir(dir.into());
        }
        Ok(())
    }

    /// Check if node has keys loaded (replaces get_keystore_state)
    /// Returns true if keys are loaded and ready, false otherwise
    #[napi]
    pub fn has_keys(&self) -> Result<bool> {
        let inner = self.inner.lock().unwrap();

        if let Some(node_manager) = inner.node_key_manager.as_ref() {
            // Check if keys are actually generated by trying to get the node ID
            // If we can get the node ID, then keys are generated
            match node_manager.read().unwrap().get_node_id() {
                Some(_) => Ok(true),
                None => Ok(false),
            }
        } else {
            Ok(false)
        }
    }

    #[napi]
    pub fn node_get_keystore_state(&self) -> Result<i32> {
        let inner = self.inner.lock().unwrap();

        if let Some(node_manager) = inner.node_key_manager.as_ref() {
            // Check if keys are actually generated by trying to get the node ID
            // If we can get the node ID, then keys are generated
            match node_manager.read().unwrap().get_node_id() {
                Some(_) => Ok(1), // Keys are ready
                None => Ok(0),    // Keys not ready
            }
        } else {
            Ok(0) // No node manager
        }
    }

    #[napi]
    pub fn mobile_get_keystore_state(&self) -> Result<i32> {
        let inner = self.inner.lock().unwrap();

        if let Some(mobile_manager) = inner.mobile_key_manager.as_ref() {
            // Check if mobile keys are actually generated by trying to get the user public key
            match mobile_manager.read().unwrap().get_user_public_key() {
                Ok(_) => Ok(1),  // Keys are ready
                Err(_) => Ok(0), // Keys not ready
            }
        } else {
            Ok(0) // No mobile manager
        }
    }

    /// Generate keys for node (explicit key generation when no state exists)
    /// Returns error if keys already exist or if generation fails
    #[napi]
    pub fn generate_keys(&self) -> Result<()> {
        let inner = self.inner.lock().unwrap();

        if let Some(node_manager) = inner.node_key_manager.as_ref() {
            node_manager
                .write()
                .unwrap()
                .generate_keys()
                .map_err(|e| Error::from_reason(format!("Failed to generate keys: {e}")))?;
            Ok(())
        } else {
            Err(Error::from_reason("Node manager not initialized"))
        }
    }

    #[napi]
    pub fn node_generate_keys(&self) -> Result<()> {
        let inner = self.inner.lock().unwrap();

        if let Some(node_manager) = inner.node_key_manager.as_ref() {
            node_manager
                .write()
                .unwrap()
                .generate_keys()
                .map_err(|e| Error::from_reason(format!("Failed to generate keys: {e}")))?;
            Ok(())
        } else {
            Err(Error::from_reason("Node key manager not initialized"))
        }
    }

    #[napi]
    pub async fn mobile_initialize_user_root_key(&self) -> Result<()> {
        let mut guard = self.inner.lock().unwrap();
        if guard.mobile_key_manager.is_none() {
            guard.mobile_key_manager = Some(Arc::new(RwLock::new(
                MobileKeyManager::new(guard.logger.clone())
                    .map_err(|e| Error::from_reason(e.to_string()))?,
            )));
        }
        let _result = guard
            .mobile_key_manager
            .as_mut()
            .unwrap()
            .write()
            .unwrap()
            .initialize_user_root_key()
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(())
    }

    /// Encrypt data using envelope encryption with mobile manager
    ///
    /// This function encrypts data for a specific network and profile public keys
    /// using the mobile key manager's envelope encryption.
    #[napi]
    pub fn mobile_encrypt_with_envelope(
        &self,
        data: Uint8Array,
        network_public_key: Option<Uint8Array>, // ← NETWORK PUBLIC KEY BYTES
        profile_public_keys: Vec<Uint8Array>,
    ) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();

        let mobile_manager = inner
            .mobile_key_manager
            .as_ref()
            .ok_or_else(|| Error::from_reason("Mobile manager not initialized"))?;

        let network_public_key_ref = network_public_key.as_ref().map(|b| b.as_ref());
        let profile_keys_ref: Vec<Vec<u8>> =
            profile_public_keys.iter().map(|pk| pk.to_vec()).collect();

        let encrypted = mobile_manager
            .read()
            .unwrap()
            .encrypt_with_envelope(&data, network_public_key_ref, profile_keys_ref)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        // Convert EnvelopeEncryptedData to CBOR bytes like the FFI implementation
        let cbor_bytes = cbor::to_vec(&encrypted).map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(Uint8Array::from(cbor_bytes))
    }

    /// Encrypt data using envelope encryption with node manager
    ///
    /// This function encrypts data for a specific network and profile public keys
    /// using the node key manager's envelope encryption.
    #[napi]
    pub fn node_encrypt_with_envelope(
        &self,
        data: Uint8Array,
        network_public_key: Option<Uint8Array>, // ← NETWORK PUBLIC KEY BYTES
        profile_public_keys: Vec<Uint8Array>,
    ) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();

        let node_manager = inner
            .node_key_manager
            .as_ref()
            .ok_or_else(|| Error::from_reason("Node manager not initialized"))?;

        let network_public_key_ref = network_public_key.as_ref().map(|b| b.as_ref());
        let profile_keys_ref: Vec<Vec<u8>> =
            profile_public_keys.iter().map(|pk| pk.to_vec()).collect();

        let encrypted = node_manager
            .read()
            .unwrap()
            .encrypt_with_envelope(&data, network_public_key_ref, profile_keys_ref)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        // Convert EnvelopeEncryptedData to CBOR bytes like the FFI implementation
        let cbor_bytes = cbor::to_vec(&encrypted).map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(Uint8Array::from(cbor_bytes))
    }

    /// Decrypt data using envelope decryption with node manager
    #[napi]
    pub fn node_decrypt_with_envelope(&self, encrypted_data: Uint8Array) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();

        let node_manager = inner
            .node_key_manager
            .as_ref()
            .ok_or_else(|| Error::from_reason("Node manager not initialized"))?;

        // Parse the encrypted data from CBOR
        let encrypted: runar_keys::mobile::EnvelopeEncryptedData =
            cbor::from_slice(&encrypted_data)
                .map_err(|e| Error::from_reason(format!("Failed to parse encrypted data: {e}")))?;

        let decrypted = node_manager
            .read()
            .unwrap()
            .decrypt_envelope_data(&encrypted)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(Uint8Array::from(decrypted))
    }

    #[napi]
    pub fn node_get_node_id(&self) -> Result<String> {
        let inner = self.inner.lock().unwrap();
        let id = if let Some(n) = inner.node_key_manager.as_ref() {
            n.read().unwrap().get_node_id()
        } else {
            return Err(Error::from_reason("Node not init"));
        };

        match id {
            Some(node_id) => Ok(node_id),
            None => Err(Error::from_reason(
                "Node ID not available - call init_as_node first",
            )),
        }
    }

    #[napi]
    pub fn node_get_public_key(&self) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();
        let pk = if let Some(n) = inner.node_key_manager.as_ref() {
            n.read().unwrap().get_node_public_key()
        } else {
            return Err(Error::from_reason("Node not init"));
        };

        match pk {
            Some(public_key) => Ok(Uint8Array::from(public_key)),
            None => Err(Error::from_reason(
                "Node public key not available - call init_as_node first",
            )),
        }
    }

    #[napi]
    pub fn enable_auto_persist(&self, enabled: bool) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(n) = inner.node_key_manager.as_ref() {
            n.write().unwrap().enable_auto_persist(enabled);
        }
        if let Some(m) = inner.mobile_key_manager.as_ref() {
            m.write().unwrap().enable_auto_persist(enabled);
        }
        inner.auto_persist = enabled;
        Ok(())
    }

    #[napi]
    pub async fn wipe_persistence(&self) -> Result<()> {
        let inner = self.inner.lock().unwrap();
        if let Some(n) = inner.node_key_manager.as_ref() {
            n.write()
                .unwrap()
                .wipe_persistence()
                .map_err(|e| Error::from_reason(e.to_string()))?;
        }
        if let Some(m) = inner.mobile_key_manager.as_ref() {
            m.write()
                .unwrap()
                .wipe_persistence()
                .map_err(|e| Error::from_reason(e.to_string()))?;
        }
        Ok(())
    }

    #[napi]
    pub async fn flush_state(&self) -> Result<()> {
        let inner = self.inner.lock().unwrap();
        if let Some(n) = inner.node_key_manager.as_ref() {
            n.write()
                .unwrap()
                .flush_state()
                .map_err(|e| Error::from_reason(e.to_string()))?;
        }
        if let Some(m) = inner.mobile_key_manager.as_ref() {
            m.write()
                .unwrap()
                .flush_state()
                .map_err(|e| Error::from_reason(e.to_string()))?;
        }
        Ok(())
    }

    #[napi]
    pub fn get_keystore_caps(&self) -> Result<DeviceKeystoreCaps> {
        let inner = self.inner.lock().unwrap();
        let caps = if let Some(n) = inner.node_key_manager.as_ref() {
            n.read().unwrap().get_keystore_caps().unwrap_or_default()
        } else if let Some(m) = inner.mobile_key_manager.as_ref() {
            m.read().unwrap().get_keystore_caps().unwrap_or_default()
        } else {
            runar_keys::keystore::DeviceKeystoreCaps::default()
        };
        let mut flags = 0u32;
        if caps.hardware_backed {
            flags |= 1;
        }
        if caps.biometric_gate {
            flags |= 2;
        }
        if caps.screenlock_required {
            flags |= 4;
        }
        if caps.strongbox {
            flags |= 8;
        }
        Ok(DeviceKeystoreCaps {
            version: caps.version,
            flags,
        })
    }

    #[napi]
    pub fn encrypt_local_data(&self, data: Uint8Array) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();
        let node_ref = inner
            .node_key_manager
            .as_ref()
            .ok_or_else(|| Error::from_reason("Node not init".to_string()))?;
        let out = node_ref
            .read()
            .unwrap()
            .encrypt_local_data(&data)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Uint8Array::from(out))
    }

    #[napi]
    pub fn decrypt_local_data(&self, data: Uint8Array) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();
        let node_ref = inner
            .node_key_manager
            .as_ref()
            .ok_or_else(|| Error::from_reason("Node not init".to_string()))?;
        let out = node_ref
            .read()
            .unwrap()
            .decrypt_local_data(&data)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Uint8Array::from(out))
    }

    #[napi]
    pub fn mobile_decrypt_envelope(&self, eed_cbor: Uint8Array) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();

        // Validate mobile manager exists
        if inner.mobile_key_manager.is_none() {
            return Err(Error::from_reason("Mobile manager not initialized"));
        }

        let eed: runar_keys::mobile::EnvelopeEncryptedData =
            cbor::from_slice(eed_cbor.as_ref()).map_err(|e| Error::from_reason(e.to_string()))?;

        let plain = inner
            .mobile_key_manager
            .as_ref()
            .unwrap()
            .read()
            .unwrap()
            .decrypt_envelope_data(&eed)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(Uint8Array::from(plain))
    }

    #[napi]
    pub fn node_decrypt_envelope(&self, eed_cbor: Uint8Array) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();

        // Validate node manager exists
        if inner.node_key_manager.is_none() {
            return Err(Error::from_reason("Node manager not initialized"));
        }

        let eed: runar_keys::mobile::EnvelopeEncryptedData =
            cbor::from_slice(eed_cbor.as_ref()).map_err(|e| Error::from_reason(e.to_string()))?;

        let plain = if let Some(n) = inner.node_key_manager.as_ref() {
            n.read().unwrap().decrypt_envelope_data(&eed)
        } else {
            return Err(Error::from_reason("Node manager not available"));
        }
        .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(Uint8Array::from(plain))
    }

    #[napi]
    pub fn node_generate_csr(&self) -> Result<Uint8Array> {
        let mut inner = self.inner.lock().unwrap();
        let n = inner
            .node_key_manager
            .as_mut()
            .ok_or_else(|| Error::from_reason("node is shared; CSR not available".to_string()))?;
        let st = n
            .write()
            .unwrap()
            .generate_csr()
            .map_err(|e| Error::from_reason(e.to_string()))?;
        cbor::to_vec(&st)
            .map(Uint8Array::from)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn node_generate_csr_der(&self) -> Result<Uint8Array> {
        let mut inner = self.inner.lock().unwrap();
        let n = inner
            .node_key_manager
            .as_mut()
            .ok_or_else(|| Error::from_reason("node is shared; CSR not available".to_string()))?;
        let st = n
            .write()
            .unwrap()
            .generate_csr()
            .map_err(|e| Error::from_reason(e.to_string()))?;
        // Return just the CSR DER bytes, not the entire SetupToken
        Ok(Uint8Array::from(st.csr_der))
    }

    #[napi]
    pub fn mobile_process_setup_token(&self, st_cbor: Uint8Array) -> Result<Uint8Array> {
        let mut inner = self.inner.lock().unwrap();
        if inner.mobile_key_manager.is_none() {
            inner.mobile_key_manager = Some(Arc::new(RwLock::new(
                MobileKeyManager::new(inner.logger.clone())
                    .map_err(|e| Error::from_reason(e.to_string()))?,
            )));
        }
        let st: runar_keys::mobile::SetupToken =
            cbor::from_slice(st_cbor.as_ref()).map_err(|e| Error::from_reason(e.to_string()))?;
        let msg = inner
            .mobile_key_manager
            .as_mut()
            .unwrap()
            .write()
            .unwrap()
            .process_setup_token(&st)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        cbor::to_vec(&msg)
            .map(Uint8Array::from)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn node_install_certificate(&self, ncm_cbor: Uint8Array) -> Result<()> {
        let inner = self.inner.lock().unwrap();
        let n = inner.node_key_manager.as_ref().ok_or_else(|| {
            Error::from_reason("node is shared; install_certificate not available".to_string())
        })?;
        let mut n = n.write().unwrap();
        let msg: runar_keys::mobile::NodeCertificateMessage =
            cbor::from_slice(ncm_cbor.as_ref()).map_err(|e| Error::from_reason(e.to_string()))?;
        n.install_certificate(msg)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn mobile_generate_network_data_key(&self) -> Result<Uint8Array> {
        let mut inner = self.inner.lock().unwrap();
        if inner.mobile_key_manager.is_none() {
            inner.mobile_key_manager = Some(Arc::new(RwLock::new(
                MobileKeyManager::new(inner.logger.clone())
                    .map_err(|e| Error::from_reason(e.to_string()))?,
            )));
        }
        let result = inner
            .mobile_key_manager
            .as_mut()
            .unwrap()
            .write()
            .unwrap()
            .generate_network_data_key()
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Uint8Array::from(result))
    }

    #[napi]
    pub fn mobile_install_network_public_key(&self, network_pk: Uint8Array) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.mobile_key_manager.is_none() {
            inner.mobile_key_manager = Some(Arc::new(RwLock::new(
                MobileKeyManager::new(inner.logger.clone())
                    .map_err(|e| Error::from_reason(e.to_string()))?,
            )));
        }
        inner
            .mobile_key_manager
            .as_mut()
            .unwrap()
            .write()
            .unwrap()
            .install_network_public_key(&network_pk)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(())
    }

    #[napi]
    pub fn node_install_network_key(&self, nkm_cbor: Uint8Array) -> Result<()> {
        let inner = self.inner.lock().unwrap();
        let n = inner.node_key_manager.as_ref().ok_or_else(|| {
            Error::from_reason("node is shared; install_network_key not available".to_string())
        })?;
        let mut n = n.write().unwrap();
        let msg: runar_keys::mobile::NetworkKeyMessage =
            cbor::from_slice(nkm_cbor.as_ref()).map_err(|e| Error::from_reason(e.to_string()))?;
        n.install_network_key(msg)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn set_local_node_info(&self, node_info_cbor: Uint8Array) -> Result<()> {
        let info: NodeInfo = cbor::from_slice(node_info_cbor.as_ref())
            .map_err(|e| Error::from_reason(e.to_string()))?;
        let inner = self.inner.lock().unwrap();
        let mut holder = inner.local_node_info.lock().unwrap();
        *holder = Some(info);
        Ok(())
    }

    #[napi]
    pub fn encrypt_for_network(
        &self,
        data: Uint8Array,
        network_public_key: Uint8Array,
    ) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();
        let node_ref = inner
            .node_key_manager
            .as_ref()
            .ok_or_else(|| Error::from_reason("Node not init".to_string()))?;
        let eed = node_ref
            .read()
            .unwrap()
            .encrypt_for_network(&data, &network_public_key)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        cbor::to_vec(&eed)
            .map(Uint8Array::from)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn decrypt_network_data(&self, eed_cbor: Uint8Array) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();
        let node_ref = inner
            .node_key_manager
            .as_ref()
            .ok_or_else(|| Error::from_reason("Node not init".to_string()))?;
        let eed: runar_keys::mobile::EnvelopeEncryptedData =
            cbor::from_slice(eed_cbor.as_ref()).map_err(|e| Error::from_reason(e.to_string()))?;
        let plain = node_ref
            .read()
            .unwrap()
            .decrypt_network_data(&eed)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Uint8Array::from(plain))
    }

    #[napi]
    pub fn encrypt_message_for_mobile(
        &self,
        message: Uint8Array,
        mobile_pk: Uint8Array,
    ) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();
        let node_ref = inner
            .node_key_manager
            .as_ref()
            .ok_or_else(|| Error::from_reason("Node not init".to_string()))?;
        let cipher = node_ref
            .read()
            .unwrap()
            .encrypt_message_for_mobile(&message, &mobile_pk)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Uint8Array::from(cipher))
    }

    #[napi]
    pub fn decrypt_message_from_mobile(&self, encrypted: Uint8Array) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();
        let node_ref = inner
            .node_key_manager
            .as_ref()
            .ok_or_else(|| Error::from_reason("Node not init".to_string()))?;
        let plain = node_ref
            .read()
            .unwrap()
            .decrypt_message_from_mobile(&encrypted)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Uint8Array::from(plain))
    }

    #[napi]
    pub fn mobile_derive_user_profile_key(&self, label: String) -> Result<Uint8Array> {
        let mut inner = self.inner.lock().unwrap();
        if inner.mobile_key_manager.is_none() {
            inner.mobile_key_manager = Some(Arc::new(RwLock::new(
                MobileKeyManager::new(inner.logger.clone())
                    .map_err(|e| Error::from_reason(e.to_string()))?,
            )));
        }
        let pk = inner
            .mobile_key_manager
            .as_mut()
            .unwrap()
            .write()
            .unwrap()
            .derive_user_profile_key(&label)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Uint8Array::from(pk))
    }

    #[napi]
    pub fn mobile_has_network_private_key(&self, network_public_key: Uint8Array) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if inner.mobile_key_manager.is_none() {
            match MobileKeyManager::new(inner.logger.clone()) {
                Ok(manager) => {
                    inner.mobile_key_manager = Some(Arc::new(RwLock::new(manager)));
                }
                Err(_) => {
                    // Return false if we can't create the manager
                    return false;
                }
            }
        }
        let has_key = inner
            .mobile_key_manager
            .as_mut()
            .unwrap()
            .write()
            .unwrap()
            .has_network_private_key(&network_public_key);
        has_key
    }

    #[napi]
    pub fn mobile_create_network_key_message(
        &self,
        network_public_key: Uint8Array,
        node_agreement_pk: Uint8Array,
    ) -> Result<Uint8Array> {
        let mut inner = self.inner.lock().unwrap();
        if inner.mobile_key_manager.is_none() {
            inner.mobile_key_manager = Some(Arc::new(RwLock::new(
                MobileKeyManager::new(inner.logger.clone())
                    .map_err(|e| Error::from_reason(e.to_string()))?,
            )));
        }
        let msg = inner
            .mobile_key_manager
            .as_mut()
            .unwrap()
            .write()
            .unwrap()
            .create_network_key_message(&network_public_key, &node_agreement_pk)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        cbor::to_vec(&msg)
            .map(Uint8Array::from)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn ensure_symmetric_key(&self, key_name: String) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();
        let key = if let Some(n) = inner.node_key_manager.as_ref() {
            n.write().unwrap().ensure_symmetric_key(&key_name)
        } else if let Some(_n) = inner.node_key_manager.as_ref() {
            // For shared NodeKeyManager, we can't modify it, so we can't ensure symmetric keys
            return Err(Error::from_reason(
                "node is shared; ensure_symmetric_key not available",
            ));
        } else {
            return Err(Error::from_reason("Node not init"));
        }
        .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Uint8Array::from(key))
    }

    /// Get the user public key after mobile initialization
    /// This is essential for encrypting setup tokens to the mobile
    #[napi]
    pub fn mobile_get_user_public_key(&self) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();

        // Validate mobile manager exists
        if inner.mobile_key_manager.is_none() {
            return Err(Error::from_reason("Mobile manager not initialized"));
        }

        let pk = inner
            .mobile_key_manager
            .as_ref()
            .unwrap()
            .read()
            .unwrap()
            .get_user_public_key()
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(Uint8Array::from(pk))
    }

    #[napi]
    pub fn mobile_get_public_key(&self) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();

        // Validate mobile manager exists
        if inner.mobile_key_manager.is_none() {
            return Err(Error::from_reason("Mobile manager not initialized"));
        }

        let pk = inner
            .mobile_key_manager
            .as_ref()
            .unwrap()
            .read()
            .unwrap()
            .get_user_public_key()
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(Uint8Array::from(pk))
    }

    /// Get the node agreement public key
    /// This is used for verifying agreement keys in CSR flow
    #[napi]
    pub fn node_get_agreement_public_key(&self) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();

        // Validate node manager exists
        if inner.node_key_manager.is_none() {
            return Err(Error::from_reason("Node manager not initialized"));
        }

        let pk = if let Some(n) = inner.node_key_manager.as_ref() {
            n.read().unwrap().get_node_agreement_public_key()
        } else {
            return Err(Error::from_reason("Node manager not available"));
        }
        .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(Uint8Array::from(pk))
    }

    /// Convert CA Node enrollment response to NodeCertificateMessage format for certificate installation
    #[napi]
    pub fn mobile_from_enroll_response(&self, response_cbor: Uint8Array) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();

        // Validate mobile manager exists
        if inner.mobile_key_manager.is_none() {
            return Err(Error::from_reason("Mobile manager not initialized"));
        }

        // Deserialize the enrollment response
        let response: runar_keys::ca_node_types::CsrEnrollResponse =
            cbor::from_slice(&response_cbor).map_err(|e| {
                Error::from_reason(format!("Failed to parse enrollment response: {e}"))
            })?;

        // Convert to NodeCertificateMessage
        let cert_message = inner
            .mobile_key_manager
            .as_ref()
            .unwrap()
            .read()
            .unwrap()
            .from_enroll_response(&response)
            .map_err(|e| {
                Error::from_reason(format!("Failed to convert enrollment response: {e}"))
            })?;

        // Serialize the NodeCertificateMessage
        cbor::to_vec(&cert_message)
            .map(Uint8Array::from)
            .map_err(|e| {
                Error::from_reason(format!("Failed to serialize certificate message: {e}"))
            })
    }

    /// Convert CA Node renewal response to NodeCertificateMessage format for certificate installation
    #[napi]
    pub fn mobile_from_renew_response(&self, response_cbor: Uint8Array) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();

        // Validate mobile manager exists
        if inner.mobile_key_manager.is_none() {
            return Err(Error::from_reason("Mobile manager not initialized"));
        }

        // Deserialize the renewal response
        let response: runar_keys::ca_node_types::RenewResponse = cbor::from_slice(&response_cbor)
            .map_err(|e| {
            Error::from_reason(format!("Failed to parse renewal response: {e}"))
        })?;

        // Convert to NodeCertificateMessage
        let cert_message = inner
            .mobile_key_manager
            .as_ref()
            .unwrap()
            .read()
            .unwrap()
            .from_renew_response(&response)
            .map_err(|e| Error::from_reason(format!("Failed to convert renewal response: {e}")))?;

        // Serialize the NodeCertificateMessage
        cbor::to_vec(&cert_message)
            .map(Uint8Array::from)
            .map_err(|e| {
                Error::from_reason(format!("Failed to serialize certificate message: {e}"))
            })
    }

    /// Derive user profile key using node manager (for mobile role)
    /// This is used when the node is acting as a mobile device
    #[napi]
    pub fn node_derive_user_profile_key(&self, label: String) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();

        // Validate node manager exists
        if inner.node_key_manager.is_none() {
            return Err(Error::from_reason("Node manager not initialized"));
        }

        let pk = inner
            .node_key_manager
            .as_ref()
            .unwrap()
            .write()
            .unwrap()
            .derive_user_profile_key(&label)
            .map_err(|e| Error::from_reason(format!("Failed to derive profile key: {e}")))?;

        Ok(Uint8Array::from(pk))
    }

    /// Decrypt data using profile key (for mobile role)
    /// This is used when the node is acting as a mobile device
    #[napi]
    pub fn node_decrypt_with_profile(
        &self,
        envelope_cbor: Uint8Array,
        profile_id: String,
    ) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();

        // Validate node manager exists
        if inner.node_key_manager.is_none() {
            return Err(Error::from_reason("Node manager not initialized"));
        }

        // Deserialize the envelope encrypted data
        let eed: runar_keys::mobile::EnvelopeEncryptedData =
            cbor::from_slice(envelope_cbor.as_ref())
                .map_err(|e| Error::from_reason(format!("Failed to parse envelope: {e}")))?;

        let plain = inner
            .node_key_manager
            .as_ref()
            .unwrap()
            .read()
            .unwrap()
            .decrypt_with_profile(&eed, &profile_id)
            .map_err(|e| Error::from_reason(format!("Failed to decrypt with profile: {e}")))?;

        Ok(Uint8Array::from(plain))
    }

    /// Extract SKI (Subject Key Identifier) from DER-encoded certificate
    #[napi]
    pub fn certificate_extract_ski(cert_der: Uint8Array) -> Result<String> {
        let cert = runar_keys::certificate::X509Certificate::from_der(cert_der.to_vec())
            .map_err(|e| Error::from_reason(format!("Failed to parse certificate: {e}")))?;

        let ski_bytes = runar_keys::certificate::CertificateValidator::extract_ski(&cert)
            .map_err(|e| Error::from_reason(format!("Failed to extract SKI: {e}")))?;

        // Convert to hex string
        let ski_hex = ski_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("");
        Ok(ski_hex)
    }

    /// Extract serial number from DER-encoded certificate
    #[napi]
    pub fn certificate_get_serial(cert_der: Uint8Array) -> Result<String> {
        let cert = runar_keys::certificate::X509Certificate::from_der(cert_der.to_vec())
            .map_err(|e| Error::from_reason(format!("Failed to parse certificate: {e}")))?;

        let parsed = cert
            .parsed()
            .map_err(|e| Error::from_reason(format!("Failed to parse certificate: {e}")))?;

        let serial = parsed.tbs_certificate.serial.to_string();
        Ok(serial)
    }

    /// Get node certificate (for QUIC mTLS)
    /// Returns the DER-encoded node certificate
    #[napi]
    pub fn node_get_node_certificate(&self) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();

        if let Some(node_manager) = inner.node_key_manager.as_ref() {
            let node_guard = node_manager.read().unwrap();
            let cert = node_guard
                .get_node_certificate()
                .ok_or_else(|| Error::from_reason("Node certificate not available"))?;
            let der_bytes = cert.der_bytes().to_vec();
            Ok(Uint8Array::from(der_bytes))
        } else {
            Err(Error::from_reason("Node manager not initialized"))
        }
    }

    /// Get QUIC certificate configuration
    /// Returns CBOR-encoded QUIC certificate configuration
    #[napi]
    pub fn node_get_quic_certificate_config(&self) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();

        if let Some(node_manager) = inner.node_key_manager.as_ref() {
            let _config = node_manager
                .read()
                .unwrap()
                .get_quic_certificate_config()
                .map_err(|e| {
                    Error::from_reason(format!("Failed to get QUIC certificate config: {e}"))
                })?;

            // For now, return a simple placeholder CBOR structure
            // The full implementation would serialize the actual config
            let placeholder_config = serde_json::json!({
                "certificate": "placeholder",
                "private_key": "placeholder"
            });

            let config_cbor = cbor::to_vec(&placeholder_config)
                .map_err(|e| Error::from_reason(format!("Failed to serialize QUIC config: {e}")))?;
            Ok(Uint8Array::from(config_cbor))
        } else {
            Err(Error::from_reason("Node manager not initialized"))
        }
    }
}

#[cfg(all(feature = "linux-keystore", target_os = "linux"))]
#[napi]
impl Keys {
    #[napi]
    pub fn register_linux_device_keystore(&self, service: String, account: String) -> Result<()> {
        let inner = self.inner.lock().unwrap();
        let ks: Arc<dyn runar_keys::keystore::DeviceKeystore> = Arc::new(
            runar_keys::keystore::linux::LinuxDeviceKeystore::new(&service, &account)
                .map_err(|e| Error::from_reason(e.to_string()))?,
        );
        if let Some(n) = inner.node_key_manager.as_ref() {
            n.write().unwrap().register_device_keystore(ks.clone());
        }
        if let Some(m) = inner.mobile_key_manager.as_ref() {
            m.write().unwrap().register_device_keystore(ks.clone());
        }
        Ok(())
    }
}

impl Default for Keys {
    fn default() -> Self {
        Self::new()
    }
}

// Transport - Polling Pattern (following FFI exactly)
#[napi]
pub struct Transport {
    state: Arc<TransportState>,
}

struct TransportState {
    transport: Arc<QuicTransport>,
    #[allow(dead_code)] // Used by callbacks stored during initialization
    events_tx: mpsc::UnboundedSender<Vec<u8>>,
    events_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
    pending_requests: Arc<
        tokio::sync::Mutex<
            HashMap<String, oneshot::Sender<runar_transporter::transport::NetworkMessage>>,
        >,
    >,
    running: Arc<tokio::sync::Mutex<bool>>,
}

#[napi]
impl Transport {
    /// Create new Transport with QuicTransport backend
    /// Following FFI pattern exactly - bridge callbacks to polling channels
    #[napi(constructor)]
    pub fn new(keys: &Keys, options: TransportOptions) -> Result<Self> {
        // Get keys inner
        let keys_inner = keys
            .inner
            .lock()
            .map_err(|_| Error::from_reason("Failed to acquire keys lock"))?;

        // Get node manager
        let manager = keys_inner
            .node_key_manager
            .as_ref()
            .ok_or_else(|| Error::from_reason("Node manager not initialized"))?;

        // Check local node info is set
        {
            let local_info = keys_inner
                .local_node_info
                .lock()
                .map_err(|_| Error::from_reason("Failed to acquire local_node_info lock"))?;
            if local_info.is_none() {
                return Err(Error::from_reason(
                    "Local NodeInfo required - call setLocalNodeInfo first",
                ));
            }
        }

        // Get node public key
        let node_public_key = {
            let mgr = manager
                .read()
                .map_err(|_| Error::from_reason("Failed to acquire node manager lock"))?;
            mgr.get_node_public_key()
                .ok_or_else(|| Error::from_reason("Node public key not available"))?
        };

        // Create channels for polling (exactly like FFI)
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let pending_requests: Arc<
            tokio::sync::Mutex<
                HashMap<String, oneshot::Sender<runar_transporter::transport::NetworkMessage>>,
            >,
        > = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

        // Create request callback (exactly like FFI lines 3794-3857)
        let req_tx = events_tx.clone();
        let pending_cb = pending_requests.clone();
        let request_callback: runar_transporter::transport::RequestCallback =
            Arc::new(move |req| {
                let req_tx = req_tx.clone();
                let pending_cb = pending_cb.clone();
                Box::pin(async move {
                    let request_id = uuid::Uuid::new_v4().to_string();
                    let (tx_resp, rx_resp) = oneshot::channel();
                    pending_cb.lock().await.insert(request_id.clone(), tx_resp);

                    // Build CBOR event
                    let mut map = std::collections::BTreeMap::new();
                    map.insert(
                        serde_cbor::Value::Text("type".into()),
                        serde_cbor::Value::Text("RequestReceived".into()),
                    );
                    map.insert(
                        serde_cbor::Value::Text("v".into()),
                        serde_cbor::Value::Integer(1),
                    );
                    map.insert(
                        serde_cbor::Value::Text("request_id".into()),
                        serde_cbor::Value::Text(request_id.clone()),
                    );
                    map.insert(
                        serde_cbor::Value::Text("path".into()),
                        serde_cbor::Value::Text(req.payload.path.clone()),
                    );
                    map.insert(
                        serde_cbor::Value::Text("correlation_id".into()),
                        serde_cbor::Value::Text(req.payload.correlation_id.clone()),
                    );
                    map.insert(
                        serde_cbor::Value::Text("payload".into()),
                        serde_cbor::Value::Bytes(req.payload.payload_bytes.clone()),
                    );
                    map.insert(
                        serde_cbor::Value::Text("source_node_id".into()),
                        serde_cbor::Value::Text(req.source_node_id.clone()),
                    );
                    map.insert(
                        serde_cbor::Value::Text("destination_node_id".into()),
                        serde_cbor::Value::Text(req.destination_node_id.clone()),
                    );
                    map.insert(
                        serde_cbor::Value::Text("profile_public_keys".into()),
                        serde_cbor::Value::Array(
                            req.payload
                                .profile_public_keys
                                .iter()
                                .map(|k| serde_cbor::Value::Bytes(k.clone()))
                                .collect(),
                        ),
                    );
                    if let Some(npk) = &req.payload.network_public_key {
                        map.insert(
                            serde_cbor::Value::Text("network_public_key".into()),
                            serde_cbor::Value::Bytes(npk.clone()),
                        );
                    }

                    if let Ok(cbor_bytes) = serde_cbor::to_vec(&serde_cbor::Value::Map(map)) {
                        let _ = req_tx.send(cbor_bytes);
                    }

                    // Wait for response
                    match rx_resp.await {
                        Ok(resp) => Ok(resp),
                        Err(_) => Ok(runar_transporter::transport::NetworkMessage {
                            source_node_id: String::new(),
                            destination_node_id: String::new(),
                            message_type: 5,
                            payload: runar_transporter::transport::NetworkMessagePayloadItem {
                                path: String::new(),
                                payload_bytes: Vec::new(),
                                correlation_id: String::new(),
                                network_public_key: None,
                                profile_public_keys: Vec::new(),
                            },
                        }),
                    }
                })
            });

        // Create event callback (exactly like FFI lines 3859-3889)
        let ev_tx = events_tx.clone();
        let event_callback: runar_transporter::transport::EventCallback = Arc::new(move |ev| {
            let ev_tx = ev_tx.clone();
            Box::pin(async move {
                let mut map = std::collections::BTreeMap::new();
                map.insert(
                    serde_cbor::Value::Text("type".into()),
                    serde_cbor::Value::Text("EventReceived".into()),
                );
                map.insert(
                    serde_cbor::Value::Text("v".into()),
                    serde_cbor::Value::Integer(1),
                );
                map.insert(
                    serde_cbor::Value::Text("path".into()),
                    serde_cbor::Value::Text(ev.payload.path.clone()),
                );
                map.insert(
                    serde_cbor::Value::Text("correlation_id".into()),
                    serde_cbor::Value::Text(ev.payload.correlation_id.clone()),
                );
                map.insert(
                    serde_cbor::Value::Text("payload".into()),
                    serde_cbor::Value::Bytes(ev.payload.payload_bytes.clone()),
                );
                map.insert(
                    serde_cbor::Value::Text("source_node_id".into()),
                    serde_cbor::Value::Text(ev.source_node_id.clone()),
                );
                map.insert(
                    serde_cbor::Value::Text("destination_node_id".into()),
                    serde_cbor::Value::Text(ev.destination_node_id.clone()),
                );
                map.insert(
                    serde_cbor::Value::Text("profile_public_keys".into()),
                    serde_cbor::Value::Array(
                        ev.payload
                            .profile_public_keys
                            .iter()
                            .map(|k| serde_cbor::Value::Bytes(k.clone()))
                            .collect(),
                    ),
                );
                if let Some(npk) = &ev.payload.network_public_key {
                    map.insert(
                        serde_cbor::Value::Text("network_public_key".into()),
                        serde_cbor::Value::Bytes(npk.clone()),
                    );
                }

                if let Ok(cbor_bytes) = serde_cbor::to_vec(&serde_cbor::Value::Map(map)) {
                    let _ = ev_tx.send(cbor_bytes);
                }
                Ok(())
            })
        });

        // Create peer connected callback
        let pc_tx = events_tx.clone();
        let peer_connected_callback: runar_transporter::transport::PeerConnectedCallback =
            Arc::new(move |peer_id, node_info| {
                let pc_tx = pc_tx.clone();
                Box::pin(async move {
                    let mut map = std::collections::BTreeMap::new();
                    map.insert(
                        serde_cbor::Value::Text("type".into()),
                        serde_cbor::Value::Text("PeerConnected".into()),
                    );
                    map.insert(
                        serde_cbor::Value::Text("v".into()),
                        serde_cbor::Value::Integer(1),
                    );
                    map.insert(
                        serde_cbor::Value::Text("peer_id".into()),
                        serde_cbor::Value::Text(peer_id),
                    );
                    // Flatten NodeInfo
                    let mut node_info_map = std::collections::BTreeMap::new();
                    node_info_map.insert(
                        serde_cbor::Value::Text("node_public_key".into()),
                        serde_cbor::Value::Bytes(node_info.node_public_key.clone()),
                    );
                    node_info_map.insert(
                        serde_cbor::Value::Text("network_ids".into()),
                        serde_cbor::Value::Array(
                            node_info
                                .network_ids
                                .iter()
                                .map(|id| serde_cbor::Value::Text(id.clone()))
                                .collect(),
                        ),
                    );
                    node_info_map.insert(
                        serde_cbor::Value::Text("addresses".into()),
                        serde_cbor::Value::Array(
                            node_info
                                .addresses
                                .iter()
                                .map(|addr| serde_cbor::Value::Text(addr.to_string()))
                                .collect(),
                        ),
                    );
                    node_info_map.insert(
                        serde_cbor::Value::Text("version".into()),
                        serde_cbor::Value::Integer(node_info.version as i128),
                    );
                    map.insert(
                        serde_cbor::Value::Text("node_info".into()),
                        serde_cbor::Value::Map(node_info_map),
                    );

                    if let Ok(cbor_bytes) = serde_cbor::to_vec(&serde_cbor::Value::Map(map)) {
                        let _ = pc_tx.send(cbor_bytes);
                    }
                })
            });

        // Create peer disconnected callback
        let pd_tx = events_tx.clone();
        let peer_disconnected_callback: runar_transporter::transport::PeerDisconnectedCallback =
            Arc::new(move |peer_id| {
                let pd_tx = pd_tx.clone();
                Box::pin(async move {
                    let mut map = std::collections::BTreeMap::new();
                    map.insert(
                        serde_cbor::Value::Text("type".into()),
                        serde_cbor::Value::Text("PeerDisconnected".into()),
                    );
                    map.insert(
                        serde_cbor::Value::Text("v".into()),
                        serde_cbor::Value::Integer(1),
                    );
                    map.insert(
                        serde_cbor::Value::Text("peer_node_id".into()),
                        serde_cbor::Value::Text(peer_id),
                    );

                    if let Ok(cbor_bytes) = serde_cbor::to_vec(&serde_cbor::Value::Map(map)) {
                        let _ = pd_tx.send(cbor_bytes);
                    }
                })
            });

        // Build QuicTransport options
        let mut transport_options = QuicTransportOptions::new();
        if let Some(bind_addr) = options.bind_addr {
            if let Ok(addr) = bind_addr.parse() {
                transport_options = transport_options.with_bind_addr(addr);
            }
        }
        // Note: connection_idle_timeout, keep_alive_interval, and max_message_size
        // are not currently supported by QuicTransportOptions. They are managed
        // by the underlying QUIC implementation defaults.

        // Configure mTLS - get certificate configuration from key manager (FFI lines 3963-4006)
        let cert_config = {
            let mgr = manager
                .read()
                .map_err(|_| Error::from_reason("Failed to acquire manager lock"))?;
            mgr.get_quic_certificate_config()
                .map_err(|e| Error::from_reason(format!("Failed to get certificate config: {e}")))?
        };

        // Extract CA certificate from certificate chain (last certificate in chain)
        let ca_cert = cert_config
            .certificate_chain
            .last()
            .ok_or_else(|| Error::from_reason("CA certificate not found in certificate chain"))?;

        // Create get_local_node_info callback (like FFI lines 3937-3949)
        let local_node_info_holder = Arc::clone(&keys_inner.local_node_info);
        let get_local_node_info_cb: runar_transporter::transport::GetLocalNodeInfoCallback =
            Arc::new(move || {
                let holder = Arc::clone(&local_node_info_holder);
                Box::pin(async move {
                    let guard = holder.lock().map_err(|e| {
                        anyhow::anyhow!("Failed to acquire local_node_info lock: {e}")
                    })?;
                    match guard.as_ref() {
                        Some(info) => Ok(info.clone()),
                        None => Err(anyhow::anyhow!("Local NodeInfo not set")),
                    }
                })
            });

        // Wire up callbacks and create transport (FFI lines 4003-4006, 3925-3948)
        transport_options = transport_options
            .with_key_manager(Arc::clone(manager))
            .with_root_certificates(vec![ca_cert.clone()])
            .with_local_node_public_key(node_public_key)
            .with_logger(Arc::clone(&keys_inner.logger))
            .with_request_callback(request_callback)
            .with_event_callback(event_callback)
            .with_peer_connected_callback(peer_connected_callback)
            .with_peer_disconnected_callback(peer_disconnected_callback)
            .with_get_local_node_info(get_local_node_info_cb);

        let transport = Arc::new(
            QuicTransport::new(transport_options)
                .map_err(|e| Error::from_reason(format!("Failed to create transport: {e}")))?,
        );

        let state = Arc::new(TransportState {
            transport,
            events_tx,
            events_rx: Arc::new(tokio::sync::Mutex::new(events_rx)),
            pending_requests,
            running: Arc::new(tokio::sync::Mutex::new(false)),
        });

        Ok(Self { state })
    }

    /// Start the transport
    #[napi]
    pub async fn start(&self) -> Result<()> {
        NetworkTransport::start(Arc::clone(&self.state.transport))
            .await
            .map_err(|e| Error::from_reason(format!("Failed to start transport: {e}")))?;

        let mut running = self.state.running.lock().await;
        *running = true;

        Ok(())
    }

    /// Stop the transport
    #[napi]
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.state.running.lock().await;
        *running = false;
        drop(running);

        self.state
            .transport
            .stop()
            .await
            .map_err(|e| Error::from_reason(format!("Failed to stop transport: {e}")))?;

        // Drain pending requests
        let mut pending = self.state.pending_requests.lock().await;
        for (_request_id, sender) in pending.drain() {
            let _ = sender.send(runar_transporter::transport::NetworkMessage {
                source_node_id: String::new(),
                destination_node_id: String::new(),
                message_type: 5,
                payload: runar_transporter::transport::NetworkMessagePayloadItem {
                    path: String::new(),
                    payload_bytes: Vec::new(),
                    correlation_id: String::new(),
                    network_public_key: None,
                    profile_public_keys: Vec::new(),
                },
            });
        }

        Ok(())
    }

    /// Poll for events (internal - called by TypeScript wrapper)
    /// Returns CBOR-encoded event or null
    #[napi]
    pub async fn poll_event(&self) -> Result<Option<Buffer>> {
        let mut rx = self.state.events_rx.lock().await;

        match rx.try_recv() {
            Ok(buf) => Ok(Some(buf.into())),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(_) => Err(Error::from_reason("Event channel closed")),
        }
    }

    /// Complete a pending request (internal - called by TypeScript wrapper)
    #[napi]
    pub async fn complete_request(
        &self,
        request_id: String,
        payload: Buffer,
        profile_public_keys: Vec<Buffer>,
    ) -> Result<()> {
        let mut pending = self.state.pending_requests.lock().await;

        if let Some(sender) = pending.remove(&request_id) {
            let response = runar_transporter::transport::NetworkMessage {
                source_node_id: String::new(),
                destination_node_id: String::new(),
                message_type: 5,
                payload: runar_transporter::transport::NetworkMessagePayloadItem {
                    path: String::new(),
                    payload_bytes: payload.to_vec(),
                    correlation_id: String::new(),
                    network_public_key: None,
                    profile_public_keys: profile_public_keys
                        .into_iter()
                        .map(|b| b.to_vec())
                        .collect(),
                },
            };

            let _ = sender.send(response);
        }

        Ok(())
    }

    /// Send a request and wait for response
    #[napi]
    pub async fn request(
        &self,
        path: String,
        correlation_id: String,
        payload: Buffer,
        dest_peer_id: String,
        network_public_key: Option<Buffer>,
        profile_public_keys: Vec<Buffer>,
    ) -> Result<Buffer> {
        let response = self
            .state
            .transport
            .request(
                &path,
                &correlation_id,
                payload.to_vec(),
                &dest_peer_id,
                network_public_key.map(|b| b.to_vec()),
                profile_public_keys
                    .into_iter()
                    .map(|k| k.to_vec())
                    .collect(),
            )
            .await
            .map_err(|e| Error::from_reason(format!("Request failed: {e}")))?;

        Ok(response.into())
    }

    /// Publish an event
    #[napi]
    pub async fn publish(
        &self,
        path: String,
        correlation_id: String,
        payload: Buffer,
        dest_peer_id: String,
        network_public_key: Option<Buffer>,
    ) -> Result<()> {
        self.state
            .transport
            .publish(
                &path,
                &correlation_id,
                payload.to_vec(),
                &dest_peer_id,
                network_public_key.map(|b| b.to_vec()),
            )
            .await
            .map_err(|e| Error::from_reason(format!("Publish failed: {e}")))?;

        Ok(())
    }

    /// Connect to a peer
    #[napi]
    pub async fn connect_peer(&self, peer_info_cbor: Buffer) -> Result<()> {
        let peer_info: runar_transporter::discovery::PeerInfo =
            serde_cbor::from_slice(&peer_info_cbor)
                .map_err(|e| Error::from_reason(format!("Invalid peer info: {e}")))?;

        NetworkTransport::connect_peer(Arc::clone(&self.state.transport), peer_info)
            .await
            .map_err(|e| Error::from_reason(format!("Failed to connect peer: {e}")))?;

        Ok(())
    }

    /// Check if connected to a peer
    #[napi]
    pub async fn is_connected(&self, peer_id: String) -> Result<bool> {
        Ok(self.state.transport.is_connected(&peer_id).await)
    }

    /// Get local address
    #[napi]
    pub fn get_local_addr(&self) -> Result<String> {
        Ok(self.state.transport.get_local_address())
    }

    /// Update local node info - stores locally and notifies peers
    #[napi]
    pub async fn update_local_node_info(&self, node_info_cbor: Buffer) -> Result<()> {
        let node_info: runar_schemas::NodeInfo = serde_cbor::from_slice(&node_info_cbor)
            .map_err(|e| Error::from_reason(format!("Invalid node info: {e}")))?;

        self.state
            .transport
            .update_peers(node_info)
            .await
            .map_err(|e| Error::from_reason(format!("Failed to update peers: {e}")))?;

        Ok(())
    }
}

#[napi]
pub struct Discovery {
    state: Arc<DiscoveryState>,
}

struct DiscoveryState {
    discovery: Arc<runar_transporter::discovery::MulticastDiscovery>,
    #[allow(dead_code)] // Used by listener callback stored during subscribe
    discovered_tx: mpsc::UnboundedSender<Vec<u8>>,
    discovered_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
    #[allow(dead_code)] // Used by listener callback stored during subscribe
    updated_tx: mpsc::UnboundedSender<Vec<u8>>,
    updated_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
    #[allow(dead_code)] // Used by listener callback stored during subscribe
    lost_tx: mpsc::UnboundedSender<String>,
    lost_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<String>>>,
}

fn parse_discovery_options(cbor_bytes: &[u8]) -> DiscoveryOptions {
    let mut opts = DiscoveryOptions::default();
    if let Ok(serde_cbor::Value::Map(m)) = cbor::from_slice::<serde_cbor::Value>(cbor_bytes) {
        for (k, v) in m {
            if let serde_cbor::Value::Text(s) = k {
                match s.as_str() {
                    "announce_interval_ms" => {
                        if let serde_cbor::Value::Integer(ms) = v {
                            if ms > 0 {
                                opts.announce_interval = std::time::Duration::from_millis(ms as u64)
                            }
                        }
                    }
                    "discovery_timeout_ms" => {
                        if let serde_cbor::Value::Integer(ms) = v {
                            if ms > 0 {
                                opts.discovery_timeout = std::time::Duration::from_millis(ms as u64)
                            }
                        }
                    }
                    "debounce_window_ms" => {
                        if let serde_cbor::Value::Integer(ms) = v {
                            if ms > 0 {
                                opts.debounce_window = std::time::Duration::from_millis(ms as u64)
                            }
                        }
                    }
                    "use_multicast" => {
                        if let serde_cbor::Value::Bool(b) = v {
                            opts.use_multicast = b
                        }
                    }
                    "local_network_only" => {
                        if let serde_cbor::Value::Bool(b) = v {
                            opts.local_network_only = b
                        }
                    }
                    "multicast_group" => {
                        if let serde_cbor::Value::Text(addr) = v {
                            opts.multicast_group = addr
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    opts
}

#[napi]
impl Discovery {
    #[napi(constructor)]
    pub fn new(keys: &Keys, options_cbor: Uint8Array) -> Result<Self> {
        let inner = keys
            .inner
            .lock()
            .map_err(|_| Error::from_reason("Failed to acquire keys lock"))?;
        let node_pk = if let Some(n) = inner.node_key_manager.as_ref() {
            n.read()
                .map_err(|_| Error::from_reason("Failed to acquire node manager lock"))?
                .get_node_public_key()
        } else {
            return Err(Error::from_reason("Node not init"));
        };

        let node_pk = node_pk.ok_or_else(|| Error::from_reason("Node public key not available"))?;
        let mut addrs: Vec<String> = Vec::new();
        if let Ok(serde_cbor::Value::Map(map)) =
            cbor::from_slice::<serde_cbor::Value>(options_cbor.as_ref())
        {
            if let Some(serde_cbor::Value::Array(arr)) =
                map.get(&serde_cbor::Value::Text("local_addresses".into()))
            {
                for it in arr {
                    if let serde_cbor::Value::Text(a) = it {
                        addrs.push(a.to_string())
                    }
                }
            }
        }
        let local_peer =
            runar_transporter::discovery::multicast_discovery::PeerInfo::new(node_pk, addrs);
        let logger = inner.logger.clone();
        let opts = parse_discovery_options(&options_cbor);
        let disc = RT
            .block_on(runar_transporter::discovery::MulticastDiscovery::new(
                local_peer,
                opts,
                Arc::clone(&logger),
            ))
            .map_err(|e| Error::from_reason(e.to_string()))?;

        // Create channels for polling (exactly like FFI pattern)
        let (discovered_tx, discovered_rx) = mpsc::unbounded_channel();
        let (updated_tx, updated_rx) = mpsc::unbounded_channel();
        let (lost_tx, lost_rx) = mpsc::unbounded_channel();

        // Create discovery listener to feed events into channels
        let disc_tx = discovered_tx.clone();
        let upd_tx = updated_tx.clone();
        let lst_tx = lost_tx.clone();

        let discovery = Arc::new(disc);
        let listener_discovery = Arc::clone(&discovery);

        // Subscribe listener asynchronously
        RT.spawn(async move {
            let listener: runar_transporter::discovery::DiscoveryListener =
                Arc::new(move |ev: runar_transporter::discovery::DiscoveryEvent| {
                    let disc_tx = disc_tx.clone();
                    let upd_tx = upd_tx.clone();
                    let lst_tx = lst_tx.clone();
                    Box::pin(async move {
                        match ev {
                            runar_transporter::discovery::DiscoveryEvent::Discovered(peer) => {
                                if let Ok(cbor_bytes) = serde_cbor::to_vec(&peer) {
                                    let _ = disc_tx.send(cbor_bytes);
                                }
                            }
                            runar_transporter::discovery::DiscoveryEvent::Updated(peer) => {
                                if let Ok(cbor_bytes) = serde_cbor::to_vec(&peer) {
                                    let _ = upd_tx.send(cbor_bytes);
                                }
                            }
                            runar_transporter::discovery::DiscoveryEvent::Lost(peer_id) => {
                                let _ = lst_tx.send(peer_id);
                            }
                        }
                    })
                });
            let _ = listener_discovery.subscribe(listener).await;
        });

        let state = Arc::new(DiscoveryState {
            discovery,
            discovered_tx,
            discovered_rx: Arc::new(tokio::sync::Mutex::new(discovered_rx)),
            updated_tx,
            updated_rx: Arc::new(tokio::sync::Mutex::new(updated_rx)),
            lost_tx,
            lost_rx: Arc::new(tokio::sync::Mutex::new(lost_rx)),
        });

        Ok(Discovery { state })
    }

    /// Initialize the discovery mechanism
    #[napi]
    pub async fn init(&self, options_cbor: Uint8Array) -> Result<()> {
        let opts = parse_discovery_options(options_cbor.as_ref());
        self.state
            .discovery
            .init(opts)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Start announcing this node's presence
    #[napi]
    pub async fn start_announcing(&self) -> Result<()> {
        self.state
            .discovery
            .start_announcing()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Stop announcing this node's presence
    #[napi]
    pub async fn stop_announcing(&self) -> Result<()> {
        self.state
            .discovery
            .stop_announcing()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Shutdown the discovery mechanism
    #[napi]
    pub async fn shutdown(&self) -> Result<()> {
        self.state
            .discovery
            .shutdown()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Update local peer information
    #[napi]
    pub async fn update_local_peer_info(&self, peer_info_cbor: Uint8Array) -> Result<()> {
        let peer: runar_transporter::discovery::multicast_discovery::PeerInfo =
            cbor::from_slice(peer_info_cbor.as_ref())
                .map_err(|e| Error::from_reason(e.to_string()))?;
        self.state
            .discovery
            .update_local_peer_info(peer)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Poll for discovered peers (internal - called by TypeScript wrapper)
    /// Returns CBOR-encoded PeerInfo or null
    #[napi]
    pub async fn poll_discovered(&self) -> Result<Option<Buffer>> {
        let mut rx = self.state.discovered_rx.lock().await;

        match rx.try_recv() {
            Ok(buf) => Ok(Some(buf.into())),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(_) => Err(Error::from_reason("Discovered channel closed")),
        }
    }

    /// Poll for updated peers (internal - called by TypeScript wrapper)
    /// Returns CBOR-encoded PeerInfo or null
    #[napi]
    pub async fn poll_updated(&self) -> Result<Option<Buffer>> {
        let mut rx = self.state.updated_rx.lock().await;

        match rx.try_recv() {
            Ok(buf) => Ok(Some(buf.into())),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(_) => Err(Error::from_reason("Updated channel closed")),
        }
    }

    /// Poll for lost peers (internal - called by TypeScript wrapper)
    /// Returns peer ID string or null
    #[napi]
    pub async fn poll_lost(&self) -> Result<Option<String>> {
        let mut rx = self.state.lost_rx.lock().await;

        match rx.try_recv() {
            Ok(peer_id) => Ok(Some(peer_id)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(_) => Err(Error::from_reason("Lost channel closed")),
        }
    }

    /// Bind discovery events to transport (auto-connect discovered peers)
    #[napi]
    pub async fn bind_events_to_transport(&self, transport: &Transport) -> Result<()> {
        let t = Arc::clone(&transport.state.transport);
        let listener: runar_transporter::discovery::DiscoveryListener =
            Arc::new(move |ev: runar_transporter::discovery::DiscoveryEvent| {
                let t = t.clone();
                Box::pin(async move {
                    match ev {
                        runar_transporter::discovery::DiscoveryEvent::Discovered(peer)
                        | runar_transporter::discovery::DiscoveryEvent::Updated(peer) => {
                            let _ = NetworkTransport::connect_peer(t.clone(), peer).await;
                        }
                        runar_transporter::discovery::DiscoveryEvent::Lost(_id) => {
                            // Optional: disconnect
                        }
                    }
                })
            });
        self.state
            .discovery
            .subscribe(listener)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }
}

// CA Server Operations APIs
#[napi]
pub struct CaServer {
    inner: Arc<AsyncMutex<TransporterCaServer>>,
    bootstrap_addr: Arc<Mutex<Option<String>>>,
    authenticated_addr: Arc<Mutex<Option<String>>>,
}

// CA Client Operations APIs
#[napi]
pub struct CaClient {
    inner: Arc<AsyncMutex<TransporterCaClient>>,
}

// Certificate Authority Creation APIs
#[napi]
pub struct CaCreator;

#[napi]
pub struct Ca {
    inner: Arc<Mutex<runar_keys::CertificateAuthority>>,
}

// Enrollment Token Management APIs
#[napi]
pub struct EnrollmentToken;

#[napi]
impl CaServer {
    #[napi(constructor)]
    pub fn new(config_cbor: Uint8Array, shared_ca_node: &CaNodeShared) -> Result<Self> {
        // Parse configuration
        let nodejs_config: NodejsCaServerConfig = cbor::from_slice(&config_cbor)
            .map_err(|e| Error::from_reason(format!("Failed to parse server config: {e}")))?;

        // Convert to transporter config
        let config = CaServerConfig {
            bootstrap_bind: nodejs_config
                .bootstrap_bind
                .parse()
                .map_err(|e| Error::from_reason(format!("Invalid bootstrap_bind: {e}")))?,
            authenticated_bind: nodejs_config
                .authenticated_bind
                .parse()
                .map_err(|e| Error::from_reason(format!("Invalid authenticated_bind: {e}")))?,
            network_id: nodejs_config.network_id,
            rate_limit_config: runar_transporter::RateLimitConfig {
                burst_limit: nodejs_config.rate_limit_per_minute,
                sustained_limit: nodejs_config.rate_limit_per_hour,
                burst_window: std::time::Duration::from_secs(60),
                sustained_window: std::time::Duration::from_secs(3600),
            },
            admin_skis: nodejs_config.admin_skis,
            additional_ca_certs: vec![],
        };

        // Create logger
        let logger = Arc::new(Logger::new_root(Component::Custom("NodejsApi")));

        // Use the shared CA Node (following FFI pattern)
        // Now both use the same RwLock type, so we can share directly
        let ca_server = TransporterCaServer::new(config, shared_ca_node.inner.clone(), logger);

        Ok(Self {
            inner: Arc::new(AsyncMutex::new(ca_server)),
            bootstrap_addr: Arc::new(Mutex::new(None)),
            authenticated_addr: Arc::new(Mutex::new(None)),
        })
    }

    #[napi]
    pub async fn start(&self) -> Result<()> {
        // Initialize RustLS crypto provider before starting CA server
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let ca_server = self.inner.clone();
        let bootstrap_addr = self.bootstrap_addr.clone();
        let authenticated_addr = self.authenticated_addr.clone();

        let result = RT
            .spawn(async move {
                let mut ca_server = ca_server.lock().await;
                let (bootstrap, authenticated) = ca_server
                    .start()
                    .await
                    .map_err(|e| Error::from_reason(format!("Failed to start CA Server: {e}")))?;

                // Store addresses
                {
                    let mut bootstrap_addr = bootstrap_addr.lock().unwrap();
                    *bootstrap_addr = Some(bootstrap.to_string());
                }
                {
                    let mut authenticated_addr = authenticated_addr.lock().unwrap();
                    *authenticated_addr = Some(authenticated.to_string());
                }

                Ok(())
            })
            .await
            .map_err(|e| Error::from_reason(format!("Failed to start CA Server: {e}")))?;

        result
    }

    #[napi]
    pub async fn stop(&self) -> Result<()> {
        let ca_server = self.inner.clone();
        RT.spawn(async move {
            let mut ca_server = ca_server.lock().await;
            ca_server
                .stop()
                .await
                .map_err(|e| Error::from_reason(format!("Failed to stop CA Server: {e}")))
        })
        .await
        .map_err(|e| Error::from_reason(format!("Failed to stop CA Server: {e}")))?
    }

    #[napi]
    pub async fn get_bootstrap_addr(&self) -> Result<String> {
        let bootstrap_addr = self.bootstrap_addr.lock().unwrap();
        bootstrap_addr
            .clone()
            .ok_or_else(|| Error::from_reason("CA Server not started"))
    }

    #[napi]
    pub async fn get_authenticated_addr(&self) -> Result<String> {
        let authenticated_addr = self.authenticated_addr.lock().unwrap();
        authenticated_addr
            .clone()
            .ok_or_else(|| Error::from_reason("CA Server not started"))
    }

    #[napi]
    pub async fn configure_admin_skis(&self, admin_skis_cbor: Uint8Array) -> Result<()> {
        let admin_skis: Vec<String> = cbor::from_slice(&admin_skis_cbor)
            .map_err(|e| Error::from_reason(format!("Failed to parse admin SKIs: {e}")))?;

        let ca_server = self.inner.clone();
        RT.spawn(async move {
            let mut ca_server = ca_server.lock().await;
            ca_server.configure_admin_skis(admin_skis);
            Ok(())
        })
        .await
        .map_err(|e| Error::from_reason(format!("Failed to configure admin SKIs: {e}")))?
    }

    #[napi]
    pub fn free(&self) {
        // NAPI-RS handles memory cleanup automatically
    }
}

// CA Client Operations APIs
#[napi]
impl CaClient {
    #[napi(constructor)]
    pub fn new(config_cbor: Uint8Array, node_keys: &Keys) -> Result<Self> {
        // Parse configuration
        let nodejs_config: NodejsCaClientConfig = cbor::from_slice(&config_cbor)
            .map_err(|e| Error::from_reason(format!("Failed to parse client config: {e}")))?;

        // Convert to transporter config
        let config = CaClientConfig {
            bootstrap_server: nodejs_config
                .bootstrap_server
                .parse()
                .map_err(|e| Error::from_reason(format!("Invalid bootstrap_server: {e}")))?,
            authenticated_server: nodejs_config
                .authenticated_server
                .parse()
                .map_err(|e| Error::from_reason(format!("Invalid authenticated_server: {e}")))?,
            network_id: nodejs_config.network_id,
            request_timeout: std::time::Duration::from_secs(
                nodejs_config.request_timeout_seconds as u64,
            ),
            max_retries: nodejs_config.max_retries,
        };

        // Create logger
        let logger = Logger::new_root(Component::Custom("NodejsApi"));

        // Get node key manager from Keys
        let node_key_manager = {
            let keys_inner = node_keys.inner.lock().unwrap();
            keys_inner.node_key_manager.clone().unwrap()
        };

        // Create CA Client
        let ca_client = TransporterCaClient::new(config, Arc::new(logger))
            .with_node_key_manager(node_key_manager)
            .with_root_ca_cert(nodejs_config.root_ca_der)
            .with_issuing_ca_cert(nodejs_config.issuing_ca_der);

        Ok(Self {
            inner: Arc::new(AsyncMutex::new(ca_client)),
        })
    }

    #[napi]
    pub async fn enroll(
        &self,
        _bootstrap_addr: String,
        request_cbor: Uint8Array,
    ) -> Result<Uint8Array> {
        // Initialize RustLS crypto provider before CA client operations
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let request: CsrEnrollRequest = cbor::from_slice(&request_cbor)
            .map_err(|e| Error::from_reason(format!("Failed to parse enroll request: {e}")))?;

        let ca_client = self.inner.clone();
        let result = RT
            .spawn(async move {
                let ca_client = ca_client.lock().await;
                ca_client
                    .enroll(request)
                    .await
                    .map_err(|e| Error::from_reason(format!("Failed to enroll: {e}")))
            })
            .await
            .map_err(|e| Error::from_reason(format!("Failed to enroll: {e}")))?;

        let response = result?;
        let response_cbor = cbor::to_vec(&response)
            .map_err(|e| Error::from_reason(format!("Failed to serialize response: {e}")))?;

        Ok(response_cbor.into())
    }

    #[napi]
    pub async fn renew(
        &self,
        _authenticated_addr: String,
        request_cbor: Uint8Array,
    ) -> Result<Uint8Array> {
        let request: RenewRequest = cbor::from_slice(&request_cbor)
            .map_err(|e| Error::from_reason(format!("Failed to parse renew request: {e}")))?;

        let ca_client = self.inner.clone();
        let result = RT
            .spawn(async move {
                let ca_client = ca_client.lock().await;
                ca_client
                    .renew(request)
                    .await
                    .map_err(|e| Error::from_reason(format!("Failed to renew: {e}")))
            })
            .await
            .map_err(|e| Error::from_reason(format!("Failed to renew: {e}")))?;

        let response = result?;
        let response_cbor = cbor::to_vec(&response)
            .map_err(|e| Error::from_reason(format!("Failed to serialize response: {e}")))?;

        Ok(response_cbor.into())
    }

    #[napi]
    pub async fn revoke(
        &self,
        _authenticated_addr: String,
        request_cbor: Uint8Array,
    ) -> Result<Uint8Array> {
        let request: RevokeRequest = cbor::from_slice(&request_cbor)
            .map_err(|e| Error::from_reason(format!("Failed to parse revoke request: {e}")))?;

        let ca_client = self.inner.clone();
        let result = RT
            .spawn(async move {
                let ca_client = ca_client.lock().await;
                ca_client
                    .revoke(request)
                    .await
                    .map_err(|e| Error::from_reason(format!("Failed to revoke: {e}")))
            })
            .await
            .map_err(|e| Error::from_reason(format!("Failed to revoke: {e}")))?;

        let response = result?;
        let response_cbor = cbor::to_vec(&response)
            .map_err(|e| Error::from_reason(format!("Failed to serialize response: {e}")))?;

        Ok(response_cbor.into())
    }

    #[napi]
    pub async fn get_chain(
        &self,
        _bootstrap_addr: String,
        _network_id: String,
    ) -> Result<Uint8Array> {
        let ca_client = self.inner.clone();
        let result = RT
            .spawn(async move {
                let ca_client = ca_client.lock().await;
                ca_client
                    .fetch_chain()
                    .await
                    .map_err(|e| Error::from_reason(format!("Failed to get chain: {e}")))
            })
            .await
            .map_err(|e| Error::from_reason(format!("Failed to get chain: {e}")))?;

        let response = result?;
        let response_cbor = cbor::to_vec(&response)
            .map_err(|e| Error::from_reason(format!("Failed to serialize response: {e}")))?;

        Ok(response_cbor.into())
    }

    #[napi]
    pub async fn get_status(
        &self,
        _authenticated_addr: String,
        _network_id: String,
    ) -> Result<Uint8Array> {
        let ca_client = self.inner.clone();
        let result = RT
            .spawn(async move {
                let ca_client = ca_client.lock().await;
                ca_client
                    .get_status()
                    .await
                    .map_err(|e| Error::from_reason(format!("Failed to get status: {e}")))
            })
            .await
            .map_err(|e| Error::from_reason(format!("Failed to get status: {e}")))?;

        let response = result?;
        let response_cbor = cbor::to_vec(&response)
            .map_err(|e| Error::from_reason(format!("Failed to serialize response: {e}")))?;

        Ok(response_cbor.into())
    }

    #[napi]
    pub async fn get_crl(
        &self,
        _authenticated_addr: String,
        _network_id: String,
    ) -> Result<Uint8Array> {
        let ca_client = self.inner.clone();
        let result = RT
            .spawn(async move {
                let ca_client = ca_client.lock().await;
                ca_client
                    .fetch_crl()
                    .await
                    .map_err(|e| Error::from_reason(format!("Failed to get CRL: {e}")))
            })
            .await
            .map_err(|e| Error::from_reason(format!("Failed to get CRL: {e}")))?;

        let response = result?;
        let response_cbor = cbor::to_vec(&response)
            .map_err(|e| Error::from_reason(format!("Failed to serialize response: {e}")))?;

        Ok(response_cbor.into())
    }

    #[napi]
    pub fn free(&self) {
        // NAPI-RS handles memory cleanup automatically
    }
}

// Certificate Authority Creation APIs
#[napi]
impl CaCreator {
    #[napi]
    pub fn create_root_ca(subject: String) -> Result<Ca> {
        let ca =
            runar_keys::CertificateAuthority::new(&subject).map_err(to_napi_error_with_code)?;

        Ok(Ca {
            inner: Arc::new(Mutex::new(ca)),
        })
    }

    #[napi]
    pub fn create_issuing_ca(
        root_ca: &Ca,
        subject: String,
        validity_days: u32,
        serial: i64,
    ) -> Result<Ca> {
        use runar_keys::certificate::{CertificateAuthority, CertificateRequest, EcdsaKeyPair};

        // Validate parameters
        if validity_days == 0 {
            return Err(Error::from_reason("validity_days cannot be zero"));
        }
        if serial == 0 {
            return Err(Error::from_reason("serial cannot be zero"));
        }

        // Create issuing CA key pair
        let issuing_ca_key = EcdsaKeyPair::new()
            .map_err(|e| Error::from_reason(format!("Failed to create issuing CA key: {e}")))?;

        // Create CSR for issuing CA
        let issuing_ca_csr_der = CertificateRequest::create(&issuing_ca_key, &subject)
            .map_err(|e| Error::from_reason(format!("Failed to create issuing CA CSR: {e}")))?;

        // Get the root CA and sign the issuing CA certificate
        let root_ca_inner = root_ca.inner.lock().unwrap();
        let issuing_ca_cert = root_ca_inner
            .sign_ca_certificate_request_with_serial(
                &issuing_ca_csr_der,
                validity_days,
                Some(serial as u64),
            )
            .map_err(|e| {
                Error::from_reason(format!("Failed to sign issuing CA certificate: {e}"))
            })?;

        // Create issuing CA from existing key pair and certificate
        let issuing_ca = CertificateAuthority::from_existing(issuing_ca_key, issuing_ca_cert);

        Ok(Ca {
            inner: Arc::new(Mutex::new(issuing_ca)),
        })
    }

    #[napi]
    pub fn create_ea_key() -> Result<Uint8Array> {
        let ea_key = runar_keys::certificate::EcdsaKeyPair::new()
            .map_err(|e| Error::from_reason(format!("Failed to create EA key: {e}")))?;

        let private_key_der = ea_key
            .private_key_der()
            .map_err(|e| Error::from_reason(format!("Failed to get EA key DER: {e}")))?;

        Ok(Uint8Array::from(private_key_der))
    }

    #[napi]
    pub fn get_ea_public_key(ea_private_key_der: Uint8Array) -> Result<Uint8Array> {
        let ea_key =
            runar_keys::certificate::EcdsaKeyPair::from_pkcs8_der(&ea_private_key_der.to_vec())
                .map_err(|e| {
                    Error::from_reason(format!("Failed to create EA key from DER: {e}"))
                })?;

        // Return raw public key bytes (not DER-encoded) to match FFI behavior
        let public_key_bytes = ea_key.public_key().as_bytes().to_vec();

        Ok(Uint8Array::from(public_key_bytes))
    }
}

#[napi]
impl Ca {
    #[napi]
    pub fn get_certificate(&self) -> Result<Uint8Array> {
        let ca = self.inner.lock().unwrap();
        let cert = ca.ca_certificate();
        Ok(Uint8Array::new(cert.der_bytes().to_vec()))
    }

    #[napi]
    pub fn get_public_key(&self) -> Result<Uint8Array> {
        let ca = self.inner.lock().unwrap();
        let public_key = ca.ca_public_key();
        // Convert VerifyingKey to bytes
        let public_key_bytes = public_key.to_encoded_point(false).as_bytes().to_vec();
        Ok(Uint8Array::new(public_key_bytes))
    }

    #[napi]
    pub fn get_ski(&self) -> Result<String> {
        let ca = self.inner.lock().unwrap();
        let cert = ca.ca_certificate();
        let ski = CertificateValidator::extract_ski(cert).map_err(to_napi_error_with_code)?;
        Ok(hex::encode(ski))
    }

    #[napi]
    pub fn get_subject(&self) -> Result<String> {
        let ca = self.inner.lock().unwrap();
        let cert = ca.ca_certificate();
        Ok(cert.subject().to_string())
    }

    #[napi]
    pub fn get_issuer(&self) -> Result<String> {
        let ca = self.inner.lock().unwrap();
        let cert = ca.ca_certificate();
        Ok(cert.issuer().to_string())
    }

    #[napi]
    pub fn get_serial_number(&self) -> Result<String> {
        let ca = self.inner.lock().unwrap();
        let cert = ca.ca_certificate();
        let parsed = cert
            .parsed()
            .map_err(|e| Error::from_reason(format!("Failed to parse certificate: {e}")))?;
        let serial = parsed.tbs_certificate.serial.to_string();
        Ok(serial)
    }

    #[napi]
    pub fn get_validity_period(&self) -> Result<(i64, i64)> {
        let ca = self.inner.lock().unwrap();
        let cert = ca.ca_certificate();
        let parsed = cert
            .parsed()
            .map_err(|e| Error::from_reason(format!("Failed to parse certificate: {e}")))?;
        let validity = parsed.validity();
        let not_before = validity.not_before.to_datetime().unix_timestamp();
        let not_after = validity.not_after.to_datetime().unix_timestamp();
        Ok((not_before, not_after))
    }

    #[napi]
    pub fn is_ca(&self) -> Result<bool> {
        let ca = self.inner.lock().unwrap();
        let cert = ca.ca_certificate();
        let parsed = cert
            .parsed()
            .map_err(|e| Error::from_reason(format!("Failed to parse certificate: {e}")))?;
        // Check if the certificate has the CA basic constraint
        let is_ca = parsed
            .tbs_certificate
            .basic_constraints()
            .is_ok_and(|bc| bc.unwrap().value.ca);
        Ok(is_ca)
    }

    #[napi]
    pub fn get_key_usage(&self) -> Result<Vec<String>> {
        let ca = self.inner.lock().unwrap();
        let cert = ca.ca_certificate();
        let parsed = cert
            .parsed()
            .map_err(|e| Error::from_reason(format!("Failed to parse certificate: {e}")))?;

        let mut key_usage = Vec::new();
        if let Ok(Some(ku)) = parsed.tbs_certificate.key_usage() {
            if ku.value.digital_signature() {
                key_usage.push("Digital Signature".to_string());
            }
            if ku.value.non_repudiation() {
                key_usage.push("Non Repudiation".to_string());
            }
            if ku.value.key_encipherment() {
                key_usage.push("Key Encipherment".to_string());
            }
            if ku.value.data_encipherment() {
                key_usage.push("Data Encipherment".to_string());
            }
            if ku.value.key_agreement() {
                key_usage.push("Key Agreement".to_string());
            }
            if ku.value.key_cert_sign() {
                key_usage.push("Key Cert Sign".to_string());
            }
            if ku.value.crl_sign() {
                key_usage.push("CRL Sign".to_string());
            }
            if ku.value.encipher_only() {
                key_usage.push("Encipher Only".to_string());
            }
            if ku.value.decipher_only() {
                key_usage.push("Decipher Only".to_string());
            }
        }
        Ok(key_usage)
    }

    #[napi]
    pub fn get_extended_key_usage(&self) -> Result<Vec<String>> {
        let ca = self.inner.lock().unwrap();
        let cert = ca.ca_certificate();
        let parsed = cert
            .parsed()
            .map_err(|e| Error::from_reason(format!("Failed to parse certificate: {e}")))?;

        let mut extended_key_usage = Vec::new();
        if let Ok(Some(eku)) = parsed.tbs_certificate.extended_key_usage() {
            for oid in &eku.value.other {
                extended_key_usage.push(oid.to_string());
            }
        }
        Ok(extended_key_usage)
    }

    #[napi]
    pub fn verify(&self, issuer_cert: &Ca) -> Result<bool> {
        let ca = self.inner.lock().unwrap();
        let cert = ca.ca_certificate();
        let issuer_ca = issuer_cert.inner.lock().unwrap();
        let issuer_public_key = issuer_ca.ca_public_key();

        match cert.validate(issuer_public_key) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    #[napi]
    pub fn free(&self) {
        // NAPI-RS handles memory cleanup automatically
    }
}

// Enrollment Token Management APIs
#[napi]
impl EnrollmentToken {
    #[napi]
    pub fn generate(
        ea_key_der: Uint8Array,
        network_id: String,
        subject_hint: Option<String>,
        validity_days: u32,
        permissions: Vec<String>,
    ) -> Result<Uint8Array> {
        // Parse the enrollment authority key
        let ea_key = runar_keys::certificate::EcdsaKeyPair::from_pkcs8_der(&ea_key_der)
            .map_err(to_napi_error_with_code)?;

        // Calculate token validity times
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let not_before = now;
        let expires_at = now + (validity_days as u64 * 24 * 60 * 60);

        // Generate random token ID and nonce
        let mut token_id_bytes = [0u8; 16];
        let mut nonce_bytes = [0u8; 16];
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.fill(&mut token_id_bytes);
        rng.fill(&mut nonce_bytes);

        let token_id = hex::encode(token_id_bytes);
        let nonce = nonce_bytes;

        // Create token body
        let token_body = EnrollmentTokenBody::new(
            token_id,
            network_id,
            subject_hint,
            not_before,
            expires_at,
            nonce,
            permissions,
        );

        // Generate the signed token
        let token =
            KeysEnrollmentToken::generate(&ea_key, token_body).map_err(to_napi_error_with_code)?;

        // Serialize to CBOR
        let token_cbor = serde_cbor::to_vec(&token).map_err(|e| {
            create_napi_error_with_code(
                RN_ERROR_SERIALIZATION_FAILED,
                &format!("Failed to serialize token: {e}"),
            )
        })?;

        Ok(Uint8Array::new(token_cbor))
    }

    #[napi]
    pub fn validate(
        token_cbor: Uint8Array,
        network_id: String,
        ea_public_key: Uint8Array,
    ) -> Result<bool> {
        // Deserialize token
        let token: KeysEnrollmentToken = serde_cbor::from_slice(&token_cbor)
            .map_err(|e| Error::from_reason(format!("Failed to deserialize token: {e}")))?;

        // Verify signature
        match token.verify(&ea_public_key) {
            Ok(()) => {
                // Validate for enrollment
                match token.validate_for_enrollment(&network_id) {
                    Ok(()) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            Err(_) => Ok(false),
        }
    }

    #[napi]
    pub fn get_token_info(token_cbor: Uint8Array) -> Result<Uint8Array> {
        // Deserialize token
        let token: KeysEnrollmentToken = serde_cbor::from_slice(&token_cbor)
            .map_err(|e| Error::from_reason(format!("Failed to deserialize token: {e}")))?;

        // Create token info struct
        let token_info = serde_json::json!({
            "token_id": token.body.token_id,
            "network_id": token.body.network_id,
            "subject_hint": token.body.subject_hint,
            "not_before": token.body.not_before,
            "expires_at": token.body.expires_at,
            "permissions": token.body.permissions,
            "signer_id": token.signer_id,
            "is_valid_now": token.body.is_valid_now(),
        });

        // Serialize to CBOR
        let info_cbor = serde_cbor::to_vec(&token_info)
            .map_err(|e| Error::from_reason(format!("Failed to serialize token info: {e}")))?;

        Ok(Uint8Array::new(info_cbor))
    }
}

// CA Node Management APIs
#[napi]
pub struct CaNode {
    inner: Arc<RwLock<CANode>>,
}

#[napi]
impl CaNode {
    #[napi(constructor)]
    pub fn new() -> Result<Self> {
        let logger = Arc::new(Logger::new_root(Component::Keys));

        // Create a proper CA Node with valid certificates
        // This follows the design pattern from the FFI implementation
        let temp_key = runar_keys::certificate::EcdsaKeyPair::new()
            .map_err(|e| Error::from_reason(format!("Failed to create CA key: {e}")))?;

        // Create temporary certificates using CertificateAuthority
        // These will be replaced by setup_complete with the real certificates
        let temp_ca_authority =
            runar_keys::certificate::CertificateAuthority::new("CN=Temp CA,O=Temp,C=US")
                .map_err(|e| Error::from_reason(format!("Failed to create temporary CA: {e}")))?;

        let temp_cert = temp_ca_authority.ca_certificate().clone();
        let temp_root_cert = temp_ca_authority.ca_certificate().clone();

        let ca_node = CANode::new(
            temp_key,
            temp_cert,
            temp_root_cert,
            "uninitialized".to_string(), // Will be updated by setup_complete
            logger,
        );

        Ok(Self {
            inner: Arc::new(RwLock::new(ca_node)),
        })
    }

    /// Create new shared CA Node (following FFI pattern exactly)
    #[napi]
    pub fn new_shared() -> Result<CaNodeShared> {
        let logger = Arc::new(Logger::new_root(Component::Keys));

        // Create a proper CA Node with valid certificates
        // This follows the design pattern from the FFI implementation
        let temp_key = runar_keys::certificate::EcdsaKeyPair::new()
            .map_err(|e| Error::from_reason(format!("Failed to create CA key: {e}")))?;

        // Create temporary certificates using CertificateAuthority
        // These will be replaced by setup_complete with the real certificates
        let temp_ca_authority =
            runar_keys::certificate::CertificateAuthority::new("CN=Temp CA,O=Temp,C=US")
                .map_err(|e| Error::from_reason(format!("Failed to create temporary CA: {e}")))?;

        let temp_cert = temp_ca_authority.ca_certificate().clone();
        let temp_root_cert = temp_ca_authority.ca_certificate().clone();

        let ca_node = CANode::new(
            temp_key,
            temp_cert,
            temp_root_cert,
            "uninitialized".to_string(), // Will be updated by setup_complete
            logger,
        );

        Ok(CaNodeShared {
            inner: Arc::new(RwLock::new(ca_node)),
        })
    }

    #[napi]
    pub fn install_issuing_ca(&self, ca_cert_der: Uint8Array) -> Result<()> {
        let _ca_cert = runar_keys::certificate::X509Certificate::from_der(ca_cert_der.to_vec())
            .map_err(|e| Error::from_reason(format!("Failed to parse CA cert: {e}")))?;

        let mut ca_node = self.inner.write().unwrap();
        // For now, just add the cert to the admin SKI allowlist as a placeholder
        // The full implementation would require more parameters
        ca_node.add_admin_ski("placeholder".to_string());

        Ok(())
    }

    #[napi]
    pub fn setup_complete(
        &self,
        root_ca_subject: String,
        issuing_ca_subject: String,
        validity_days: u32,
        issuing_ca_serial: i64,
        ea_public_keys: Uint8Array,
        network_id: String,
    ) -> Result<()> {
        // Parse enrollment authority public keys
        let ea_public_keys_vec: Vec<Vec<u8>> = cbor::from_slice(&ea_public_keys)
            .map_err(|e| Error::from_reason(format!("Failed to parse EA public keys: {e}")))?;

        // Create Root CA internally (private key never leaves Rust)
        let root_ca = runar_keys::certificate::CertificateAuthority::new(&root_ca_subject)
            .map_err(|e| Error::from_reason(format!("Failed to create Root CA: {e}")))?;

        // Create Issuing CA key internally (private key never leaves Rust)
        let issuing_key = runar_keys::certificate::EcdsaKeyPair::new()
            .map_err(|e| Error::from_reason(format!("Failed to create Issuing CA key: {e}")))?;

        // Create and sign Issuing CA certificate internally
        let issuing_csr =
            runar_keys::certificate::CertificateRequest::create(&issuing_key, &issuing_ca_subject)
                .map_err(|e| Error::from_reason(format!("Failed to create Issuing CA CSR: {e}")))?;

        let issuing_cert = root_ca
            .sign_ca_certificate_request_with_serial(
                &issuing_csr,
                validity_days,
                Some(issuing_ca_serial as u64),
            )
            .map_err(|e| {
                Error::from_reason(format!("Failed to sign Issuing CA certificate: {e}"))
            })?;

        // Install everything in CA Node (no private keys exposed) - SYNCHRONOUS like FFI
        let mut ca_node = self.inner.write().unwrap();
        ca_node.network_id = network_id.clone();

        ca_node
            .install_issuing_ca(
                issuing_key,
                issuing_cert,
                root_ca.ca_certificate().clone(),
                ea_public_keys_vec,
            )
            .map_err(|e| Error::from_reason(format!("Failed to install Issuing CA: {e}")))?;

        Ok(())
    }

    #[napi]
    pub fn get_root_ca_certificate(&self) -> Result<Uint8Array> {
        let ca_node = self.inner.read().unwrap();
        let cert_bytes = ca_node.root_ca_cert.der_bytes().to_vec();
        Ok(Uint8Array::from(cert_bytes))
    }

    #[napi]
    pub async fn get_issuing_ca_certificate(&self) -> Result<Uint8Array> {
        let ca_node = self.inner.clone();
        let result = RT
            .spawn(async move {
                let ca_node = ca_node.read().unwrap();
                Ok::<Vec<u8>, String>(ca_node.issuing_ca_cert.der_bytes().to_vec())
            })
            .await
            .map_err(|e| {
                Error::from_reason(format!("Failed to get issuing CA certificate: {e}"))
            })?;

        let cert_bytes = result
            .map_err(|e| Error::from_reason(format!("Failed to get certificate bytes: {e}")))?;
        Ok(Uint8Array::from(cert_bytes))
    }

    #[napi]
    pub async fn handle_enroll(&self, request_cbor: Uint8Array) -> Result<Uint8Array> {
        let request: CsrEnrollRequest = cbor::from_slice(&request_cbor)
            .map_err(|e| Error::from_reason(format!("Failed to deserialize request: {e}")))?;

        let ca_node = self.inner.clone();
        let result = RT
            .spawn(async move {
                let mut ca_node = ca_node.write().unwrap();
                ca_node.handle_enroll(request, "127.0.0.1:8080")
            })
            .await
            .map_err(|e| Error::from_reason(format!("Failed to handle enroll: {e}")))?;

        let response =
            result.map_err(|e| Error::from_reason(format!("Failed to handle enroll: {e}")))?;
        let response_cbor = cbor::to_vec(&response)
            .map_err(|e| Error::from_reason(format!("Failed to serialize response: {e}")))?;

        Ok(response_cbor.into())
    }

    #[napi]
    pub async fn handle_renew(&self, request_cbor: Uint8Array) -> Result<Uint8Array> {
        let request: RenewRequest = cbor::from_slice(&request_cbor)
            .map_err(|e| Error::from_reason(format!("Failed to deserialize request: {e}")))?;

        let ca_node = self.inner.clone();
        let result = RT
            .spawn(async move {
                let mut ca_node = ca_node.write().unwrap();
                ca_node.handle_renew(request, &[])
            })
            .await
            .map_err(|e| Error::from_reason(format!("Failed to handle renew: {e}")))?;

        let response =
            result.map_err(|e| Error::from_reason(format!("Failed to handle renew: {e}")))?;
        let response_cbor = cbor::to_vec(&response)
            .map_err(|e| Error::from_reason(format!("Failed to serialize response: {e}")))?;

        Ok(response_cbor.into())
    }

    #[napi]
    pub async fn handle_revoke(&self, request_cbor: Uint8Array) -> Result<Uint8Array> {
        let request: RevokeRequest = cbor::from_slice(&request_cbor)
            .map_err(|e| Error::from_reason(format!("Failed to deserialize request: {e}")))?;

        let ca_node = self.inner.clone();
        let result = RT
            .spawn(async move {
                let mut ca_node = ca_node.write().unwrap();
                ca_node.handle_revoke(request, "admin_ski")
            })
            .await
            .map_err(|e| Error::from_reason(format!("Failed to handle revoke: {e}")))?;

        let response =
            result.map_err(|e| Error::from_reason(format!("Failed to handle revoke: {e}")))?;
        let response_cbor = cbor::to_vec(&response)
            .map_err(|e| Error::from_reason(format!("Failed to serialize response: {e}")))?;

        Ok(response_cbor.into())
    }

    #[napi]
    pub async fn get_chain(&self) -> Result<Uint8Array> {
        let ca_node = self.inner.clone();
        let result = RT
            .spawn(async move {
                let ca_node = ca_node.read().unwrap();
                ca_node.handle_chain("default_network".to_string())
            })
            .await
            .map_err(|e| Error::from_reason(format!("Failed to get chain: {e}")))?;

        let chain = result.map_err(|e| Error::from_reason(format!("Failed to get chain: {e}")))?;
        let chain_cbor = cbor::to_vec(&chain)
            .map_err(|e| Error::from_reason(format!("Failed to serialize chain: {e}")))?;

        Ok(chain_cbor.into())
    }

    #[napi]
    pub async fn get_status(&self) -> Result<Uint8Array> {
        let ca_node = self.inner.clone();
        let result = RT
            .spawn(async move {
                let ca_node = ca_node.read().unwrap();
                ca_node.handle_status("default_network".to_string())
            })
            .await
            .map_err(|e| Error::from_reason(format!("Failed to get status: {e}")))?;

        let status =
            result.map_err(|e| Error::from_reason(format!("Failed to get status: {e}")))?;
        let status_cbor = cbor::to_vec(&status)
            .map_err(|e| Error::from_reason(format!("Failed to serialize status: {e}")))?;

        Ok(status_cbor.into())
    }

    #[napi]
    pub async fn get_crl(&self) -> Result<Uint8Array> {
        let ca_node = self.inner.clone();
        let result = RT
            .spawn(async move {
                let ca_node = ca_node.read().unwrap();
                ca_node.handle_crl("default_network".to_string())
            })
            .await
            .map_err(|e| Error::from_reason(format!("Failed to get CRL: {e}")))?;

        let crl = result.map_err(|e| Error::from_reason(format!("Failed to get CRL: {e}")))?;
        let crl_cbor = cbor::to_vec(&crl)
            .map_err(|e| Error::from_reason(format!("Failed to serialize CRL: {e}")))?;

        Ok(crl_cbor.into())
    }

    #[napi]
    pub async fn add_admin_ski(&self, admin_ski: String) -> Result<()> {
        let ca_node = self.inner.clone();
        RT.spawn(async move {
            let mut ca_node = ca_node.write().unwrap();
            ca_node.add_admin_ski(admin_ski);
        })
        .await
        .map_err(|e| Error::from_reason(format!("Failed to add admin SKI: {e}")))?;

        Ok(())
    }

    #[napi]
    pub async fn revoke_token(&self, token: String) -> Result<()> {
        let ca_node = self.inner.clone();
        RT.spawn(async move {
            let mut ca_node = ca_node.write().unwrap();
            let _ = ca_node.revoke_token(token);
        })
        .await
        .map_err(|e| Error::from_reason(format!("Failed to revoke token: {e}")))?;

        Ok(())
    }

    #[napi]
    pub async fn generate_crl(&self) -> Result<Uint8Array> {
        let ca_node = self.inner.clone();
        let result = RT
            .spawn(async move {
                let ca_node = ca_node.read().unwrap();
                ca_node.generate_crl_lite()
            })
            .await
            .map_err(|e| Error::from_reason(format!("Failed to generate CRL: {e}")))?;

        let crl = result.map_err(|e| Error::from_reason(format!("Failed to generate CRL: {e}")))?;
        let crl_cbor = cbor::to_vec(&crl)
            .map_err(|e| Error::from_reason(format!("Failed to serialize CRL: {e}")))?;

        Ok(crl_cbor.into())
    }

    #[napi]
    pub fn create_shared(&self) -> Result<CaNodeShared> {
        Ok(CaNodeShared {
            inner: self.inner.clone(),
        })
    }

    /// Free CA Node resources (following FFI pattern)
    #[napi]
    pub fn free(&self) {
        // NAPI-RS handles memory cleanup automatically
        // This method exists for API consistency with FFI
    }

    #[napi]
    pub async fn configure_enrollment_authority(
        &self,
        ea_public_keys_cbor: Uint8Array,
    ) -> Result<()> {
        let ca_node = self.inner.clone();
        RT.spawn(async move {
            let mut ca_node = ca_node.write().unwrap();
            // For now, this is a placeholder implementation
            // The full implementation would parse and configure EA keys
            // Use parameter to avoid warnings
            let _ = ea_public_keys_cbor;
            ca_node.add_admin_ski("ea_placeholder".to_string());
            Ok(())
        })
        .await
        .map_err(|e| Error::from_reason(format!("Failed to configure enrollment authority: {e}")))?
    }
}

// CA Node Shared Reference API
#[napi]
pub struct CaNodeShared {
    inner: Arc<RwLock<CANode>>,
}

#[napi]
impl CaNodeShared {
    #[napi]
    pub fn add_admin_ski(&self, admin_ski: String) -> Result<()> {
        let mut ca_node = self.inner.write().unwrap();
        ca_node.add_admin_ski(admin_ski);
        Ok(())
    }

    /// Setup shared CA Node (following FFI pattern)
    #[napi]
    pub async fn setup_complete(
        &self,
        root_ca_subject: String,
        issuing_ca_subject: String,
        validity_days: u32,
        issuing_ca_serial: i64,
        ea_public_keys: Uint8Array,
        network_id: String,
    ) -> Result<()> {
        // Parse enrollment authority public keys
        let ea_public_keys_vec: Vec<Vec<u8>> = cbor::from_slice(&ea_public_keys)
            .map_err(|e| Error::from_reason(format!("Failed to parse EA public keys: {e}")))?;

        // Create Root CA internally (private key never leaves Rust)
        let root_ca = runar_keys::certificate::CertificateAuthority::new(&root_ca_subject)
            .map_err(|e| Error::from_reason(format!("Failed to create Root CA: {e}")))?;

        // Create Issuing CA key internally (private key never leaves Rust)
        let issuing_key = runar_keys::certificate::EcdsaKeyPair::new()
            .map_err(|e| Error::from_reason(format!("Failed to create Issuing CA key: {e}")))?;

        // Create and sign Issuing CA certificate internally
        let issuing_csr =
            runar_keys::certificate::CertificateRequest::create(&issuing_key, &issuing_ca_subject)
                .map_err(|e| Error::from_reason(format!("Failed to create Issuing CA CSR: {e}")))?;

        let issuing_cert = root_ca
            .sign_ca_certificate_request_with_serial(
                &issuing_csr,
                validity_days,
                Some(issuing_ca_serial as u64),
            )
            .map_err(|e| {
                Error::from_reason(format!("Failed to sign Issuing CA certificate: {e}"))
            })?;

        // Install everything in shared CA Node (no private keys exposed) - SYNCHRONOUS like FFI
        let mut ca_node = self.inner.write().unwrap();
        ca_node.network_id = network_id.clone();

        ca_node
            .install_issuing_ca(
                issuing_key,
                issuing_cert,
                root_ca.ca_certificate().clone(),
                ea_public_keys_vec,
            )
            .map_err(|e| Error::from_reason(format!("Failed to install Issuing CA: {e}")))?;

        Ok(())
    }

    /// Configure enrollment authority (following FFI pattern)
    #[napi]
    pub async fn configure_enrollment_authority(
        &self,
        ea_public_keys_cbor: Uint8Array,
    ) -> Result<()> {
        let ea_public_keys: Vec<Vec<u8>> = cbor::from_slice(&ea_public_keys_cbor)
            .map_err(|e| Error::from_reason(format!("Failed to parse EA public keys: {e}")))?;

        let mut ca_node = self.inner.write().unwrap();
        for ea_public_key in ea_public_keys {
            let signer_id = runar_common::compact_ids::compact_id(&ea_public_key);
            ca_node
                .enrollment_authorities
                .insert(signer_id, ea_public_key);
        }
        Ok(())
    }

    /// Get root CA certificate (following FFI pattern)
    #[napi]
    pub fn get_root_ca_certificate(&self) -> Result<Uint8Array> {
        let ca_node = self.inner.read().unwrap();
        let cert_bytes = ca_node.root_ca_cert.der_bytes().to_vec();
        Ok(cert_bytes.into())
    }

    /// Get issuing CA certificate (following FFI pattern)
    #[napi]
    pub async fn get_issuing_ca_certificate(&self) -> Result<Uint8Array> {
        let ca_node = self.inner.read().unwrap();
        let cert_bytes = ca_node.issuing_ca_cert.der_bytes().to_vec();
        Ok(cert_bytes.into())
    }

    /// Handle enrollment request (following FFI pattern)
    #[napi]
    pub async fn handle_enroll(
        &self,
        request_cbor: Uint8Array,
        remote_addr: String,
    ) -> Result<Uint8Array> {
        // Parse the enrollment request
        let enroll_request: runar_keys::ca_node_types::CsrEnrollRequest =
            cbor::from_slice(&request_cbor)
                .map_err(|e| Error::from_reason(format!("Failed to parse enroll request: {e}")))?;

        // Handle the enrollment request
        let mut ca_node = self.inner.write().unwrap();
        let response = ca_node
            .handle_enroll(enroll_request, &remote_addr)
            .map_err(|e| Error::from_reason(format!("Failed to handle enroll request: {e}")))?;

        // Serialize response to CBOR
        let response_cbor = cbor::to_vec(&response)
            .map_err(|e| Error::from_reason(format!("Failed to serialize enroll response: {e}")))?;

        Ok(response_cbor.into())
    }

    /// Handle renewal request (following FFI pattern)
    #[napi]
    pub async fn handle_renew(
        &self,
        request_cbor: Uint8Array,
        peer_cert_der: Uint8Array,
    ) -> Result<Uint8Array> {
        // Parse the renewal request
        let renew_request: runar_keys::ca_node_types::RenewRequest =
            cbor::from_slice(&request_cbor)
                .map_err(|e| Error::from_reason(format!("Failed to parse renew request: {e}")))?;

        // Handle the renewal request
        let mut ca_node = self.inner.write().unwrap();
        let response = ca_node
            .handle_renew(renew_request, &peer_cert_der)
            .map_err(|e| Error::from_reason(format!("Failed to handle renew request: {e}")))?;

        // Serialize response to CBOR
        let response_cbor = cbor::to_vec(&response)
            .map_err(|e| Error::from_reason(format!("Failed to serialize renew response: {e}")))?;

        Ok(response_cbor.into())
    }

    /// Handle revocation request (following FFI pattern)
    #[napi]
    pub async fn handle_revoke(
        &self,
        request_cbor: Uint8Array,
        peer_ski: String,
    ) -> Result<Uint8Array> {
        // Parse the revocation request
        let revoke_request: runar_keys::ca_node_types::RevokeRequest =
            cbor::from_slice(&request_cbor)
                .map_err(|e| Error::from_reason(format!("Failed to parse revoke request: {e}")))?;

        // Handle the revocation request
        let mut ca_node = self.inner.write().unwrap();
        let response = ca_node
            .handle_revoke(revoke_request, &peer_ski)
            .map_err(|e| Error::from_reason(format!("Failed to handle revoke request: {e}")))?;

        // Serialize response to CBOR
        let response_cbor = cbor::to_vec(&response)
            .map_err(|e| Error::from_reason(format!("Failed to serialize revoke response: {e}")))?;

        Ok(response_cbor.into())
    }

    /// Handle chain request (following FFI pattern)
    #[napi]
    pub async fn handle_chain(&self, network_id: String) -> Result<Uint8Array> {
        // Handle the chain request
        let ca_node = self.inner.read().unwrap();
        let response = ca_node
            .handle_chain(network_id)
            .map_err(|e| Error::from_reason(format!("Failed to handle chain request: {e}")))?;

        // Serialize response to CBOR
        let response_cbor = cbor::to_vec(&response)
            .map_err(|e| Error::from_reason(format!("Failed to serialize chain response: {e}")))?;

        Ok(response_cbor.into())
    }

    /// Handle status request (following FFI pattern)
    #[napi]
    pub async fn handle_status(&self, network_id: String) -> Result<Uint8Array> {
        // Handle the status request
        let ca_node = self.inner.read().unwrap();
        let response = ca_node
            .handle_status(network_id)
            .map_err(|e| Error::from_reason(format!("Failed to handle status request: {e}")))?;

        // Serialize response to CBOR
        let response_cbor = cbor::to_vec(&response)
            .map_err(|e| Error::from_reason(format!("Failed to serialize status response: {e}")))?;

        Ok(response_cbor.into())
    }

    /// Handle CRL request (following FFI pattern)
    #[napi]
    pub async fn handle_crl(&self, network_id: String) -> Result<Uint8Array> {
        // Handle the CRL request
        let ca_node = self.inner.read().unwrap();
        let response = ca_node
            .handle_crl(network_id)
            .map_err(|e| Error::from_reason(format!("Failed to handle CRL request: {e}")))?;

        // Serialize response to CBOR
        let response_cbor = cbor::to_vec(&response)
            .map_err(|e| Error::from_reason(format!("Failed to serialize CRL response: {e}")))?;

        Ok(response_cbor.into())
    }

    /// Revoke token (following FFI pattern)
    #[napi]
    pub async fn revoke_token(&self, token_id: String) -> Result<()> {
        let mut ca_node = self.inner.write().unwrap();
        ca_node
            .revoke_token(token_id)
            .map_err(|e| Error::from_reason(format!("Failed to revoke token: {e}")))?;
        Ok(())
    }

    /// Generate CRL-lite (following FFI pattern)
    #[napi]
    pub async fn generate_crl_lite(&self) -> Result<Uint8Array> {
        let ca_node = self.inner.read().unwrap();
        let crl_data = ca_node
            .generate_crl_lite()
            .map_err(|e| Error::from_reason(format!("Failed to generate CRL-lite: {e}")))?;

        // Serialize CRL to CBOR
        let crl_cbor = cbor::to_vec(&crl_data)
            .map_err(|e| Error::from_reason(format!("Failed to serialize CRL-lite: {e}")))?;

        Ok(crl_cbor.into())
    }

    /// Free shared CA Node resources (following FFI pattern)
    #[napi]
    pub fn free(&self) {
        // NAPI-RS handles memory cleanup automatically
        // This method exists for API consistency with FFI
    }
}

/// Utility functions for common operations
#[napi]
pub struct Utils;

#[napi]
impl Utils {
    /// Calculate compact ID from public key (following FFI pattern)
    #[napi]
    pub fn compact_id(public_key: Uint8Array) -> String {
        runar_common::compact_ids::compact_id(&public_key)
    }
}

// Certificate utility functions
#[napi]
pub struct Certificate;

#[napi]
impl Certificate {
    /// Extract SKI (Subject Key Identifier) from DER-encoded certificate
    #[napi]
    pub fn extract_ski(cert_der: Uint8Array) -> Result<String> {
        let cert = runar_keys::certificate::X509Certificate::from_der(cert_der.to_vec())
            .map_err(|e| Error::from_reason(format!("Failed to parse certificate: {e}")))?;

        let ski_bytes = runar_keys::certificate::CertificateValidator::extract_ski(&cert)
            .map_err(|e| Error::from_reason(format!("Failed to extract SKI: {e}")))?;

        // Convert to hex string
        let ski_hex = ski_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("");
        Ok(ski_hex)
    }

    /// Extract serial number from DER-encoded certificate
    #[napi]
    pub fn get_serial(cert_der: Uint8Array) -> Result<String> {
        let cert = runar_keys::certificate::X509Certificate::from_der(cert_der.to_vec())
            .map_err(|e| Error::from_reason(format!("Failed to parse certificate: {e}")))?;

        let parsed = cert
            .parsed()
            .map_err(|e| Error::from_reason(format!("Failed to parse certificate: {e}")))?;

        let serial = parsed.tbs_certificate.serial.to_string();
        Ok(serial)
    }
}

/// Set the global log level (following FFI pattern exactly)
#[napi]
pub fn set_log_level(level: i32) -> Result<()> {
    let log_level = match level {
        0 => LogLevel::Off,
        1 => LogLevel::Error,
        2 => LogLevel::Warn,
        3 => LogLevel::Info,
        4 => LogLevel::Debug,
        5 => LogLevel::Trace,
        _ => {
            return Err(Error::from_reason(format!(
                "Invalid log level: {level}. Must be 0-5"
            )));
        }
    };

    let logging_config = LoggingConfig::new().with_default_level(log_level);
    logging_config.apply();

    Ok(())
}

/// Set node ID on root logger (following FFI pattern exactly)
#[napi]
pub fn set_logger_node_id(node_id: String) -> Result<()> {
    let logger = get_global_logger();
    logger.set_context(node_id);
    Ok(())
}
