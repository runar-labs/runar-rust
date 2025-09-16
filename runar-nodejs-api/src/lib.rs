// Full impl for Keys
use anyhow::anyhow;
use napi::bindgen_prelude::*;
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
// no event registration exported for now
use napi_derive::napi;
use once_cell::sync::Lazy;

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

use runar_keys::{
    CANode, CertificateValidator, CsrEnrollRequest, EnrollmentToken as KeysEnrollmentToken,
    EnrollmentTokenBody, EnvelopeCrypto, MobileKeyManager, NodeKeyManager, RenewRequest,
    RevokeRequest,
};
use runar_logging::{Component, Logger};
use runar_schemas::NodeInfo;

use runar_transporter::discovery::{DiscoveryEvent, DiscoveryOptions};
use runar_transporter::transport::NetworkTransport;
use runar_transporter::{
    CaClient as TransporterCaClient, CaClientConfig, CaServer as TransporterCaServer,
    CaServerConfig, NodeDiscovery, QuicTransport, QuicTransportOptions,
};
use serde::{Deserialize, Serialize};
use serde_cbor as cbor;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock as StdRwLock};
use tokio::runtime::Runtime;
use tokio::sync::{oneshot, Mutex as AsyncMutex};

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
    node_key_manager: Option<Arc<StdRwLock<NodeKeyManager>>>,
    mobile_key_manager: Option<Arc<StdRwLock<MobileKeyManager>>>,
    persistence_dir: Option<String>,
    auto_persist: bool,
    logger: Arc<Logger>,

    local_node_info: Arc<Mutex<Option<NodeInfo>>>,
}

#[napi]
impl Keys {
    #[napi(constructor)]
    pub fn new() -> Self {
        let logger = Arc::new(Logger::new_root(Component::Keys));
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
            inner.mobile_key_manager = Some(Arc::new(StdRwLock::new(mobile)));
        }

        Ok(())
    }

    /// Initialize this instance as a node manager
    /// Returns error if already initialized with different type
    #[napi]
    pub fn init_as_node(&self) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();

        // Check if already initialized as mobile
        if inner.mobile_key_manager.is_some() {
            return Err(Error::from_reason("Already initialized as mobile manager"));
        }

        // Initialize node manager if not already present
        if inner.node_key_manager.is_none() {
            let mut node = NodeKeyManager::new(inner.logger.clone())
                .map_err(|e| Error::from_reason(e.to_string()))?;

            // Try to load existing state first, otherwise generate keys
            let state_loaded = node
                .probe_and_load_state()
                .map_err(|e| Error::from_reason(format!("Failed to probe state: {e}")))?;

            if !state_loaded {
                // No state found - generate keys
                node.generate_keys()
                    .map_err(|e| Error::from_reason(format!("Failed to generate keys: {e}")))?;
            }

            // Logger is updated in both probe_and_load_state and generate_keys
            inner.node_key_manager = Some(Arc::new(StdRwLock::new(node)));
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

    #[napi]
    pub async fn mobile_initialize_user_root_key(&self) -> Result<()> {
        let mut guard = self.inner.lock().unwrap();
        if guard.mobile_key_manager.is_none() {
            guard.mobile_key_manager = Some(Arc::new(StdRwLock::new(
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
    pub fn node_get_keystore_state(&self) -> Result<i32> {
        let inner = self.inner.lock().unwrap();
        let mut ready = 0i32;
        if let Some(n) = inner.node_key_manager.as_ref() {
            match n.write().unwrap().probe_and_load_state() {
                Ok(true) => ready = 1,
                _ => ready = 0,
            }
        }
        Ok(ready)
    }

    #[napi]
    pub fn mobile_get_keystore_state(&self) -> Result<i32> {
        let mut inner = self.inner.lock().unwrap();
        if inner.mobile_key_manager.is_none() {
            inner.mobile_key_manager = Some(Arc::new(StdRwLock::new(
                MobileKeyManager::new(inner.logger.clone())
                    .map_err(|e| Error::from_reason(e.to_string()))?,
            )));
        }
        let mut ready = 0i32;
        if let Some(m) = inner.mobile_key_manager.as_ref() {
            match m.write().unwrap().probe_and_load_state() {
                Ok(true) => ready = 1,
                _ => ready = 0,
            }
        }
        Ok(ready)
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
    pub fn mobile_process_setup_token(&self, st_cbor: Uint8Array) -> Result<Uint8Array> {
        let mut inner = self.inner.lock().unwrap();
        if inner.mobile_key_manager.is_none() {
            inner.mobile_key_manager = Some(Arc::new(StdRwLock::new(
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
            inner.mobile_key_manager = Some(Arc::new(StdRwLock::new(
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
            inner.mobile_key_manager = Some(Arc::new(StdRwLock::new(
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
    pub fn encrypt_for_public_key(
        &self,
        data: Uint8Array,
        recipient_pk: Uint8Array,
    ) -> Result<Uint8Array> {
        let inner = self.inner.lock().unwrap();
        let node_ref = inner
            .node_key_manager
            .as_ref()
            .ok_or_else(|| Error::from_reason("Node not init".to_string()))?;
        let eed = node_ref
            .read()
            .unwrap()
            .encrypt_for_public_key(&data, &recipient_pk)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        cbor::to_vec(&eed)
            .map(Uint8Array::from)
            .map_err(|e| Error::from_reason(e.to_string()))
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
            inner.mobile_key_manager = Some(Arc::new(StdRwLock::new(
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
    pub fn mobile_has_network_private_key(
        &self,
        network_public_key: Uint8Array,
    ) -> Result<Uint8Array> {
        let mut inner = self.inner.lock().unwrap();
        if inner.mobile_key_manager.is_none() {
            inner.mobile_key_manager = Some(Arc::new(StdRwLock::new(
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
            .has_network_private_key(&network_public_key)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Uint8Array::from(pk))
    }

    #[napi]
    pub fn mobile_create_network_key_message(
        &self,
        network_public_key: Uint8Array,
        node_agreement_pk: Uint8Array,
    ) -> Result<Uint8Array> {
        let mut inner = self.inner.lock().unwrap();
        if inner.mobile_key_manager.is_none() {
            inner.mobile_key_manager = Some(Arc::new(StdRwLock::new(
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
}

#[cfg(all(feature = "linux-keystore", target_os = "linux"))]
#[napi]
impl Keys {
    #[napi]
    pub fn register_linux_device_keystore(&self, service: String, account: String) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
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

// Transport
#[napi]
pub struct Transport {
    inner: Arc<Mutex<TransportInner>>,
}

type EventTsfn = ThreadsafeFunction<(String, Uint8Array)>;

struct TransportInner {
    transport: Arc<QuicTransport>,
    pending:
        AsyncMutex<HashMap<String, oneshot::Sender<runar_transporter::transport::NetworkMessage>>>,
}

#[napi]
impl Transport {
    #[napi(constructor)]
    pub fn new(keys: &Keys, options_cbor: Uint8Array) -> Result<Self> {
        // Extract shared NodeKeyManager and logger/resolver
        let (km_arc, logger, local_info_arc, node_pk) = {
            let guard = keys.inner.lock().unwrap();
            let km_arc = guard
                .node_key_manager
                .as_ref()
                .ok_or_else(|| Error::from_reason("Node not init"))?
                .clone();
            let logger = guard.logger.clone();
            let node_pk = km_arc
                .read()
                .unwrap()
                .get_node_public_key()
                .ok_or_else(|| Error::from_reason("Node public key not available"))?;
            (km_arc, logger, guard.local_node_info.clone(), node_pk)
        };

        // Parse bind address from options (CBOR: { bind_addr: "ip:port" })
        let mut bind_addr: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
        if let Ok(serde_cbor::Value::Map(map)) =
            cbor::from_slice::<serde_cbor::Value>(options_cbor.as_ref())
        {
            if let Some(serde_cbor::Value::Text(addr)) =
                map.get(&serde_cbor::Value::Text("bind_addr".into()))
            {
                if let Ok(parsed) = addr.parse() {
                    bind_addr = parsed
                }
            }
        }

        // Threadsafe event emitter holder and pending map
        let event_tsfn: Arc<Mutex<Option<EventTsfn>>> = Arc::new(Mutex::new(None));
        let pending_map: Arc<
            AsyncMutex<
                HashMap<String, oneshot::Sender<runar_transporter::transport::NetworkMessage>>,
            >,
        > = Arc::new(AsyncMutex::new(HashMap::new()));

        // Build transport options with callbacks
        let get_local_node_info: runar_transporter::transport::GetLocalNodeInfoCallback = {
            let local_info_arc = Arc::clone(&local_info_arc);
            let km_arc = Arc::clone(&km_arc);
            Arc::new(move || {
                let local_info_arc = Arc::clone(&local_info_arc);
                let km_arc = Arc::clone(&km_arc);
                Box::pin(async move {
                    if let Some(info) = local_info_arc.lock().unwrap().clone() {
                        Ok(info)
                    } else {
                        Ok(runar_schemas::NodeInfo {
                            node_public_key: km_arc
                                .read()
                                .unwrap()
                                .get_node_public_key()
                                .unwrap_or_default(),
                            network_ids: Vec::new(),
                            addresses: vec!["0.0.0.0:0".to_string()],
                            node_metadata: runar_schemas::NodeMetadata {
                                services: Vec::new(),
                                subscriptions: Vec::new(),
                            },
                            version: 0,
                        })
                    }
                })
            })
        };

        let request_cb: runar_transporter::transport::RequestCallback = {
            let event_tsfn = Arc::clone(&event_tsfn);
            let pending_map = Arc::clone(&pending_map);
            Arc::new(move |req: runar_transporter::transport::NetworkMessage| {
                let event_tsfn = Arc::clone(&event_tsfn);
                let pending_map = Arc::clone(&pending_map);
                Box::pin(async move {
                    // If no JS listener registered, auto-echo to avoid hangs in tests
                    let maybe_tsfn_present = event_tsfn.lock().unwrap().is_some();
                    if !maybe_tsfn_present {
                        return Ok(runar_transporter::transport::NetworkMessage {
                            source_node_id: String::new(),
                            destination_node_id: String::new(),
                            message_type: 5, // MESSAGE_TYPE_RESPONSE
                            payload: runar_transporter::transport::NetworkMessagePayloadItem {
                                path: req.payload.path.clone(),
                                payload_bytes: req.payload.payload_bytes.clone(),
                                correlation_id: req.payload.correlation_id.clone(),
                                network_public_key: None,
                                profile_public_keys: req.payload.profile_public_keys.clone(),
                            },
                        });
                    }
                    // Else, register oneshot and emit event for JS to complete
                    let (tx, rx) = oneshot::channel();
                    {
                        let mut map = pending_map.lock().await;
                        map.insert(req.payload.correlation_id.clone(), tx);
                    }
                    if let Some(tsfn) = event_tsfn.lock().unwrap().as_ref() {
                        let payload = cbor::to_vec(&req)
                            .map_err(|e| anyhow!(format!("Failed to CBOR encode request: {e}")))?;
                        let _ = tsfn.call(
                            Ok(("request".to_string(), Uint8Array::from(payload))),
                            ThreadsafeFunctionCallMode::NonBlocking,
                        );
                    }
                    let resp = rx.await.map_err(|_| anyhow!("request canceled"))?;
                    Ok(resp)
                })
            })
        };

        let event_cb: runar_transporter::transport::EventCallback = {
            let event_tsfn = Arc::clone(&event_tsfn);
            Arc::new(move |ev: runar_transporter::transport::NetworkMessage| {
                let event_tsfn = Arc::clone(&event_tsfn);
                Box::pin(async move {
                    if let Some(tsfn) = event_tsfn.lock().unwrap().as_ref() {
                        if let Ok(payload) = cbor::to_vec(&ev) {
                            let _ = tsfn.call(
                                Ok(("event".to_string(), Uint8Array::from(payload))),
                                ThreadsafeFunctionCallMode::NonBlocking,
                            );
                        }
                    }
                    Ok(())
                })
            })
        };

        let peer_connected_cb: runar_transporter::transport::PeerConnectedCallback = {
            let event_tsfn = Arc::clone(&event_tsfn);
            Arc::new(move |_peer_id: String, info: runar_schemas::NodeInfo| {
                let event_tsfn = Arc::clone(&event_tsfn);
                Box::pin(async move {
                    if let Some(tsfn) = event_tsfn.lock().unwrap().as_ref() {
                        if let Ok(payload) = cbor::to_vec(&info) {
                            let _ = tsfn.call(
                                Ok(("peerConnected".to_string(), Uint8Array::from(payload))),
                                ThreadsafeFunctionCallMode::NonBlocking,
                            );
                        }
                    }
                })
            })
        };

        let opts = QuicTransportOptions::new()
            .with_bind_addr(bind_addr)
            .with_local_node_public_key(node_pk)
            .with_logger(logger)
            .with_key_manager(km_arc)
            .with_get_local_node_info(get_local_node_info)
            .with_request_callback(request_cb)
            .with_event_callback(event_cb)
            .with_peer_connected_callback(peer_connected_cb);

        let transport = QuicTransport::new(opts)
            .map_err(|e| Error::from_reason(format!("Transport init error: {e}")))?;

        Ok(Transport {
            inner: Arc::new(Mutex::new(TransportInner {
                transport: Arc::new(transport),
                pending: AsyncMutex::new(HashMap::new()),
            })),
        })
    }

    // Intentionally not exposing event registration to JS yet; tests use request/publish directly

    #[napi]
    pub async fn complete_request(
        &self,
        request_id: String,
        response_payload: Uint8Array,
        profile_public_keys: Vec<Uint8Array>,
    ) -> Result<()> {
        let guard = self.inner.lock().unwrap();
        let mut map = guard.pending.blocking_lock();
        if let Some(sender) = map.remove(&request_id) {
            let profile_pks: Vec<Vec<u8>> =
                profile_public_keys.iter().map(|pk| pk.to_vec()).collect();
            let _ = sender.send(runar_transporter::transport::NetworkMessage {
                source_node_id: String::new(),
                destination_node_id: String::new(),
                message_type: 5, // MESSAGE_TYPE_RESPONSE
                payload: runar_transporter::transport::NetworkMessagePayloadItem {
                    path: String::new(),
                    payload_bytes: response_payload.to_vec(),
                    correlation_id: String::new(),
                    network_public_key: None,
                    profile_public_keys: profile_pks,
                },
            });
            Ok(())
        } else {
            Err(Error::from_reason("unknown request_id"))
        }
    }

    // --- Transport control & messaging API ---

    #[napi]
    pub async fn start(&self) -> Result<()> {
        let t = { self.inner.lock().unwrap().transport.clone() };
        t.start()
            .await
            .map_err(|e| Error::from_reason(format!("start failed: {e}")))
    }

    #[napi]
    pub async fn stop(&self) -> Result<()> {
        let t = { self.inner.lock().unwrap().transport.clone() };
        t.stop()
            .await
            .map_err(|e| Error::from_reason(format!("stop failed: {e}")))
    }

    #[napi]
    pub async fn connect_peer(&self, peer_info_cbor: Uint8Array) -> Result<()> {
        let peer: runar_transporter::discovery::multicast_discovery::PeerInfo =
            cbor::from_slice(peer_info_cbor.as_ref())
                .map_err(|e| Error::from_reason(format!("peer decode failed: {e}")))?;
        let t = { self.inner.lock().unwrap().transport.clone() };
        runar_transporter::transport::NetworkTransport::connect_peer(t, peer)
            .await
            .map_err(|e| Error::from_reason(format!("connect_peer failed: {e}")))
    }

    #[napi]
    pub async fn is_connected(&self, peer_id: String) -> Result<bool> {
        let t = { self.inner.lock().unwrap().transport.clone() };
        Ok(t.is_connected(&peer_id).await)
    }

    #[napi]
    pub async fn is_connected_to_public_key(&self, peer_public_key: Uint8Array) -> Result<bool> {
        let id = runar_common::compact_ids::compact_id(&peer_public_key);
        self.is_connected(id)
            .await
            .map_err(|e| Error::from_reason(format!("is_connected failed: {e}")))
    }

    #[napi]
    pub async fn request(
        &self,
        path: String,
        correlation_id: String,
        payload: Uint8Array,
        dest_peer_id: String,
        network_public_key: Option<Uint8Array>,
        profile_public_keys: Option<Vec<Uint8Array>>,
    ) -> Result<Uint8Array> {
        let t = { self.inner.lock().unwrap().transport.clone() };
        let network_pk = network_public_key.map(|b| b.to_vec());
        let profile_pks = profile_public_keys
            .map(|pks| pks.iter().map(|pk| pk.to_vec()).collect())
            .unwrap_or_default();

        let res = t
            .request(
                &path,
                &correlation_id,
                payload.to_vec(),
                &dest_peer_id,
                network_pk,
                profile_pks,
            )
            .await
            .map_err(|e| Error::from_reason(format!("request failed: {e}")))?;
        Ok(Uint8Array::from(res))
    }

    #[napi]
    pub async fn publish(
        &self,
        path: String,
        correlation_id: String,
        payload: Uint8Array,
        dest_peer_id: String,
        network_public_key: Option<Uint8Array>,
    ) -> Result<()> {
        let t = { self.inner.lock().unwrap().transport.clone() };
        let network_pk = network_public_key.map(|b| b.to_vec());
        t.publish(
            &path,
            &correlation_id,
            payload.to_vec(),
            &dest_peer_id,
            network_pk,
        )
        .await
        .map_err(|e| Error::from_reason(format!("publish failed: {e}")))
    }

    #[napi]
    pub async fn update_peers(&self, node_info_cbor: Uint8Array) -> Result<()> {
        let info: runar_schemas::NodeInfo = cbor::from_slice(node_info_cbor.as_ref())
            .map_err(|e| Error::from_reason(format!("NodeInfo decode failed: {e}")))?;
        let t = { self.inner.lock().unwrap().transport.clone() };
        t.update_peers(info)
            .await
            .map_err(|e| Error::from_reason(format!("update_peers failed: {e}")))
    }
}

// Discovery implementation
#[napi]
pub struct Discovery {
    inner: Arc<Mutex<DiscoveryInner>>,
}

struct DiscoveryInner {
    discovery: Arc<runar_transporter::discovery::MulticastDiscovery>,
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
        let inner = keys.inner.lock().unwrap();
        let node_pk = if let Some(n) = inner.node_key_manager.as_ref() {
            n.read().unwrap().get_node_public_key()
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
                (*logger).clone(),
            ))
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Discovery {
            inner: Arc::new(Mutex::new(DiscoveryInner {
                discovery: Arc::new(disc),
            })),
        })
    }

    #[napi]
    pub async fn init(&self, options_cbor: Uint8Array) -> Result<()> {
        let opts = parse_discovery_options(options_cbor.as_ref());
        let d = { self.inner.lock().unwrap().discovery.clone() };
        d.init(opts)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn bind_events_to_transport(&self, transport: &Transport) -> Result<()> {
        let d = { self.inner.lock().unwrap().discovery.clone() };
        let t = { transport.inner.lock().unwrap().transport.clone() };
        let listener: runar_transporter::discovery::DiscoveryListener =
            Arc::new(move |ev: DiscoveryEvent| {
                let t = t.clone();
                Box::pin(async move {
                    match ev {
                        DiscoveryEvent::Discovered(peer) | DiscoveryEvent::Updated(peer) => {
                            let _ = NetworkTransport::connect_peer(t.clone(), peer).await;
                        }
                        DiscoveryEvent::Lost(_id) => {
                            // Optional: disconnect
                        }
                    }
                })
            });
        d.subscribe(listener)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn start_announcing(&self) -> Result<()> {
        let d = { self.inner.lock().unwrap().discovery.clone() };
        d.start_announcing()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn stop_announcing(&self) -> Result<()> {
        let d = { self.inner.lock().unwrap().discovery.clone() };
        d.stop_announcing()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn shutdown(&self) -> Result<()> {
        let d = { self.inner.lock().unwrap().discovery.clone() };
        d.shutdown()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn update_local_peer_info(&self, peer_info_cbor: Uint8Array) -> Result<()> {
        let d = { self.inner.lock().unwrap().discovery.clone() };
        let peer: runar_transporter::discovery::multicast_discovery::PeerInfo =
            cbor::from_slice(peer_info_cbor.as_ref())
                .map_err(|e| Error::from_reason(e.to_string()))?;
        d.update_local_peer_info(peer)
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
    pub fn new(config_cbor: Uint8Array, _shared_ca_node: &CaNodeShared) -> Result<Self> {
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

        // Create CA Server - we need to create a new CANode since we can't easily convert AsyncMutex to RwLock
        // For now, create a placeholder CANode - this will be properly implemented when the full CA infrastructure is ready
        let ca_logger = Arc::new(Logger::new_root(Component::Keys));
        let ca_node = CANode::new(
            runar_keys::certificate::EcdsaKeyPair::new()
                .map_err(|e| Error::from_reason(format!("Failed to create CA key: {e}")))?,
            runar_keys::certificate::X509Certificate::from_der(vec![])
                .map_err(|e| Error::from_reason(format!("Failed to create CA cert: {e}")))?,
            runar_keys::certificate::X509Certificate::from_der(vec![])
                .map_err(|e| Error::from_reason(format!("Failed to create root cert: {e}")))?,
            "default_network".to_string(),
            ca_logger,
        );
        let ca_node_rwlock = Arc::new(StdRwLock::new(ca_node));
        let ca_server = TransporterCaServer::new(config, ca_node_rwlock, logger);

        Ok(Self {
            inner: Arc::new(AsyncMutex::new(ca_server)),
            bootstrap_addr: Arc::new(Mutex::new(None)),
            authenticated_addr: Arc::new(Mutex::new(None)),
        })
    }

    #[napi]
    pub async fn start(&self) -> Result<()> {
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
        _root_ca: &Ca,
        _subject: String,
        _validity_days: u32,
        _serial: i64,
    ) -> Result<Ca> {
        // For now, we'll use a simplified approach since we need to create a CSR first
        // This is a placeholder - we need to implement CSR creation
        Err(Error::from_reason("CSR creation not yet implemented"))
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
    inner: Arc<AsyncMutex<CANode>>,
}

#[napi]
impl CaNode {
    #[napi(constructor)]
    pub fn new() -> Result<Self> {
        let logger = Arc::new(Logger::new_root(Component::Keys));
        let ca_node = CANode::new(
            runar_keys::certificate::EcdsaKeyPair::new()
                .map_err(|e| Error::from_reason(format!("Failed to create CA key: {e}")))?,
            runar_keys::certificate::X509Certificate::from_der(vec![])
                .map_err(|e| Error::from_reason(format!("Failed to create CA cert: {e}")))?,
            runar_keys::certificate::X509Certificate::from_der(vec![])
                .map_err(|e| Error::from_reason(format!("Failed to create root cert: {e}")))?,
            "default_network".to_string(),
            logger,
        );
        Ok(Self {
            inner: Arc::new(AsyncMutex::new(ca_node)),
        })
    }

    #[napi]
    pub async fn install_issuing_ca(&self, ca_cert_der: Uint8Array) -> Result<()> {
        let _ca_cert = runar_keys::certificate::X509Certificate::from_der(ca_cert_der.to_vec())
            .map_err(|e| Error::from_reason(format!("Failed to parse CA cert: {e}")))?;

        let ca_node = self.inner.clone();
        RT.spawn(async move {
            let mut ca_node = ca_node.lock().await;
            // For now, just add the cert to the admin SKI allowlist as a placeholder
            // The full implementation would require more parameters
            ca_node.add_admin_ski("placeholder".to_string());
        })
        .await
        .map_err(|e| Error::from_reason(format!("Failed to install issuing CA: {e}")))?;

        Ok(())
    }

    #[napi]
    pub async fn handle_enroll(&self, request_cbor: Uint8Array) -> Result<Uint8Array> {
        let request: CsrEnrollRequest = cbor::from_slice(&request_cbor)
            .map_err(|e| Error::from_reason(format!("Failed to deserialize request: {e}")))?;

        let ca_node = self.inner.clone();
        let result = RT
            .spawn(async move {
                let mut ca_node = ca_node.lock().await;
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
                let mut ca_node = ca_node.lock().await;
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
                let mut ca_node = ca_node.lock().await;
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
                let ca_node = ca_node.lock().await;
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
                let ca_node = ca_node.lock().await;
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
                let ca_node = ca_node.lock().await;
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
            let mut ca_node = ca_node.lock().await;
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
            let mut ca_node = ca_node.lock().await;
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
                let ca_node = ca_node.lock().await;
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
}

// CA Node Shared Reference API
#[napi]
pub struct CaNodeShared {
    inner: Arc<AsyncMutex<CANode>>,
}

#[napi]
impl CaNodeShared {
    #[napi]
    pub async fn add_admin_ski(&self, admin_ski: String) -> Result<()> {
        let ca_node = self.inner.clone();
        RT.spawn(async move {
            let mut ca_node = ca_node.lock().await;
            ca_node.add_admin_ski(admin_ski);
        })
        .await
        .map_err(|e| Error::from_reason(format!("Failed to add admin SKI: {e}")))?;

        Ok(())
    }
}
