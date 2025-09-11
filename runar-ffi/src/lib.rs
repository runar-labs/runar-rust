#![allow(clippy::missing_safety_doc)]

use std::{
    ffi::{c_void, CString},
    os::raw::c_char,
    ptr,
    sync::{Arc, RwLock},
};

use arc_swap::ArcSwap;
use once_cell::sync::OnceCell;
use runar_common::logging::{Component, Logger};
use runar_keys::keystore;

use runar_keys::{
    ca_node::CANode,
    ca_node_types::{CsrEnrollRequest, RenewRequest, RevokeRequest},
    certificate::{EcdsaKeyPair, X509Certificate},
    mobile::{MobileKeyManager, NodeCertificateMessage, SetupToken},
    node::NodeKeyManager,
    EnvelopeCrypto,
};
use runar_schemas::NodeInfo;

use runar_transporter::discovery::multicast_discovery::PeerInfo;
use runar_transporter::discovery::{DiscoveryEvent, DiscoveryOptions, MulticastDiscovery};
use runar_transporter::{
    ca_client::CaClient, ca_server::CaServer, NetworkTransport, NodeDiscovery, QuicTransport,
    QuicTransportOptions,
};

/// FFI wrapper for CA Client with configuration data
pub struct CaClientWrapper {
    pub client: CaClient,
    pub config: runar_transporter::CaClientConfig,
    pub logger: Arc<Logger>,
    pub root_ca_cert: Option<Vec<u8>>,
    pub issuing_ca_cert: Option<Vec<u8>>,
    pub node_key_manager: Option<Arc<std::sync::RwLock<NodeKeyManager>>>,
}
use serde_cbor as _; // keep dependency linked for now
                     // panic handling imports removed - no longer needed without ffi_guard
use std::sync::Mutex as StdMutex;
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot, Mutex};

#[repr(C)]
pub struct RnError {
    pub code: i32,
    pub message: *const c_char,
}

// C-compatible data structures are defined later in the file

// Error code constants - unique for each error type
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

static LAST_ERROR: OnceCell<StdMutex<Option<String>>> = OnceCell::new();

// Minimal memory helpers (placeholders; to be filled during implementation)
#[no_mangle]
pub extern "C" fn rn_free(_p: *mut u8, _len: usize) {}

#[no_mangle]
pub extern "C" fn rn_string_free(s: *const c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(s as *mut c_char);
    }
}

// Placeholders for handles to satisfy linkage while we implement
#[repr(C)]
pub struct FfiTransportHandle {
    inner: *mut TransportInner,
}

struct KeysInner {
    logger: Arc<Logger>,

    // Separate fields for each manager type - either Node OR Mobile, never both
    mobile_key_manager: Option<Arc<RwLock<MobileKeyManager>>>,
    node_key_manager: Option<Arc<RwLock<NodeKeyManager>>>,

    // Local NodeInfo holder (push-updated from FFI)
    local_node_info: Arc<ArcSwap<Option<NodeInfo>>>,
    // Shared device keystore registered at FFI level
    device_keystore: Option<Arc<dyn keystore::DeviceKeystore>>,
    // Persistence directory and auto-persist flag
    persistence_dir: Option<std::path::PathBuf>,
    auto_persist: bool,
}

// New transport parameter types for CBOR serialization
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TransportRequestParams {
    pub path: String,
    pub correlation_id: String,
    pub payload: Vec<u8>,
    pub dest_peer_id: String,
    pub network_public_key: Option<Vec<u8>>,
    pub profile_public_keys: Vec<Vec<u8>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct TransportPublishParams {
    pub path: String,
    pub correlation_id: String,
    pub payload: Vec<u8>,
    pub dest_peer_id: String,
    pub network_public_key: Option<Vec<u8>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct TransportCompleteRequestParams {
    pub request_id: String,
    pub response_payload: Vec<u8>,
    pub profile_public_keys: Vec<Vec<u8>>,
}

// Error types for validation
#[derive(Debug, Clone)]
enum RnErrorType {
    NotInitialized,
    WrongManagerType(String),
}

impl RnErrorType {
    fn code(&self) -> i32 {
        match self {
            RnErrorType::NotInitialized => RN_ERROR_NOT_INITIALIZED,
            RnErrorType::WrongManagerType(_) => RN_ERROR_WRONG_MANAGER_TYPE,
        }
    }

    fn message(&self) -> String {
        match self {
            RnErrorType::NotInitialized => "key manager not initialized".to_string(),
            RnErrorType::WrongManagerType(msg) => msg.clone(),
        }
    }
}

/// Validate mobile key manager exists and node manager doesn't
fn validate_mobile_manager(
    inner: &KeysInner,
) -> Result<&Arc<RwLock<MobileKeyManager>>, RnErrorType> {
    // Check for wrong manager type first
    if inner.node_key_manager.is_some() {
        return Err(RnErrorType::WrongManagerType(
            "expected mobile manager, found node manager".into(),
        ));
    }

    // Check if mobile manager exists
    inner
        .mobile_key_manager
        .as_ref()
        .ok_or_else(|| RnErrorType::NotInitialized)
}

/// Validate node key manager exists and mobile manager doesn't
fn validate_node_manager(inner: &KeysInner) -> Result<&Arc<RwLock<NodeKeyManager>>, RnErrorType> {
    // Check for wrong manager type first
    if inner.mobile_key_manager.is_some() {
        return Err(RnErrorType::WrongManagerType(
            "expected node manager, found mobile manager".into(),
        ));
    }

    // Check if node manager exists
    inner
        .node_key_manager
        .as_ref()
        .ok_or_else(|| RnErrorType::NotInitialized)
}

// Common keystore registration helpers
#[cfg(any(
    all(
        feature = "apple-keystore",
        any(target_os = "macos", target_os = "ios")
    ),
    all(feature = "linux-keystore", target_os = "linux")
))]
/// Common parameter validation for keystore registration
unsafe fn validate_keystore_params(
    keys: *mut c_void,
    err: *mut RnError,
) -> Result<*mut KeysInner, i32> {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return Err(RN_ERROR_INVALID_HANDLE);
    };
    Ok(inner)
}

#[cfg(any(
    all(
        feature = "apple-keystore",
        any(target_os = "macos", target_os = "ios")
    ),
    all(feature = "linux-keystore", target_os = "linux")
))]
/// Common UTF-8 validation for keystore registration
unsafe fn validate_utf8_string(
    ptr: *const c_char,
    err: *mut RnError,
    param_name: &str,
) -> Result<String, i32> {
    if ptr.is_null() {
        set_error(
            err,
            RN_ERROR_NULL_ARGUMENT,
            &format!("{param_name} is null"),
        );
        return Err(RN_ERROR_NULL_ARGUMENT);
    }
    match std::ffi::CStr::from_ptr(ptr).to_str() {
        Ok(s) => Ok(s.to_string()),
        Err(_) => {
            set_error(
                err,
                RN_ERROR_INVALID_UTF8,
                &format!("invalid utf8 in {param_name}"),
            );
            Err(RN_ERROR_INVALID_UTF8)
        }
    }
}

#[cfg(any(
    all(
        feature = "apple-keystore",
        any(target_os = "macos", target_os = "ios")
    ),
    all(feature = "linux-keystore", target_os = "linux")
))]
/// Common manager registration logic
fn register_keystore_with_managers(
    inner: &mut KeysInner,
    keystore: Arc<dyn keystore::DeviceKeystore>,
) {
    if let Some(manager) = &inner.node_key_manager {
        let mut mgr = manager.write().unwrap();
        mgr.register_device_keystore(keystore.clone());
    }
    if let Some(manager) = &inner.mobile_key_manager {
        let mut mgr = manager.write().unwrap();
        mgr.register_device_keystore(keystore.clone());
    }
    inner.device_keystore = Some(keystore);
}

#[cfg(any(
    all(
        feature = "apple-keystore",
        any(target_os = "macos", target_os = "ios")
    ),
    all(feature = "linux-keystore", target_os = "linux")
))]
/// Common keystore creation error handling
fn handle_keystore_creation_error(
    err: *mut RnError,
    keystore_type: &str,
    error: impl std::fmt::Display,
) -> i32 {
    set_error(
        err,
        RN_ERROR_KEYSTORE_FAILED,
        &format!("Failed to create {keystore_type}: {error}"),
    );
    RN_ERROR_KEYSTORE_FAILED
}

struct TransportInner {
    transport: Arc<QuicTransport>,
    events_tx: mpsc::Sender<Vec<u8>>,
    events_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    pending: Arc<
        Mutex<
            std::collections::HashMap<
                String,
                oneshot::Sender<runar_transporter::transport::NetworkMessage>,
            >,
        >,
    >,
    local_node_info: Arc<ArcSwap<Option<NodeInfo>>>,
}

struct DiscoveryInner {
    discovery: Arc<MulticastDiscovery>,
    events_tx: Option<mpsc::Sender<Vec<u8>>>,
}

#[repr(C)]
pub struct FfiKeysHandle {
    inner: *mut KeysInner,
}
#[repr(C)]
pub struct FfiDiscoveryHandle {
    inner: *mut DiscoveryInner,
}

fn set_error(err: *mut RnError, code: i32, message: &str) {
    if err.is_null() {
        // still store the message globally
        let cell = LAST_ERROR.get_or_init(|| StdMutex::new(None));
        let mut guard = cell.lock().unwrap();
        *guard = Some(message.to_string());
        return;
    }
    let c_msg = CString::new(message).unwrap_or_else(|_| CString::new("ffi error").unwrap());
    // store message globally as well
    let cell = LAST_ERROR.get_or_init(|| StdMutex::new(None));
    let mut guard = cell.lock().unwrap();
    *guard = Some(message.to_string());
    unsafe {
        (*err).code = code;
        (*err).message = c_msg.into_raw();
    }
}

fn alloc_bytes(out_ptr: *mut *mut u8, out_len: *mut usize, data: &[u8]) -> bool {
    if out_ptr.is_null() || out_len.is_null() {
        return false;
    }
    let mut v = Vec::with_capacity(data.len());
    v.extend_from_slice(data);
    let len = v.len();
    let ptr_raw = v.as_mut_ptr();
    std::mem::forget(v);
    unsafe {
        *out_ptr = ptr_raw;
        *out_len = len;
    }
    true
}

/// Set local NodeInfo from a CBOR buffer.
///
/// Returns 0 on success.
/// Returns 1 on null/invalid arguments.
/// Returns 2 on CBOR decode error; call `rn_last_error` to retrieve the error message.
#[no_mangle]
pub unsafe extern "C" fn rn_keys_set_local_node_info(
    keys: *mut c_void,
    node_info_cbor: *const u8,
    len: usize,
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        return 1;
    };
    if node_info_cbor.is_null() || len == 0 {
        return 1;
    }
    let slice = std::slice::from_raw_parts(node_info_cbor, len);
    let info: NodeInfo = match serde_cbor::from_slice(slice) {
        Ok(v) => v,
        Err(e) => {
            // Store human-readable error for debugging
            set_error(std::ptr::null_mut(), 2, &format!("decode NodeInfo: {e}"));
            return 2;
        }
    };
    inner.local_node_info.store(Arc::new(Some(info)));
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_last_error(out: *mut c_char, out_len: usize) -> i32 {
    if out.is_null() || out_len == 0 {
        return 1;
    }
    let cell = LAST_ERROR.get_or_init(|| StdMutex::new(None));
    let msg = cell.lock().unwrap().clone().unwrap_or_default();
    let bytes = msg.as_bytes();
    // ensure space for NUL terminator
    let copy_len = bytes.len().min(out_len.saturating_sub(1));
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out as *mut u8, copy_len);
    let end = out.add(copy_len);
    *end = 0;
    0
}

#[no_mangle]
pub extern "C" fn rn_set_log_level(level: i32) {
    let filter = match level {
        0 => log::LevelFilter::Off,
        1 => log::LevelFilter::Error,
        2 => log::LevelFilter::Warn,
        3 => log::LevelFilter::Info,
        4 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Info,
    };
    log::set_max_level(filter);
}

fn alloc_string(out_ptr: *mut *mut c_char, out_len: *mut usize, s: &str) -> bool {
    if out_ptr.is_null() || out_len.is_null() {
        return false;
    }
    match CString::new(s) {
        Ok(cs) => {
            let len = cs.as_bytes().len();
            let raw = cs.into_raw();
            unsafe {
                *out_ptr = raw;
                *out_len = len;
            }
            true
        }
        Err(_) => false,
    }
}

fn alloc_string_simple(out_ptr: *mut *mut c_char, s: &str) -> bool {
    if out_ptr.is_null() {
        return false;
    }
    match CString::new(s) {
        Ok(cs) => {
            let raw = cs.into_raw();
            unsafe {
                *out_ptr = raw;
            }
            true
        }
        Err(_) => false,
    }
}

// ------------------------------
// C-compatible data structures
// ------------------------------

/// CA Server Configuration (C-compatible)
#[repr(C)]
pub struct CaServerConfig {
    pub bootstrap_bind: *const c_char,
    pub authenticated_bind: *const c_char,
    pub network_id: *const c_char,
    pub rate_limit_per_minute: u32,
    pub rate_limit_per_hour: u32,
}

/// CA Client Configuration (C-compatible)
#[repr(C)]
pub struct CaClientConfig {
    pub bootstrap_server: *const c_char,
    pub authenticated_server: *const c_char,
    pub network_id: *const c_char,
    pub request_timeout_seconds: u32,
    pub max_retries: u32,
}

/// Certificate Status (C-compatible)
#[repr(C)]
pub struct CertificateStatus {
    pub is_valid: i32,
    pub not_before: u64,
    pub not_after: u64,
    pub serial_hex: *mut c_char,
}

/// Profile Key Info (C-compatible)
#[repr(C)]
pub struct ProfileKeyInfo {
    pub profile_id: *mut c_char,
    pub public_key: *mut u8,
    pub public_key_len: usize,
}

/// Custom server config for deserialization
#[derive(serde::Deserialize)]
struct CustomCaServerConfig {
    bootstrap_bind: String,
    authenticated_bind: String,
    network_id: String,
    rate_limit_per_minute: u32,
    rate_limit_per_hour: u32,
}

// ------------------------------
// Persistence and keystore management
// ------------------------------

#[repr(C)]
pub struct RnDeviceKeystoreCaps {
    pub version: u32,
    pub flags: u32, // bitfield: 1=hardware_backed, 2=biometric_gate, 4=screenlock_required, 8=strongbox
}

fn map_caps(caps: keystore::DeviceKeystoreCaps) -> RnDeviceKeystoreCaps {
    let mut flags: u32 = 0;
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
    RnDeviceKeystoreCaps {
        version: caps.version,
        flags,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_set_persistence_dir(
    keys: *mut c_void,
    dir: *const c_char,
    err: *mut RnError,
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };
    if dir.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "dir is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    let path_str = match std::ffi::CStr::from_ptr(dir).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error(err, RN_ERROR_INVALID_UTF8, "invalid utf8 in dir");
            return RN_ERROR_INVALID_UTF8;
        }
    };
    let pb = std::path::PathBuf::from(path_str);
    inner.persistence_dir = Some(pb.clone());

    // Set persistence directory on whichever manager exists
    if let Some(manager) = &inner.node_key_manager {
        let mut mgr = manager.write().unwrap();
        mgr.set_persistence_dir(pb.clone());
    } else if let Some(manager) = &inner.mobile_key_manager {
        let mut mgr = manager.write().unwrap();
        mgr.set_persistence_dir(pb.clone());
    } else {
        set_error(err, RN_ERROR_NOT_INITIALIZED, "no key manager initialized");
        return RN_ERROR_NOT_INITIALIZED;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_enable_auto_persist(
    keys: *mut c_void,
    enabled: bool,
    err: *mut RnError,
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };

    // Enable auto-persist on whichever manager exists
    if let Some(manager) = &inner.node_key_manager {
        let mut mgr = manager.write().unwrap();
        mgr.enable_auto_persist(enabled);
    } else if let Some(manager) = &inner.mobile_key_manager {
        let mut mgr = manager.write().unwrap();
        mgr.enable_auto_persist(enabled);
    } else {
        set_error(err, RN_ERROR_NOT_INITIALIZED, "no key manager initialized");
        return RN_ERROR_NOT_INITIALIZED;
    }
    inner.auto_persist = enabled;
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_wipe_persistence(keys: *mut c_void, err: *mut RnError) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };

    // Wipe persistence from whichever manager exists
    if let Some(manager) = &inner.node_key_manager {
        let mgr = manager.write().unwrap();
        if let Err(e) = mgr.wipe_persistence() {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("node wipe_persistence: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    } else if let Some(manager) = &inner.mobile_key_manager {
        let mgr = manager.write().unwrap();
        if let Err(e) = mgr.wipe_persistence() {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("mobile wipe_persistence: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    } else {
        set_error(err, RN_ERROR_NOT_INITIALIZED, "no key manager initialized");
        return RN_ERROR_NOT_INITIALIZED;
    }
    // Also wipe directly from configured persistence dir if present
    if let Some(dir) = inner.persistence_dir.clone() {
        let cfg = runar_keys::keystore::persistence::PersistenceConfig::new(dir.clone());
        let _ = runar_keys::keystore::persistence::wipe(
            &cfg,
            &runar_keys::keystore::persistence::Role::Mobile,
        );
        if let Some(manager) = &inner.node_key_manager {
            let mgr = manager.read().unwrap();
            if let Some(node_id) = mgr.get_node_id() {
                let _ = runar_keys::keystore::persistence::wipe(
                    &cfg,
                    &runar_keys::keystore::persistence::Role::Node { node_id: &node_id },
                );
            }
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_get_keystore_state(
    keys: *mut c_void,
    out_state: *mut *mut c_char,
    out_has_state: *mut i32,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_state.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "out_state pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    // Validate handle upfront
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };

    // Validate manager upfront - exit early on errors
    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    // Main logic - manager is guaranteed to exist
    let mut node_manager = match manager.write() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    // Get the keystore state as Option<String>
    let state_result = match node_manager.probe_and_load_state() {
        Ok(true) => {
            // State was loaded - export the state as a string
            let state = node_manager.export_state();
            match serde_cbor::to_vec(&state) {
                Ok(state_bytes) => {
                    // Base64 encode the CBOR data to make it a valid string
                    let state_string = base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        state_bytes,
                    );
                    Some(state_string)
                }
                Err(e) => {
                    set_error(
                        err,
                        RN_ERROR_OPERATION_FAILED,
                        &format!("failed to serialize state: {e}"),
                    );
                    return RN_ERROR_OPERATION_FAILED;
                }
            }
        }
        Ok(false) => {
            // No state found - generate keys first
            match node_manager.generate_keys() {
                Ok(()) => {
                    // After generating keys, export the state
                    let state = node_manager.export_state();
                    match serde_cbor::to_vec(&state) {
                        Ok(state_bytes) => {
                            // Base64 encode the CBOR data to make it a valid string
                            let state_string = base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                state_bytes,
                            );
                            Some(state_string)
                        }
                        Err(e) => {
                            set_error(
                                err,
                                RN_ERROR_OPERATION_FAILED,
                                &format!("failed to serialize state: {e}"),
                            );
                            return RN_ERROR_OPERATION_FAILED;
                        }
                    }
                }
                Err(e) => {
                    set_error(
                        err,
                        RN_ERROR_KEYSTORE_FAILED,
                        &format!("failed to generate keys: {e}"),
                    );
                    return RN_ERROR_KEYSTORE_FAILED;
                }
            }
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("probe_and_load_state failed: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Set the output parameters
    *out_has_state = if state_result.is_some() { 1 } else { 0 };

    if let Some(state) = state_result {
        match CString::new(state) {
            Ok(state_cstr) => {
                let state_ptr = libc::malloc(state_cstr.as_bytes_with_nul().len()) as *mut c_char;
                if state_ptr.is_null() {
                    set_error(
                        err,
                        RN_ERROR_MEMORY_ALLOCATION,
                        "failed to allocate memory for state",
                    );
                    return RN_ERROR_MEMORY_ALLOCATION;
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        state_cstr.as_ptr(),
                        state_ptr,
                        state_cstr.as_bytes_with_nul().len(),
                    );
                }
                *out_state = state_ptr;
            }
            Err(e) => {
                set_error(
                    err,
                    RN_ERROR_INVALID_ARGUMENT,
                    &format!("invalid state string: {e}"),
                );
                return RN_ERROR_INVALID_ARGUMENT;
            }
        }
    } else {
        *out_state = std::ptr::null_mut();
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_mobile_get_keystore_state(
    keys: *mut c_void,
    out_state: *mut i32,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_state.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "out_state pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    // Validate handle upfront
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };

    // Validate manager upfront - exit early on errors
    let manager = match validate_mobile_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    // Main logic - manager is guaranteed to exist
    let mut mobile_manager = match manager.write() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let ready = match mobile_manager.probe_and_load_state() {
        Ok(true) => 1i32,
        Ok(false) => 0i32,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("probe_and_load_state failed: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    *out_state = ready;
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_get_keystore_caps(
    keys: *mut c_void,
    out_caps: *mut RnDeviceKeystoreCaps,
    err: *mut RnError,
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };
    if out_caps.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "out_caps is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    // Get capabilities from whichever manager exists
    let caps = if let Some(manager) = &inner.node_key_manager {
        let mgr = manager.read().unwrap();
        mgr.get_keystore_caps().unwrap_or_default()
    } else if let Some(manager) = &inner.mobile_key_manager {
        let mgr = manager.read().unwrap();
        mgr.get_keystore_caps().unwrap_or_default()
    } else {
        set_error(err, RN_ERROR_NOT_INITIALIZED, "no key manager initialized");
        return RN_ERROR_NOT_INITIALIZED;
    };
    unsafe { *out_caps = map_caps(caps) };
    0
}

// Explicit flush of state persistence
#[no_mangle]
pub unsafe extern "C" fn rn_keys_flush_state(keys: *mut c_void, err: *mut RnError) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };

    // Flush state on whichever manager exists
    if let Some(manager) = &inner.node_key_manager {
        let mgr = manager.write().unwrap();
        if let Err(e) = mgr.flush_state() {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("node flush_state: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    } else if let Some(manager) = &inner.mobile_key_manager {
        let mgr = manager.write().unwrap();
        if let Err(e) = mgr.flush_state() {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("mobile flush_state: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    } else {
        set_error(err, RN_ERROR_NOT_INITIALIZED, "no key manager initialized");
        return RN_ERROR_NOT_INITIALIZED;
    }
    0
}

#[cfg(all(
    feature = "apple-keystore",
    any(target_os = "macos", target_os = "ios")
))]
#[no_mangle]
pub unsafe extern "C" fn rn_keys_register_apple_device_keystore(
    keys: *mut c_void,
    label: *const c_char,
    err: *mut RnError,
) -> i32 {
    // Common validation - only when feature is enabled
    let inner = match validate_keystore_params(keys, err) {
        Ok(inner) => inner,
        Err(code) => return code,
    };
    let label_str = match validate_utf8_string(label, err, "label") {
        Ok(s) => s,
        Err(code) => return code,
    };

    match runar_keys::keystore::apple::AppleDeviceKeystore::new(&label_str) {
        Ok(ks) => {
            let keystore = Arc::new(ks);
            register_keystore_with_managers(unsafe { &mut *inner }, keystore);
            0
        }
        Err(e) => handle_keystore_creation_error(err, "AppleDeviceKeystore", e),
    }
}

#[cfg(all(feature = "linux-keystore", target_os = "linux"))]
#[no_mangle]
pub unsafe extern "C" fn rn_keys_register_linux_device_keystore(
    keys: *mut c_void,
    service: *const c_char,
    account: *const c_char,
    err: *mut RnError,
) -> i32 {
    // Common validation - only when feature is enabled
    let inner = match validate_keystore_params(keys, err) {
        Ok(inner) => inner,
        Err(code) => return code,
    };
    let svc = match validate_utf8_string(service, err, "service") {
        Ok(s) => s,
        Err(code) => return code,
    };
    let acc = match validate_utf8_string(account, err, "account") {
        Ok(s) => s,
        Err(code) => return code,
    };

    match runar_keys::keystore::linux::LinuxDeviceKeystore::new(&svc, &acc) {
        Ok(ks) => {
            let keystore = Arc::new(ks);
            register_keystore_with_managers(unsafe { &mut *inner }, keystore);
            0
        }
        Err(e) => handle_keystore_creation_error(err, "LinuxDeviceKeystore", e),
    }
}

// Envelope helpers (CBOR EED)
// Legacy function removed - replaced by rn_keys_node_encrypt_with_envelope and rn_keys_mobile_encrypt_with_envelope

#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_encrypt_with_envelope(
    keys: *mut c_void,
    data: *const u8,
    data_len: usize,
    network_public_key: *const u8, // ← NETWORK PUBLIC KEY BYTES
    network_public_key_len: usize,
    profile_pks: *const *const u8,
    profile_lens: *const usize,
    profiles_count: usize,
    out_eed_cbor: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if data.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "data pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if data_len == 0 {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "data length is zero");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_eed_cbor.is_null() {
        set_error(
            err,
            RN_ERROR_NULL_ARGUMENT,
            "output EED CBOR pointer is null",
        );
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_len.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output length pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    // Additional validation for profile keys if provided
    if profiles_count > 0 {
        if profile_pks.is_null() {
            set_error(
                err,
                RN_ERROR_NULL_ARGUMENT,
                "profile public keys pointer is null but count > 0",
            );
            return RN_ERROR_NULL_ARGUMENT;
        }
        if profile_lens.is_null() {
            set_error(
                err,
                RN_ERROR_NULL_ARGUMENT,
                "profile key lengths pointer is null but count > 0",
            );
            return RN_ERROR_NULL_ARGUMENT;
        }
    }

    // Validate handle upfront
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };

    // Validate manager upfront - exit early on errors
    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    // Main logic - manager is guaranteed to exist
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let network_public_key_opt = if network_public_key.is_null() {
        None
    } else {
        Some(std::slice::from_raw_parts(network_public_key, network_public_key_len).to_vec())
    };

    // Process profile keys
    let mut profiles: Vec<Vec<u8>> = Vec::new();
    if profiles_count > 0 && !profile_pks.is_null() && !profile_lens.is_null() {
        for i in 0..profiles_count {
            let pk_ptr = unsafe { *profile_pks.add(i) };
            let len = unsafe { *profile_lens.add(i) };
            if !pk_ptr.is_null() {
                let pk = unsafe { std::slice::from_raw_parts(pk_ptr, len) };
                profiles.push(pk.to_vec());
            }
        }
    }

    let node_manager = match manager.write() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    match node_manager.encrypt_with_envelope(
        data_slice,
        network_public_key_opt.as_deref(),
        profiles,
    ) {
        Ok(eed) => {
            let cbor = match serde_cbor::to_vec(&eed) {
                Ok(v) => v,
                Err(e) => {
                    set_error(
                        err,
                        RN_ERROR_SERIALIZATION_FAILED,
                        &format!("encode EED failed: {e}"),
                    );
                    return RN_ERROR_SERIALIZATION_FAILED;
                }
            };
            if !alloc_bytes(out_eed_cbor, out_len, &cbor) {
                set_error(err, RN_ERROR_MEMORY_ALLOCATION, "alloc failed");
                RN_ERROR_MEMORY_ALLOCATION
            } else {
                0
            }
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("encrypt_with_envelope failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_mobile_encrypt_with_envelope(
    keys: *mut c_void,
    data: *const u8,
    data_len: usize,
    network_public_key: *const u8, // ← NETWORK PUBLIC KEY BYTES
    network_public_key_len: usize,
    profile_pks: *const *const u8,
    profile_lens: *const usize,
    profiles_count: usize,
    out_eed_cbor: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if data.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "data pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if data_len == 0 {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "data length is zero");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_eed_cbor.is_null() {
        set_error(
            err,
            RN_ERROR_NULL_ARGUMENT,
            "output EED CBOR pointer is null",
        );
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_len.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output length pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    // Additional validation for profile keys if provided
    if profiles_count > 0 {
        if profile_pks.is_null() {
            set_error(
                err,
                RN_ERROR_NULL_ARGUMENT,
                "profile public keys pointer is null but count > 0",
            );
            return RN_ERROR_NULL_ARGUMENT;
        }
        if profile_lens.is_null() {
            set_error(
                err,
                RN_ERROR_NULL_ARGUMENT,
                "profile key lengths pointer is null but count > 0",
            );
            return RN_ERROR_NULL_ARGUMENT;
        }
    }

    // Validate handle upfront
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };

    // Validate manager upfront - exit early on errors
    let manager = match validate_mobile_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    // Main logic - manager is guaranteed to exist
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let network_public_key_opt = if network_public_key.is_null() {
        None
    } else {
        Some(std::slice::from_raw_parts(network_public_key, network_public_key_len).to_vec())
    };

    // Process profile keys
    let mut profiles: Vec<Vec<u8>> = Vec::new();
    if profiles_count > 0 && !profile_pks.is_null() && !profile_lens.is_null() {
        for i in 0..profiles_count {
            let pk_ptr = unsafe { *profile_pks.add(i) };
            let len = unsafe { *profile_lens.add(i) };
            if !pk_ptr.is_null() {
                let pk = unsafe { std::slice::from_raw_parts(pk_ptr, len) };
                profiles.push(pk.to_vec());
            }
        }
    }

    let mobile_manager = match manager.write() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    match mobile_manager.encrypt_with_envelope(
        data_slice,
        network_public_key_opt.as_deref(),
        profiles,
    ) {
        Ok(eed) => {
            let cbor = match serde_cbor::to_vec(&eed) {
                Ok(v) => v,
                Err(e) => {
                    set_error(
                        err,
                        RN_ERROR_SERIALIZATION_FAILED,
                        &format!("encode EED failed: {e}"),
                    );
                    return RN_ERROR_SERIALIZATION_FAILED;
                }
            };
            if !alloc_bytes(out_eed_cbor, out_len, &cbor) {
                set_error(err, RN_ERROR_MEMORY_ALLOCATION, "alloc failed");
                RN_ERROR_MEMORY_ALLOCATION
            } else {
                0
            }
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("encrypt_with_envelope failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

// Legacy function removed - replaced by rn_keys_node_decrypt_envelope and rn_keys_mobile_decrypt_envelope

// ------------------------------
// Node-specific envelope decryption
// ------------------------------

#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_decrypt_envelope(
    keys: *mut c_void,
    eed_cbor: *const u8,
    eed_len: usize,
    out_plain: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if eed_cbor.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "EED CBOR pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_plain.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output plain pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_len.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output length pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    // Validate handle upfront
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };

    // Validate manager upfront - exit early on errors
    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    // Main logic - manager is guaranteed to exist
    let slice = std::slice::from_raw_parts(eed_cbor, eed_len);
    let eed: runar_keys::mobile::EnvelopeEncryptedData = match serde_cbor::from_slice(slice) {
        Ok(v) => v,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_SERIALIZATION_FAILED,
                &format!("decode EED failed: {e}"),
            );
            return RN_ERROR_SERIALIZATION_FAILED;
        }
    };

    let node_manager = match manager.read() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let plain = match node_manager.decrypt_envelope_data(&eed) {
        Ok(p) => p,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("decrypt failed: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    if !alloc_bytes(out_plain, out_len, &plain) {
        set_error(err, RN_ERROR_MEMORY_ALLOCATION, "alloc failed");
        return RN_ERROR_MEMORY_ALLOCATION;
    }
    0
}

// ------------------------------
// Mobile-specific envelope decryption
// ------------------------------

#[no_mangle]
pub unsafe extern "C" fn rn_keys_mobile_decrypt_envelope(
    keys: *mut c_void,
    eed_cbor: *const u8,
    eed_len: usize,
    out_plain: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if eed_cbor.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "EED CBOR pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_plain.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output plain pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_len.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output length pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    // Validate handle upfront
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };

    // Validate manager upfront - exit early on errors
    let manager = match validate_mobile_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    // Main logic - manager is guaranteed to exist
    let slice = std::slice::from_raw_parts(eed_cbor, eed_len);
    let eed: runar_keys::mobile::EnvelopeEncryptedData = match serde_cbor::from_slice(slice) {
        Ok(v) => v,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_SERIALIZATION_FAILED,
                &format!("decode EED failed: {e}"),
            );
            return RN_ERROR_SERIALIZATION_FAILED;
        }
    };

    let mobile_manager = match manager.read() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let plain = match mobile_manager.decrypt_envelope_data(&eed) {
        Ok(p) => p,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("decrypt failed: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    if !alloc_bytes(out_plain, out_len, &plain) {
        set_error(err, RN_ERROR_MEMORY_ALLOCATION, "alloc failed");
        return RN_ERROR_MEMORY_ALLOCATION;
    }
    0
}

// ------------------------------
// Additional encryption/decryption APIs
// ------------------------------

#[no_mangle]
pub unsafe extern "C" fn rn_keys_encrypt_local_data(
    keys: *mut c_void,
    data: *const u8,
    data_len: usize,
    out_cipher: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if data.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "data pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_cipher.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output cipher pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_len.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output length pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    // Validate handle upfront
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let node_manager = match manager.write() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let cipher = match node_manager.encrypt_local_data(data_slice) {
        Ok(v) => v,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("encrypt_local_data failed: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };
    if !alloc_bytes(out_cipher, out_len, &cipher) {
        set_error(err, RN_ERROR_MEMORY_ALLOCATION, "alloc failed");
        return RN_ERROR_MEMORY_ALLOCATION;
    }
    0
}

// ------------------------------
// New Mobile/Node APIs for key management
// ------------------------------

#[no_mangle]
pub unsafe extern "C" fn rn_keys_mobile_initialize_user_root_key(
    keys: *mut c_void,
    err: *mut RnError,
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, 1, "keys handle is null");
        return 1;
    };
    let manager = match validate_mobile_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let mut mobile_manager = match manager.write() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    match mobile_manager.initialize_user_root_key() {
        Ok(_) => 0,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("initialize_user_root_key failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// Get the user public key after mobile initialization
/// This is essential for encrypting setup tokens to the mobile
#[no_mangle]
pub unsafe extern "C" fn rn_keys_mobile_get_user_public_key(
    keys: *mut c_void,
    out: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, 1, "keys handle is null");
        return 1;
    };
    let manager = match validate_mobile_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let mobile_manager = match manager.write() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    match mobile_manager.get_user_public_key() {
        Ok(pk) => {
            if !alloc_bytes(out, out_len, &pk) {
                set_error(err, RN_ERROR_MEMORY_ALLOCATION, "alloc failed");
                return RN_ERROR_MEMORY_ALLOCATION;
            }
            0
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("get_user_public_key failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_mobile_derive_user_profile_key(
    keys: *mut c_void,
    label: *const c_char,
    out_pk: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, 1, "keys handle is null");
        return 1;
    };
    if label.is_null() || out_pk.is_null() || out_len.is_null() {
        set_error(err, 1, "null argument");
        return 1;
    }
    let manager = match validate_mobile_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let mut mobile_manager = match manager.write() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let label = match std::ffi::CStr::from_ptr(label).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error(err, RN_ERROR_INVALID_UTF8, "invalid utf8 label");
            return RN_ERROR_INVALID_UTF8;
        }
    };

    match mobile_manager.derive_user_profile_key(label) {
        Ok(pk) => {
            if !alloc_bytes(out_pk, out_len, &pk) {
                set_error(err, RN_ERROR_MEMORY_ALLOCATION, "alloc failed");
                RN_ERROR_MEMORY_ALLOCATION
            } else {
                0
            }
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("derive_user_profile_key failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_mobile_install_network_public_key(
    keys: *mut c_void,
    network_public_key: *const u8,
    len: usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if network_public_key.is_null() {
        set_error(
            err,
            RN_ERROR_NULL_ARGUMENT,
            "network_public_key pointer is null",
        );
        return RN_ERROR_NULL_ARGUMENT;
    }
    if len == 0 {
        set_error(
            err,
            RN_ERROR_INVALID_ARGUMENT,
            "network_public_key length is zero",
        );
        return RN_ERROR_INVALID_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };
    let manager = match validate_mobile_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let mut mobile_manager = match manager.write() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let buf = std::slice::from_raw_parts(network_public_key, len);
    match mobile_manager.install_network_public_key(buf) {
        Ok(_) => 0,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("install_network_public_key failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_mobile_generate_network_data_key(
    keys: *mut c_void,
    out_pk: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_pk.is_null() {
        set_error(
            err,
            RN_ERROR_NULL_ARGUMENT,
            "output public key pointer is null",
        );
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_len.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output length pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };
    let manager = match validate_mobile_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let mut mobile_manager = match manager.write() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    match mobile_manager.generate_network_data_key() {
        Ok(network_public_key) => {
            if !alloc_bytes(out_pk, out_len, &network_public_key) {
                set_error(err, RN_ERROR_MEMORY_ALLOCATION, "alloc failed");
                RN_ERROR_MEMORY_ALLOCATION
            } else {
                0
            }
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("generate_network_data_key failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_mobile_has_network_private_key(
    keys: *mut c_void,
    network_public_key: *const u8,
    network_public_key_len: usize,
    out_pk: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if network_public_key.is_null() {
        set_error(
            err,
            RN_ERROR_NULL_ARGUMENT,
            "network_public_key pointer is null",
        );
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_pk.is_null() {
        set_error(
            err,
            RN_ERROR_NULL_ARGUMENT,
            "output public key pointer is null",
        );
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_len.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output length pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };
    let manager = match validate_mobile_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let mobile_manager = match manager.read() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let network_pk = std::slice::from_raw_parts(network_public_key, network_public_key_len);

    match mobile_manager.has_network_private_key(network_pk) {
        Ok(pk) => {
            if !alloc_bytes(out_pk, out_len, &pk) {
                set_error(err, RN_ERROR_MEMORY_ALLOCATION, "alloc failed");
                RN_ERROR_MEMORY_ALLOCATION
            } else {
                0
            }
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("has_network_private_key failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_mobile_create_network_key_message(
    keys: *mut c_void,
    network_public_key: *const u8,
    network_public_key_len: usize,
    node_agreement_pk: *const u8,
    node_agreement_pk_len: usize,
    out_msg_cbor: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };
    if network_public_key.is_null()
        || node_agreement_pk.is_null()
        || out_msg_cbor.is_null()
        || out_len.is_null()
    {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }
    let manager = match validate_mobile_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let mobile_manager = match manager.read() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let network_pk = std::slice::from_raw_parts(network_public_key, network_public_key_len);
    let node_pk = std::slice::from_raw_parts(node_agreement_pk, node_agreement_pk_len);
    let msg = match mobile_manager.create_network_key_message(network_pk, node_pk) {
        Ok(m) => m,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("create_network_key_message failed: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };
    let cbor = match serde_cbor::to_vec(&msg) {
        Ok(v) => v,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_SERIALIZATION_FAILED,
                &format!("encode NetworkKeyMessage failed: {e}"),
            );
            return RN_ERROR_SERIALIZATION_FAILED;
        }
    };
    if !alloc_bytes(out_msg_cbor, out_len, &cbor) {
        set_error(err, RN_ERROR_MEMORY_ALLOCATION, "alloc failed");
        return RN_ERROR_MEMORY_ALLOCATION;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_decrypt_local_data(
    keys: *mut c_void,
    encrypted: *const u8,
    enc_len: usize,
    out_plain: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if encrypted.is_null() {
        set_error(
            err,
            RN_ERROR_NULL_ARGUMENT,
            "encrypted data pointer is null",
        );
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_plain.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output plain pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_len.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output length pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };
    let enc_slice = std::slice::from_raw_parts(encrypted, enc_len);

    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let node_manager = match manager.read() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let plain = match node_manager.decrypt_local_data(enc_slice) {
        Ok(v) => v,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("decrypt_local_data failed: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };
    if !alloc_bytes(out_plain, out_len, &plain) {
        set_error(err, RN_ERROR_MEMORY_ALLOCATION, "alloc failed");
        return RN_ERROR_MEMORY_ALLOCATION;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_encrypt_message_for_mobile(
    keys: *mut c_void,
    message: *const u8,
    message_len: usize,
    mobile_public_key: *const u8,
    pk_len: usize,
    out_cipher: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if message.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "message pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if mobile_public_key.is_null() {
        set_error(
            err,
            RN_ERROR_NULL_ARGUMENT,
            "mobile public key pointer is null",
        );
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_cipher.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output cipher pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_len.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output length pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };
    let msg = std::slice::from_raw_parts(message, message_len);
    let pk = std::slice::from_raw_parts(mobile_public_key, pk_len);

    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let node_manager = match manager.read() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let cipher = match node_manager.encrypt_message_for_mobile(msg, pk) {
        Ok(v) => v,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("encrypt_message_for_mobile failed: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };
    if !alloc_bytes(out_cipher, out_len, &cipher) {
        set_error(err, RN_ERROR_MEMORY_ALLOCATION, "alloc failed");
        return RN_ERROR_MEMORY_ALLOCATION;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_decrypt_message_from_mobile(
    keys: *mut c_void,
    encrypted_message: *const u8,
    enc_len: usize,
    out_plain: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if encrypted_message.is_null() {
        set_error(
            err,
            RN_ERROR_NULL_ARGUMENT,
            "encrypted message pointer is null",
        );
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_plain.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output plain pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_len.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output length pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };
    let enc = std::slice::from_raw_parts(encrypted_message, enc_len);

    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let node_manager = match manager.read() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let plain = match node_manager.decrypt_message_from_mobile(enc) {
        Ok(v) => v,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("decrypt_message_from_mobile failed: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };
    if !alloc_bytes(out_plain, out_len, &plain) {
        set_error(err, RN_ERROR_MEMORY_ALLOCATION, "alloc failed");
        return RN_ERROR_MEMORY_ALLOCATION;
    }
    0
}

/// Encrypt a message from mobile to node using node's agreement public key
#[no_mangle]
pub unsafe extern "C" fn rn_keys_encrypt_message_for_node(
    keys: *mut c_void,
    message: *const u8,
    message_len: usize,
    node_agreement_public_key: *const u8,
    pk_len: usize,
    out_cipher: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if message.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "message pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if node_agreement_public_key.is_null() {
        set_error(
            err,
            RN_ERROR_NULL_ARGUMENT,
            "node agreement public key pointer is null",
        );
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_cipher.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output cipher pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_len.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output length pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };
    let manager = match validate_mobile_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let mobile_manager = match manager.read() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let msg = std::slice::from_raw_parts(message, message_len);
    let pk = std::slice::from_raw_parts(node_agreement_public_key, pk_len);

    let cipher = match mobile_manager.encrypt_message_for_node(msg, pk) {
        Ok(c) => c,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("encrypt_message_for_node failed: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    if !alloc_bytes(out_cipher, out_len, &cipher) {
        set_error(err, RN_ERROR_MEMORY_ALLOCATION, "alloc failed");
        return RN_ERROR_MEMORY_ALLOCATION;
    }
    0
}

/// Decrypt a message from node on mobile using mobile's agreement private key
#[no_mangle]
pub unsafe extern "C" fn rn_keys_mobile_decrypt_message_from_node(
    keys: *mut c_void,
    encrypted_message: *const u8,
    enc_len: usize,
    out_plain: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if encrypted_message.is_null() {
        set_error(
            err,
            RN_ERROR_NULL_ARGUMENT,
            "encrypted message pointer is null",
        );
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_plain.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output plain pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_len.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output length pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };
    let manager = match validate_mobile_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let mobile_manager = match manager.read() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let enc = std::slice::from_raw_parts(encrypted_message, enc_len);

    let plain = match mobile_manager.decrypt_message_from_node(enc) {
        Ok(p) => p,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("decrypt_message_from_node failed: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    if !alloc_bytes(out_plain, out_len, &plain) {
        set_error(err, RN_ERROR_MEMORY_ALLOCATION, "alloc failed");
        return RN_ERROR_MEMORY_ALLOCATION;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_encrypt_for_public_key(
    keys: *mut c_void,
    data: *const u8,
    data_len: usize,
    recipient_public_key: *const u8,
    pk_len: usize,
    out_eed_cbor: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if data.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "data pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if recipient_public_key.is_null() {
        set_error(
            err,
            RN_ERROR_NULL_ARGUMENT,
            "recipient public key pointer is null",
        );
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_eed_cbor.is_null() {
        set_error(
            err,
            RN_ERROR_NULL_ARGUMENT,
            "output EED CBOR pointer is null",
        );
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_len.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output length pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let pk = std::slice::from_raw_parts(recipient_public_key, pk_len);

    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let node_manager = match manager.read() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let eed = match node_manager.encrypt_for_public_key(data_slice, pk) {
        Ok(v) => v,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("encrypt_for_public_key failed: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };
    let cbor = match serde_cbor::to_vec(&eed) {
        Ok(v) => v,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_SERIALIZATION_FAILED,
                &format!("encode EED failed: {e}"),
            );
            return RN_ERROR_SERIALIZATION_FAILED;
        }
    };
    if !alloc_bytes(out_eed_cbor, out_len, &cbor) {
        set_error(err, RN_ERROR_MEMORY_ALLOCATION, "alloc failed");
        return RN_ERROR_MEMORY_ALLOCATION;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_encrypt_for_network(
    keys: *mut c_void,
    data: *const u8,
    data_len: usize,
    network_public_key: *const u8,
    network_public_key_len: usize,
    out_eed_cbor: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if data.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "data pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if network_public_key.is_null() {
        set_error(
            err,
            RN_ERROR_NULL_ARGUMENT,
            "network_public_key pointer is null",
        );
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_eed_cbor.is_null() {
        set_error(
            err,
            RN_ERROR_NULL_ARGUMENT,
            "output EED CBOR pointer is null",
        );
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_len.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output length pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let network_pk = std::slice::from_raw_parts(network_public_key, network_public_key_len);
    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let node_manager = match manager.read() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let eed = match node_manager.encrypt_for_network(data_slice, network_pk) {
        Ok(v) => v,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("encrypt_for_network failed: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };
    let cbor = match serde_cbor::to_vec(&eed) {
        Ok(v) => v,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_SERIALIZATION_FAILED,
                &format!("encode EED failed: {e}"),
            );
            return RN_ERROR_SERIALIZATION_FAILED;
        }
    };
    if !alloc_bytes(out_eed_cbor, out_len, &cbor) {
        set_error(err, RN_ERROR_MEMORY_ALLOCATION, "alloc failed");
        return RN_ERROR_MEMORY_ALLOCATION;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_decrypt_network_data(
    keys: *mut c_void,
    eed_cbor: *const u8,
    eed_len: usize,
    out_plain: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if eed_cbor.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "EED CBOR pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_plain.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output plain pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_len.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output length pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };
    let slice = std::slice::from_raw_parts(eed_cbor, eed_len);
    let eed: runar_keys::mobile::EnvelopeEncryptedData = match serde_cbor::from_slice(slice) {
        Ok(v) => v,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_SERIALIZATION_FAILED,
                &format!("decode EED failed: {e}"),
            );
            return RN_ERROR_SERIALIZATION_FAILED;
        }
    };
    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let node_manager = match manager.read() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let plain = match node_manager.decrypt_network_data(&eed) {
        Ok(v) => v,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("decrypt_network_data failed: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };
    if !alloc_bytes(out_plain, out_len, &plain) {
        set_error(err, RN_ERROR_MEMORY_ALLOCATION, "alloc failed");
        return RN_ERROR_MEMORY_ALLOCATION;
    }
    0
}
fn parse_discovery_options(cbor: &[u8]) -> DiscoveryOptions {
    let mut opts = DiscoveryOptions::default();
    if let Ok(serde_cbor::Value::Map(m)) = serde_cbor::from_slice::<serde_cbor::Value>(cbor) {
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

// ffi_guard removed - violates design principles by preventing proper error handling flow

#[no_mangle]
pub unsafe extern "C" fn rn_discovery_new_with_multicast(
    keys: *mut c_void,
    options_cbor: *const u8,
    options_len: usize,
    out_discovery: *mut *mut c_void,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if options_cbor.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "options CBOR pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_discovery.is_null() {
        set_error(
            err,
            RN_ERROR_NULL_ARGUMENT,
            "output discovery pointer is null",
        );
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(keys_inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };
    let slice = std::slice::from_raw_parts(options_cbor, options_len);
    let opts = parse_discovery_options(slice);

    // Build local peer info from node keys and provided addresses if any
    let mut addresses: Vec<String> = Vec::new();
    if let Ok(serde_cbor::Value::Map(m)) = serde_cbor::from_slice::<serde_cbor::Value>(slice) {
        for (k, v) in m {
            if let serde_cbor::Value::Text(s) = k {
                if s == "local_addresses" {
                    if let serde_cbor::Value::Array(arr) = v {
                        for it in arr {
                            if let serde_cbor::Value::Text(a) = it {
                                addresses.push(a)
                            }
                        }
                    }
                }
            }
        }
    }

    let manager = match validate_node_manager(keys_inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let node_manager = match manager.read() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let node_pk = match node_manager.get_node_public_key() {
        Some(pk) => pk,
        None => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                "Node public key not available - call rn_keys_node_get_keystore_state first",
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    let local_peer = PeerInfo {
        public_key: node_pk,
        addresses,
    };
    let logger = keys_inner.logger.as_ref().clone();
    let disc = match runtime().block_on(MulticastDiscovery::new(local_peer, opts, logger)) {
        Ok(d) => Arc::new(d),
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to create discovery: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };
    let inner = DiscoveryInner {
        discovery: disc,
        events_tx: None,
    };
    let handle = FfiDiscoveryHandle {
        inner: Box::into_raw(Box::new(inner)),
    };
    *out_discovery = Box::into_raw(Box::new(handle)) as *mut c_void;
    0
}

#[no_mangle]
pub extern "C" fn rn_discovery_free(discovery: *mut c_void) {
    if discovery.is_null() {
        return;
    }
    unsafe {
        let h = Box::from_raw(discovery as *mut FfiDiscoveryHandle);
        if !h.inner.is_null() {
            let _ = Box::from_raw(h.inner);
        }
    }
}

fn with_discovery_inner<'a>(d: *mut c_void) -> Option<&'a mut DiscoveryInner> {
    if d.is_null() {
        return None;
    }
    unsafe {
        let h = &mut *(d as *mut FfiDiscoveryHandle);
        if h.inner.is_null() {
            None
        } else {
            Some(&mut *h.inner)
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rn_discovery_init(
    discovery: *mut c_void,
    options_cbor: *const u8,
    options_len: usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if discovery.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "discovery handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if options_cbor.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "options CBOR pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_discovery_inner(discovery) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid discovery handle");
        return RN_ERROR_INVALID_HANDLE;
    };
    let slice = std::slice::from_raw_parts(options_cbor, options_len);
    let opts = parse_discovery_options(slice);
    if let Err(e) = runtime().block_on(inner.discovery.init(opts)) {
        set_error(err, RN_ERROR_OPERATION_FAILED, &format!("init failed: {e}"));
        return RN_ERROR_OPERATION_FAILED;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_discovery_bind_events_to_transport(
    discovery: *mut c_void,
    transport: *mut c_void,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if discovery.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "discovery handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if transport.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "transport handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(disc) = with_discovery_inner(discovery) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid discovery handle");
        return RN_ERROR_INVALID_HANDLE;
    };
    let t = &mut *(transport as *mut FfiTransportHandle);
    if t.inner.is_null() {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid transport handle");
        return RN_ERROR_INVALID_HANDLE;
    }
    let tx = unsafe { &*t.inner }.events_tx.clone();
    disc.events_tx = Some(tx.clone());

    // Subscribe discovery events to emit into transport poll channel
    let emitter = tx.clone();
    let listener: runar_transporter::discovery::DiscoveryListener = Arc::new(move |ev| {
        let emitter = emitter.clone();
        Box::pin(async move {
            let mut map = std::collections::BTreeMap::new();
            match ev {
                DiscoveryEvent::Discovered(peer) => {
                    map.insert(
                        serde_cbor::Value::Text("type".into()),
                        serde_cbor::Value::Text("PeerDiscovered".into()),
                    );
                    map.insert(
                        serde_cbor::Value::Text("v".into()),
                        serde_cbor::Value::Integer(1),
                    );
                    let pi = serde_cbor::to_vec(&peer).unwrap_or_default();
                    map.insert(
                        serde_cbor::Value::Text("peer_info".into()),
                        serde_cbor::Value::Bytes(pi),
                    );
                }
                DiscoveryEvent::Updated(peer) => {
                    map.insert(
                        serde_cbor::Value::Text("type".into()),
                        serde_cbor::Value::Text("PeerUpdated".into()),
                    );
                    map.insert(
                        serde_cbor::Value::Text("v".into()),
                        serde_cbor::Value::Integer(1),
                    );
                    let pi = serde_cbor::to_vec(&peer).unwrap_or_default();
                    map.insert(
                        serde_cbor::Value::Text("peer_info".into()),
                        serde_cbor::Value::Bytes(pi),
                    );
                }
                DiscoveryEvent::Lost(node_id) => {
                    map.insert(
                        serde_cbor::Value::Text("type".into()),
                        serde_cbor::Value::Text("PeerLost".into()),
                    );
                    map.insert(
                        serde_cbor::Value::Text("v".into()),
                        serde_cbor::Value::Integer(1),
                    );
                    map.insert(
                        serde_cbor::Value::Text("peer_node_id".into()),
                        serde_cbor::Value::Text(node_id),
                    );
                }
            }
            let _ = emitter
                .send(serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap_or_default())
                .await;
        })
    });
    // Register subscription
    if let Err(e) = runtime().block_on(disc.discovery.subscribe(listener)) {
        set_error(
            err,
            RN_ERROR_OPERATION_FAILED,
            &format!("subscribe failed: {e}"),
        );
        return RN_ERROR_OPERATION_FAILED;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_discovery_start_announcing(
    discovery: *mut c_void,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if discovery.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "discovery handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_discovery_inner(discovery) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid discovery handle");
        return RN_ERROR_INVALID_HANDLE;
    };
    if let Err(e) = runtime().block_on(inner.discovery.start_announcing()) {
        set_error(
            err,
            RN_ERROR_OPERATION_FAILED,
            &format!("start_announcing failed: {e}"),
        );
        return RN_ERROR_OPERATION_FAILED;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_discovery_stop_announcing(
    discovery: *mut c_void,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if discovery.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "discovery handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_discovery_inner(discovery) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid discovery handle");
        return RN_ERROR_INVALID_HANDLE;
    };
    if let Err(e) = runtime().block_on(inner.discovery.stop_announcing()) {
        set_error(
            err,
            RN_ERROR_OPERATION_FAILED,
            &format!("stop_announcing failed: {e}"),
        );
        return RN_ERROR_OPERATION_FAILED;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_discovery_shutdown(discovery: *mut c_void, err: *mut RnError) -> i32 {
    // Validate parameters upfront - specific error messages
    if discovery.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "discovery handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_discovery_inner(discovery) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid discovery handle");
        return RN_ERROR_INVALID_HANDLE;
    };
    if let Err(e) = runtime().block_on(inner.discovery.shutdown()) {
        set_error(
            err,
            RN_ERROR_OPERATION_FAILED,
            &format!("shutdown failed: {e}"),
        );
        return RN_ERROR_OPERATION_FAILED;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_discovery_update_local_peer_info(
    discovery: *mut c_void,
    peer_info_cbor: *const u8,
    len: usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if discovery.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "discovery handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if peer_info_cbor.is_null() {
        set_error(
            err,
            RN_ERROR_NULL_ARGUMENT,
            "peer info CBOR pointer is null",
        );
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_discovery_inner(discovery) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid discovery handle");
        return RN_ERROR_INVALID_HANDLE;
    };
    let slice = std::slice::from_raw_parts(peer_info_cbor, len);
    let peer: PeerInfo = match serde_cbor::from_slice(slice) {
        Ok(p) => p,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_SERIALIZATION_FAILED,
                &format!("decode PeerInfo: {e}"),
            );
            return RN_ERROR_SERIALIZATION_FAILED;
        }
    };
    if let Err(e) = runtime().block_on(inner.discovery.update_local_peer_info(peer)) {
        set_error(
            err,
            RN_ERROR_OPERATION_FAILED,
            &format!("update_local_peer_info failed: {e}"),
        );
        return RN_ERROR_OPERATION_FAILED;
    }
    0
}
// Old implementation removed; now use the keys_new_impl wrapper below

#[no_mangle]
pub extern "C" fn rn_keys_free(keys: *mut c_void) {
    if keys.is_null() {
        return;
    }
    unsafe {
        let handle = Box::from_raw(keys as *mut FfiKeysHandle);
        if !handle.inner.is_null() {
            let _inner = Box::from_raw(handle.inner);
            // Dropped here
        }
    }
}

/// Internal helper that constructs a new keys handle and sets error on failure.
fn keys_new_impl(_err: *mut RnError) -> *mut c_void {
    let logger = Arc::new(Logger::new_root(Component::Keys));

    let inner = KeysInner {
        logger,
        mobile_key_manager: None,
        node_key_manager: None,

        local_node_info: Arc::new(ArcSwap::from_pointee(None)),
        device_keystore: None,
        persistence_dir: None,
        auto_persist: true,
    };
    let boxed = Box::new(inner);
    let handle = FfiKeysHandle {
        inner: Box::into_raw(boxed),
    };
    Box::into_raw(Box::new(handle)) as *mut c_void
}

/// C-conventional: writes handle to out param; returns 0 on success, non-zero on error.
#[no_mangle]
pub unsafe extern "C" fn rn_keys_new(out_keys: *mut *mut c_void, err: *mut RnError) -> i32 {
    let ptr = keys_new_impl(err);
    if ptr.is_null() {
        return 1;
    }
    unsafe {
        *out_keys = ptr;
    }
    0
}

/// Initialize FFI instance as mobile manager
/// Returns error if already initialized with different type
#[no_mangle]
pub unsafe extern "C" fn rn_keys_init_as_mobile(keys: *mut c_void, err: *mut RnError) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };

    // Check if already initialized with wrong type
    if inner.node_key_manager.is_some() {
        set_error(
            err,
            RN_ERROR_WRONG_MANAGER_TYPE,
            "already initialized as node manager",
        );
        return RN_ERROR_WRONG_MANAGER_TYPE;
    }

    // Check if already initialized as mobile
    if inner.mobile_key_manager.is_some() {
        return 0; // Already initialized correctly
    }

    // Initialize mobile manager
    match MobileKeyManager::new(inner.logger.clone()) {
        Ok(mut manager) => {
            // Apply existing configuration
            if let Some(ks) = &inner.device_keystore {
                manager.register_device_keystore(ks.clone());
            }
            if let Some(dir) = &inner.persistence_dir {
                manager.set_persistence_dir(dir.clone());
            }
            manager.enable_auto_persist(inner.auto_persist);

            inner.mobile_key_manager = Some(Arc::new(RwLock::new(manager)));
            0
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_KEYSTORE_FAILED,
                &format!("failed to create mobile manager: {e}"),
            );
            RN_ERROR_KEYSTORE_FAILED
        }
    }
}

/// Initialize FFI instance as node manager
/// Returns error if already initialized with different type
#[no_mangle]
pub unsafe extern "C" fn rn_keys_init_as_node(keys: *mut c_void, err: *mut RnError) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };

    // Check if already initialized with wrong type
    if inner.mobile_key_manager.is_some() {
        set_error(
            err,
            RN_ERROR_WRONG_MANAGER_TYPE,
            "already initialized as mobile manager",
        );
        return RN_ERROR_WRONG_MANAGER_TYPE;
    }

    // Check if already initialized as node
    if inner.node_key_manager.is_some() {
        return 0; // Already initialized correctly
    }

    // Initialize node manager following new lifecycle
    match NodeKeyManager::new(inner.logger.clone()) {
        Ok(mut manager) => {
            // Apply existing configuration first
            if let Some(ks) = &inner.device_keystore {
                manager.register_device_keystore(ks.clone());
            }
            if let Some(dir) = &inner.persistence_dir {
                manager.set_persistence_dir(dir.clone());
            }
            manager.enable_auto_persist(inner.auto_persist);

            // Follow new lifecycle: probe_and_load_state first, then generate_keys if needed
            match manager.probe_and_load_state() {
                Ok(ready) => {
                    if !ready {
                        // Generate keys only when needed
                        if let Err(e) = manager.generate_keys() {
                            set_error(
                                err,
                                RN_ERROR_OPERATION_FAILED,
                                &format!("Failed to generate keys: {e}"),
                            );
                            return RN_ERROR_OPERATION_FAILED;
                        }
                    }
                }
                Err(e) => {
                    set_error(
                        err,
                        RN_ERROR_OPERATION_FAILED,
                        &format!("Failed to probe and load state: {e}"),
                    );
                    return RN_ERROR_OPERATION_FAILED;
                }
            }

            inner.node_key_manager = Some(Arc::new(RwLock::new(manager)));
            0
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_KEYSTORE_FAILED,
                &format!("failed to create node manager: {e}"),
            );
            RN_ERROR_KEYSTORE_FAILED
        }
    }
}

fn with_keys_inner<'a>(keys: *mut c_void) -> Option<&'a mut KeysInner> {
    if keys.is_null() {
        return None;
    }
    unsafe {
        let handle = &mut *(keys as *mut FfiKeysHandle);
        if handle.inner.is_null() {
            None
        } else {
            Some(&mut *handle.inner)
        }
    }
}

#[no_mangle]
pub extern "C" fn rn_keys_node_get_public_key(
    keys: *mut c_void,
    out: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, 1, "keys handle is null");
        return 1;
    };
    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let node_manager = match manager.read() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let pk = match node_manager.get_node_public_key() {
        Some(pk) => pk,
        None => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                "Node keys not available - call rn_keys_node_get_keystore_state first",
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };
    if !alloc_bytes(out, out_len, &pk) {
        set_error(err, RN_ERROR_MEMORY_ALLOCATION, "invalid out pointers");
        return RN_ERROR_MEMORY_ALLOCATION;
    }
    0
}

#[no_mangle]
pub extern "C" fn rn_keys_node_get_agreement_public_key(
    keys: *mut c_void,
    out: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, 1, "keys handle is null");
        return 1;
    };
    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let node_manager = match manager.read() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let pk = match node_manager.get_node_agreement_public_key() {
        Ok(pk) => pk,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to get agreement public key: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };
    if !alloc_bytes(out, out_len, &pk) {
        set_error(err, 3, "invalid out pointers");
        return 3;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_get_node_id(
    keys: *mut c_void,
    out_id: *mut *mut c_char,
    out_has_id: *mut i32,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_id.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "out_id pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_has_id.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "out_has_id pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if err.is_null() {
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };
    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let node_manager = match manager.read() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    match node_manager.get_node_id() {
        Some(node_id) => {
            if !alloc_string_simple(out_id, &node_id) {
                set_error(err, 3, "invalid out pointers or string alloc failed");
                return 3;
            }
            unsafe {
                *out_has_id = 1;
            }
            0
        }
        None => {
            unsafe {
                *out_id = ptr::null_mut();
                *out_has_id = 0;
            }
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn rn_keys_node_generate_csr(
    keys: *mut c_void,
    out_st_cbor: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, 1, "keys handle is null");
        return 1;
    };
    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let mut node_manager = match manager.write() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let token = match node_manager.generate_csr() {
        Ok(t) => t,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to generate CSR: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };
    let cbor = match serde_cbor::to_vec(&token) {
        Ok(v) => v,
        Err(e) => {
            set_error(err, 2, &format!("Failed to encode SetupToken: {e}"));
            return 2;
        }
    };
    if !alloc_bytes(out_st_cbor, out_len, &cbor) {
        set_error(err, 3, "invalid out pointers");
        return 3;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_mobile_process_setup_token(
    keys: *mut c_void,
    st_cbor: *const u8,
    st_len: usize,
    out_ncm_cbor: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, 1, "keys handle is null");
        return 1;
    };
    if st_cbor.is_null() {
        set_error(err, 4, "st_cbor is null");
        return 4;
    }
    let slice = std::slice::from_raw_parts(st_cbor, st_len);
    let token: SetupToken = match serde_cbor::from_slice(slice) {
        Ok(t) => t,
        Err(e) => {
            set_error(err, 2, &format!("Failed to decode SetupToken: {e}"));
            return 2;
        }
    };
    let manager = match validate_mobile_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let mut mobile_manager = match manager.write() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };
    let msg = match mobile_manager.process_setup_token(&token) {
        Ok(m) => m,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to process setup token: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };
    let cbor = match serde_cbor::to_vec(&msg) {
        Ok(v) => v,
        Err(e) => {
            set_error(
                err,
                2,
                &format!("Failed to encode NodeCertificateMessage: {e}"),
            );
            return 2;
        }
    };
    if !alloc_bytes(out_ncm_cbor, out_len, &cbor) {
        set_error(err, 3, "invalid out pointers");
        return 3;
    }
    0
}

/// Convert enrollment response to certificate message
#[no_mangle]
pub unsafe extern "C" fn rn_keys_mobile_from_enroll_response(
    mobile: *mut c_void,
    response: *const u8,
    response_len: usize,
    out_cert_message: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if mobile.is_null()
        || response.is_null()
        || out_cert_message.is_null()
        || out_len.is_null()
        || err.is_null()
    {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(mobile) else {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "mobile handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    };

    let manager = match validate_mobile_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let mobile_manager = match manager.read() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    // Parse the enrollment response
    let response_data = std::slice::from_raw_parts(response, response_len);
    let enroll_response =
        match serde_cbor::from_slice::<runar_keys::ca_node_types::CsrEnrollResponse>(response_data)
        {
            Ok(resp) => resp,
            Err(e) => {
                set_error(
                    err,
                    RN_ERROR_MOBILE_RESPONSE_CONVERSION_FAILED,
                    &format!("Failed to parse enrollment response: {e}"),
                );
                return RN_ERROR_MOBILE_RESPONSE_CONVERSION_FAILED;
            }
        };

    // Convert to certificate message
    let cert_message = match mobile_manager.from_enroll_response(&enroll_response) {
        Ok(msg) => msg,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_MOBILE_RESPONSE_CONVERSION_FAILED,
                &format!("Failed to convert enrollment response: {e}"),
            );
            return RN_ERROR_MOBILE_RESPONSE_CONVERSION_FAILED;
        }
    };

    // Serialize to CBOR
    let cbor = match serde_cbor::to_vec(&cert_message) {
        Ok(v) => v,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_MOBILE_RESPONSE_CONVERSION_FAILED,
                &format!("Failed to serialize certificate message: {e}"),
            );
            return RN_ERROR_MOBILE_RESPONSE_CONVERSION_FAILED;
        }
    };

    if !alloc_bytes(out_cert_message, out_len, &cbor) {
        set_error(
            err,
            RN_ERROR_MEMORY_ALLOCATION,
            "failed to allocate memory for certificate message",
        );
        return RN_ERROR_MEMORY_ALLOCATION;
    }

    0
}

/// Convert renewal response to certificate message
#[no_mangle]
pub unsafe extern "C" fn rn_keys_mobile_from_renew_response(
    mobile: *mut c_void,
    response: *const u8,
    response_len: usize,
    out_cert_message: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if mobile.is_null()
        || response.is_null()
        || out_cert_message.is_null()
        || out_len.is_null()
        || err.is_null()
    {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(mobile) else {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "mobile handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    };

    let manager = match validate_mobile_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let mobile_manager = match manager.read() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    // Parse the renewal response
    let response_data = std::slice::from_raw_parts(response, response_len);
    let renew_response =
        match serde_cbor::from_slice::<runar_keys::ca_node_types::RenewResponse>(response_data) {
            Ok(resp) => resp,
            Err(e) => {
                set_error(
                    err,
                    RN_ERROR_MOBILE_RESPONSE_CONVERSION_FAILED,
                    &format!("Failed to parse renewal response: {e}"),
                );
                return RN_ERROR_MOBILE_RESPONSE_CONVERSION_FAILED;
            }
        };

    // Convert to certificate message
    let cert_message = match mobile_manager.from_renew_response(&renew_response) {
        Ok(msg) => msg,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_MOBILE_RESPONSE_CONVERSION_FAILED,
                &format!("Failed to convert renewal response: {e}"),
            );
            return RN_ERROR_MOBILE_RESPONSE_CONVERSION_FAILED;
        }
    };

    // Serialize to CBOR
    let cbor = match serde_cbor::to_vec(&cert_message) {
        Ok(v) => v,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_MOBILE_RESPONSE_CONVERSION_FAILED,
                &format!("Failed to serialize certificate message: {e}"),
            );
            return RN_ERROR_MOBILE_RESPONSE_CONVERSION_FAILED;
        }
    };

    if !alloc_bytes(out_cert_message, out_len, &cbor) {
        set_error(
            err,
            RN_ERROR_MEMORY_ALLOCATION,
            "failed to allocate memory for certificate message",
        );
        return RN_ERROR_MEMORY_ALLOCATION;
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_install_certificate(
    keys: *mut c_void,
    ncm_cbor: *const u8,
    ncm_len: usize,
    err: *mut RnError,
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, 1, "keys handle is null");
        return 1;
    };
    if ncm_cbor.is_null() {
        set_error(err, 4, "ncm_cbor is null");
        return 4;
    }
    let slice = std::slice::from_raw_parts(ncm_cbor, ncm_len);
    let msg: NodeCertificateMessage = match serde_cbor::from_slice(slice) {
        Ok(m) => m,
        Err(e) => {
            set_error(
                err,
                2,
                &format!("Failed to decode NodeCertificateMessage: {e}"),
            );
            return 2;
        }
    };
    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let mut node_manager = match manager.write() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    if let Err(e) = node_manager.install_certificate(msg) {
        set_error(
            err,
            RN_ERROR_OPERATION_FAILED,
            &format!("Failed to install certificate: {e}"),
        );
        return RN_ERROR_OPERATION_FAILED;
    }
    0
}

// Removed legacy state import/export APIs (no backwards compatibility)

#[no_mangle]
pub unsafe extern "C" fn rn_transport_new_with_keys(
    keys: *mut c_void,
    options_cbor: *const u8,
    options_len: usize,
    out_transport: *mut *mut c_void,
    err: *mut RnError,
) -> i32 {
    if keys.is_null() || options_cbor.is_null() || out_transport.is_null() {
        set_error(err, 1, "null argument");
        return 1;
    }
    // Read keys
    let Some(keys_inner) = with_keys_inner(keys) else {
        set_error(err, 1, "invalid keys handle");
        return 1;
    };
    // Parse options from CBOR map { bind_addr, timeouts, max_message_size }
    let slice = std::slice::from_raw_parts(options_cbor, options_len);
    let mut options = QuicTransportOptions::new();
    // Minimal: expect a CBOR map with optional fields
    let value: serde_cbor::Value = match serde_cbor::from_slice(slice) {
        Ok(v) => v,
        Err(e) => {
            set_error(err, 2, &format!("Failed to decode options: {e}"));
            return 2;
        }
    };
    if let serde_cbor::Value::Map(m) = value {
        for (k, v) in m {
            if let serde_cbor::Value::Text(s) = k {
                match s.as_str() {
                    "bind_addr" => {
                        if let serde_cbor::Value::Text(addr) = v {
                            if let Ok(sock) = addr.parse() {
                                options = options.with_bind_addr(sock);
                            }
                        }
                    }
                    "handshake_timeout_ms" => {
                        if let serde_cbor::Value::Integer(ms) = v {
                            if ms > 0 {
                                options = options.with_handshake_response_timeout(
                                    std::time::Duration::from_millis(ms as u64),
                                );
                            }
                        }
                    }
                    "open_stream_timeout_ms" => {
                        if let serde_cbor::Value::Integer(ms) = v {
                            if ms > 0 {
                                options = options.with_open_stream_timeout(
                                    std::time::Duration::from_millis(ms as u64),
                                );
                            }
                        }
                    }
                    "max_message_size" => {
                        if let serde_cbor::Value::Integer(sz) = v {
                            if sz > 0 {
                                options = options.with_max_message_size(sz as usize);
                            }
                        }
                    }
                    "response_cache_ttl_ms" => {
                        if let serde_cbor::Value::Integer(ms) = v {
                            if ms > 0 {
                                options = options.with_response_cache_ttl(
                                    std::time::Duration::from_millis(ms as u64),
                                );
                            }
                        }
                    }
                    "max_request_retries" => {
                        if let serde_cbor::Value::Integer(n) = v {
                            if n >= 0 {
                                options = options.with_max_request_retries(n as u32);
                            }
                        }
                    }
                    "log_level" => {
                        if let serde_cbor::Value::Integer(lvl) = v {
                            let lf = match lvl {
                                0 => log::LevelFilter::Off,
                                1 => log::LevelFilter::Error,
                                2 => log::LevelFilter::Warn,
                                3 => log::LevelFilter::Info,
                                4 => log::LevelFilter::Debug,
                                _ => log::LevelFilter::Info,
                            };
                            log::set_max_level(lf);
                        }
                    }
                    // Inline certs (discouraged in production; for testing)
                    "cert_chain_der" => {
                        if let serde_cbor::Value::Array(arr) = v {
                            let mut certs = Vec::new();
                            for item in arr {
                                if let serde_cbor::Value::Bytes(b) = item {
                                    certs.push(rustls_pki_types::CertificateDer::from(b));
                                }
                            }
                            options = options.with_certificates(certs);
                        }
                    }
                    "private_key_der" => {
                        if let serde_cbor::Value::Bytes(b) = v {
                            // Assume PKCS#8 for FFI simplicity
                            let pk = rustls_pki_types::PrivatePkcs8KeyDer::from(b);
                            options = options.with_private_key(pk.into());
                        }
                    }
                    "root_certs_der" => {
                        if let serde_cbor::Value::Array(arr) = v {
                            let mut certs = Vec::new();
                            for item in arr {
                                if let serde_cbor::Value::Bytes(b) = item {
                                    certs.push(rustls_pki_types::CertificateDer::from(b));
                                }
                            }
                            options = options.with_root_certificates(certs);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    // Wire key manager and local pk/logger
    let manager = match validate_node_manager(keys_inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    // Node ID is now available in the logger from keys_inner
    let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
    let _ = rx; // Suppress unused variable warning - used in future implementation

    // Build callbacks to emit events
    let pc_tx = tx.clone();
    let pc_cb: runar_transporter::transport::PeerConnectedCallback =
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
                    serde_cbor::Value::Text("peer_node_id".into()),
                    serde_cbor::Value::Text(peer_id),
                );
                let ni = serde_cbor::to_vec(&node_info).unwrap_or_default();
                map.insert(
                    serde_cbor::Value::Text("node_info".into()),
                    serde_cbor::Value::Bytes(ni),
                );
                let _ = pc_tx
                    .send(serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap_or_default())
                    .await;
            })
        });

    let pd_tx = tx.clone();
    let pd_cb: runar_transporter::transport::PeerDisconnectedCallback = Arc::new(move |peer_id| {
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
            let _ = pd_tx
                .send(serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap_or_default())
                .await;
        })
    });

    let req_tx = tx.clone();
    let pending: Arc<
        Mutex<
            std::collections::HashMap<
                String,
                oneshot::Sender<runar_transporter::transport::NetworkMessage>,
            >,
        >,
    > = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let pending_cb = pending.clone();
    let rq_cb: runar_transporter::transport::RequestCallback = Arc::new(move |req| {
        let req_tx = req_tx.clone();
        let pending_cb = pending_cb.clone();
        Box::pin(async move {
            let request_id = uuid::Uuid::new_v4().to_string();
            let (tx_resp, rx_resp) = oneshot::channel();
            pending_cb.lock().await.insert(request_id.clone(), tx_resp);

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
                serde_cbor::Value::Text(request_id),
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
                serde_cbor::Value::Text("profile_public_key".into()),
                serde_cbor::Value::Bytes(
                    req.payload
                        .profile_public_keys
                        .first()
                        .cloned()
                        .unwrap_or_default(),
                ),
            );
            let _ = req_tx
                .send(serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap_or_default())
                .await;

            match rx_resp.await {
                Ok(resp) => Ok(resp),
                Err(_) => Ok(runar_transporter::transport::NetworkMessage {
                    source_node_id: String::new(),
                    destination_node_id: String::new(),
                    message_type: 5, // MESSAGE_TYPE_RESPONSE
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

    let ev_tx = tx.clone();
    let ev_cb: runar_transporter::transport::EventCallback = Arc::new(move |ev| {
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
            let _ = ev_tx
                .send(serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap_or_default())
                .await;
            Ok(())
        })
    });

    // Require local NodeInfo to be set before initializing transport
    if keys_inner.local_node_info.load().as_ref().is_none() {
        set_error(
            err,
            1,
            "local NodeInfo is required; call rn_keys_set_local_node_info() before creating the transport",
        );
        return 1;
    }
    // Get node public key for transport
    let node_public_key = {
        let mgr = match manager.read() {
            Ok(mgr) => mgr,
            Err(_) => {
                set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
                return RN_ERROR_LOCK_ERROR;
            }
        };
        mgr.get_node_public_key()
    };

    // Wire callbacks and key manager
    {
        let node_manager_for_transport = manager.clone();
        let logger = keys_inner.logger.clone();
        options = options
            .with_key_manager(node_manager_for_transport)
            .with_local_node_public_key(node_public_key.unwrap())
            .with_logger(logger)
            .with_peer_connected_callback(pc_cb)
            .with_peer_disconnected_callback(pd_cb)
            .with_request_callback(rq_cb)
            .with_event_callback(ev_cb);
    }

    // Provide NodeInfo getter from the local holder (no FFI callbacks)
    let holder = keys_inner.local_node_info.clone();
    let get_local_node_info_cb: runar_transporter::transport::GetLocalNodeInfoCallback =
        Arc::new(move || {
            let holder = holder.clone();
            Box::pin(async move {
                let cur = holder.load();
                match cur.as_ref() {
                    Some(info) => Ok(info.clone()),
                    None => Err(anyhow::anyhow!("local NodeInfo not set")),
                }
            })
        });
    options = options.with_get_local_node_info(get_local_node_info_cb);

    // Configure mTLS - get certificate configuration from key manager
    let node_manager = match manager.read() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(
                err,
                RN_ERROR_LOCK_ERROR,
                "failed to acquire lock for certificate config",
            );
            return RN_ERROR_LOCK_ERROR;
        }
    };

    // Get certificate configuration for mTLS
    let cert_config = match node_manager.get_quic_certificate_config() {
        Ok(config) => config,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to get certificate config: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Get node public key for local identity
    let node_public_key = match node_manager.get_node_public_key() {
        Some(pk) => pk,
        None => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                "Node public key not available",
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Extract CA certificate from certificate chain (last certificate in chain)
    let ca_cert = match cert_config.certificate_chain.last() {
        Some(cert) => cert,
        None => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                "CA certificate not found in certificate chain",
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Configure mTLS options
    options = options
        .with_key_manager(manager.clone())
        .with_root_certificates(vec![ca_cert.clone()])
        .with_local_node_public_key(node_public_key);

    // Configure required callbacks for transport to work
    let req_tx = tx.clone();
    let pending: Arc<
        Mutex<
            std::collections::HashMap<
                String,
                oneshot::Sender<runar_transporter::transport::NetworkMessage>,
            >,
        >,
    > = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let pending_cb = pending.clone();
    let request_callback: runar_transporter::transport::RequestCallback = Arc::new(move |req| {
        let req_tx = req_tx.clone();
        let pending_cb = pending_cb.clone();
        Box::pin(async move {
            let request_id = uuid::Uuid::new_v4().to_string();
            let (tx_resp, rx_resp) = oneshot::channel();
            pending_cb.lock().await.insert(request_id.clone(), tx_resp);

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
                serde_cbor::Value::Text(request_id),
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
                serde_cbor::Value::Text("profile_public_key".into()),
                serde_cbor::Value::Bytes(
                    req.payload
                        .profile_public_keys
                        .first()
                        .cloned()
                        .unwrap_or_default(),
                ),
            );
            let _ = req_tx
                .send(serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap_or_default())
                .await;

            match rx_resp.await {
                Ok(resp) => Ok(resp),
                Err(_) => Ok(runar_transporter::transport::NetworkMessage {
                    source_node_id: String::new(),
                    destination_node_id: String::new(),
                    message_type: 5, // MESSAGE_TYPE_RESPONSE
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

    let ev_tx = tx.clone();
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
            let _ = ev_tx
                .send(serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap_or_default())
                .await;
            Ok(())
        })
    });

    let pc_tx = tx.clone();
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
                    serde_cbor::Value::Text("peer_node_id".into()),
                    serde_cbor::Value::Text(peer_id),
                );
                let ni = serde_cbor::to_vec(&node_info).unwrap_or_default();
                map.insert(
                    serde_cbor::Value::Text("node_info".into()),
                    serde_cbor::Value::Bytes(ni),
                );
                let _ = pc_tx
                    .send(serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap_or_default())
                    .await;
            })
        });

    let pd_tx = tx.clone();
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
                let _ = pd_tx
                    .send(serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap_or_default())
                    .await;
            })
        });

    let logger = Arc::new(runar_common::logging::Logger::new_root(
        runar_common::logging::Component::Custom("ffi_transport"),
    ));

    options = options
        .with_request_callback(request_callback)
        .with_event_callback(event_callback)
        .with_peer_connected_callback(peer_connected_callback)
        .with_peer_disconnected_callback(peer_disconnected_callback)
        .with_logger(logger);

    // Construct transport
    let transport = match QuicTransport::new(options) {
        Ok(t) => Arc::new(t),
        Err(e) => {
            set_error(err, 2, &format!("Failed to create transport: {e}"));
            return 2;
        }
    };
    let inner = TransportInner {
        transport,
        events_tx: tx,
        events_rx: Mutex::new(rx),
        pending,
        local_node_info: keys_inner.local_node_info.clone(),
    };
    let handle = FfiTransportHandle {
        inner: Box::into_raw(Box::new(inner)),
    };
    *out_transport = Box::into_raw(Box::new(handle)) as *mut c_void;
    0
}

#[no_mangle]
pub extern "C" fn rn_transport_free(transport: *mut c_void) {
    if transport.is_null() {
        return;
    }
    unsafe {
        let handle = Box::from_raw(transport as *mut FfiTransportHandle);
        if !handle.inner.is_null() {
            let _ = Box::from_raw(handle.inner);
        }
    }
}
// Shared runtime (Option C)
static RUNTIME: OnceCell<Runtime> = OnceCell::new();
fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| Runtime::new().expect("tokio runtime"))
}

#[no_mangle]
pub unsafe extern "C" fn rn_transport_start(transport: *mut c_void, err: *mut RnError) -> i32 {
    if transport.is_null() {
        set_error(err, 1, "transport is null");
        return 1;
    }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() {
        set_error(err, 1, "invalid transport handle");
        return 1;
    }
    let t = (&*handle.inner).transport.clone();
    let res = runtime().block_on(async move { Arc::clone(&t).start().await });
    if let Err(e) = res {
        set_error(err, 2, &format!("Failed to start transport: {e}"));
        return 2;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_transport_poll_event(
    transport: *mut c_void,
    out_event: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if transport.is_null() {
        set_error(err, 1, "transport is null");
        return 1;
    }
    if out_event.is_null() || out_len.is_null() {
        set_error(err, 1, "null out");
        return 1;
    }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() {
        set_error(err, 1, "invalid transport handle");
        return 1;
    }
    let inner = &*handle.inner;
    let mut rx = runtime().block_on(inner.events_rx.lock());
    match rx.try_recv() {
        Ok(buf) => {
            if !alloc_bytes(out_event, out_len, &buf) {
                set_error(err, 3, "alloc failed");
                return 3;
            }
            0
        }
        Err(mpsc::error::TryRecvError::Empty) => {
            *out_event = std::ptr::null_mut();
            *out_len = 0;
            0
        }
        Err(_) => {
            set_error(err, 2, "event channel closed");
            2
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rn_transport_connect_peer(
    transport: *mut c_void,
    peer_info_cbor: *const u8,
    len: usize,
    err: *mut RnError,
) -> i32 {
    if transport.is_null() || peer_info_cbor.is_null() {
        set_error(err, 1, "null argument");
        return 1;
    }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() {
        set_error(err, 1, "invalid transport handle");
        return 1;
    }
    let slice = std::slice::from_raw_parts(peer_info_cbor, len);
    let peer: PeerInfo = match serde_cbor::from_slice(slice) {
        Ok(p) => p,
        Err(e) => {
            set_error(err, 2, &format!("decode PeerInfo: {e}"));
            return 2;
        }
    };
    let t = (&*handle.inner).transport.clone();
    let res = runtime().block_on(async move { Arc::clone(&t).connect_peer(peer).await });
    if let Err(e) = res {
        set_error(err, 2, &format!("connect_peer failed: {e}"));
        return 2;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_transport_disconnect_peer(
    transport: *mut c_void,
    peer_node_id: *const c_char,
    err: *mut RnError,
) -> i32 {
    if transport.is_null() || peer_node_id.is_null() {
        set_error(err, 1, "null argument");
        return 1;
    }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() {
        set_error(err, 1, "invalid transport handle");
        return 1;
    }
    let id = match std::ffi::CStr::from_ptr(peer_node_id).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_error(err, 2, "invalid utf8");
            return 2;
        }
    };
    let res = runtime().block_on((&*handle.inner).transport.disconnect(&id));
    if let Err(e) = res {
        set_error(err, 2, &format!("disconnect failed: {e}"));
        return 2;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_transport_is_connected(
    transport: *mut c_void,
    peer_node_id: *const c_char,
    out_connected: *mut bool,
    err: *mut RnError,
) -> i32 {
    if transport.is_null() || peer_node_id.is_null() || out_connected.is_null() {
        set_error(err, 1, "null argument");
        return 1;
    }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() {
        set_error(err, 1, "invalid transport handle");
        return 1;
    }
    let id = match std::ffi::CStr::from_ptr(peer_node_id).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_error(err, 2, "invalid utf8");
            return 2;
        }
    };
    let r = runtime().block_on((&*handle.inner).transport.is_connected(&id));
    *out_connected = r;
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_transport_update_local_node_info(
    transport: *mut c_void,
    node_info_cbor: *const u8,
    len: usize,
    err: *mut RnError,
) -> i32 {
    if transport.is_null() || node_info_cbor.is_null() {
        set_error(err, 1, "null argument");
        return 1;
    }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() {
        set_error(err, 1, "invalid transport handle");
        return 1;
    }
    let slice = std::slice::from_raw_parts(node_info_cbor, len);
    let node_info: NodeInfo = match serde_cbor::from_slice(slice) {
        Ok(v) => v,
        Err(e) => {
            set_error(err, 2, &format!("decode NodeInfo: {e}"));
            return 2;
        }
    };
    // First update the shared holder so subsequent reads see the latest
    let inner_ref = unsafe { &*handle.inner };
    inner_ref
        .local_node_info
        .store(Arc::new(Some(node_info.clone())));
    // Then notify transport runtime (now emits latest info)
    let res = runtime().block_on((&*handle.inner).transport.update_peers(node_info));
    if let Err(e) = res {
        set_error(err, 2, &format!("update_peers failed: {e}"));
        return 2;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_transport_request(
    transport: *mut c_void,
    request_cbor: *const u8,
    request_len: usize,
    err: *mut RnError,
) -> i32 {
    if transport.is_null() || request_cbor.is_null() {
        set_error(err, 1, "null argument");
        return 1;
    }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() {
        set_error(err, 1, "invalid transport handle");
        return 1;
    }

    // Deserialize CBOR request parameters
    let request: TransportRequestParams =
        match serde_cbor::from_slice(std::slice::from_raw_parts(request_cbor, request_len)) {
            Ok(r) => r,
            Err(_) => {
                set_error(err, 2, "invalid request CBOR");
                return 2;
            }
        };
    let t = (&*handle.inner).transport.clone();
    let events = (&*handle.inner).events_tx.clone();
    runtime().spawn(async move {
        match t
            .request(
                &request.path,
                &request.correlation_id,
                request.payload,
                &request.dest_peer_id,
                request.network_public_key,
                request.profile_public_keys,
            )
            .await
        {
            Ok(resp) => {
                let mut map = std::collections::BTreeMap::new();
                map.insert(
                    serde_cbor::Value::Text("type".into()),
                    serde_cbor::Value::Text("ResponseReceived".into()),
                );
                map.insert(
                    serde_cbor::Value::Text("v".into()),
                    serde_cbor::Value::Integer(1),
                );
                map.insert(
                    serde_cbor::Value::Text("correlation_id".into()),
                    serde_cbor::Value::Text(request.correlation_id),
                );
                map.insert(
                    serde_cbor::Value::Text("payload".into()),
                    serde_cbor::Value::Bytes(resp),
                );
                let _ = events
                    .send(serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap_or_default())
                    .await;
            }
            Err(_e) => {}
        }
    });
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_transport_publish(
    transport: *mut c_void,
    publish_cbor: *const u8,
    publish_len: usize,
    err: *mut RnError,
) -> i32 {
    if transport.is_null() || publish_cbor.is_null() {
        set_error(err, 1, "null argument");
        return 1;
    }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() {
        set_error(err, 1, "invalid transport handle");
        return 1;
    }

    // Deserialize CBOR publish parameters
    let publish: TransportPublishParams =
        match serde_cbor::from_slice(std::slice::from_raw_parts(publish_cbor, publish_len)) {
            Ok(p) => p,
            Err(_) => {
                set_error(err, 2, "invalid publish CBOR");
                return 2;
            }
        };
    let t = (&*handle.inner).transport.clone();
    runtime().spawn(async move {
        let _ = t
            .publish(
                &publish.path,
                &publish.correlation_id,
                publish.payload,
                &publish.dest_peer_id,
                publish.network_public_key,
            )
            .await;
    });
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_transport_complete_request(
    transport: *mut c_void,
    complete_cbor: *const u8,
    complete_len: usize,
    err: *mut RnError,
) -> i32 {
    if transport.is_null() || complete_cbor.is_null() {
        set_error(err, 1, "null argument");
        return 1;
    }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() {
        set_error(err, 1, "invalid transport handle");
        return 1;
    }

    // Deserialize CBOR complete request parameters
    let complete: TransportCompleteRequestParams =
        match serde_cbor::from_slice(std::slice::from_raw_parts(complete_cbor, complete_len)) {
            Ok(c) => c,
            Err(_) => {
                set_error(err, 2, "invalid complete request CBOR");
                return 2;
            }
        };
    let mut map = runtime().block_on((&*handle.inner).pending.lock());
    if let Some(sender) = map.remove(&complete.request_id) {
        let _ = sender.send(runar_transporter::transport::NetworkMessage {
            source_node_id: String::new(),
            destination_node_id: String::new(),
            message_type: 5, // MESSAGE_TYPE_RESPONSE
            payload: runar_transporter::transport::NetworkMessagePayloadItem {
                path: String::new(),
                payload_bytes: complete.response_payload,
                correlation_id: String::new(),
                network_public_key: None,
                profile_public_keys: complete.profile_public_keys,
            },
        });
        0
    } else {
        set_error(err, 2, "unknown request_id");
        2
    }
}
#[no_mangle]
pub unsafe extern "C" fn rn_transport_stop(transport: *mut c_void, err: *mut RnError) -> i32 {
    if transport.is_null() {
        set_error(err, 1, "transport is null");
        return 1;
    }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() {
        set_error(err, 1, "invalid transport handle");
        return 1;
    }
    let res = runtime().block_on((&*handle.inner).transport.stop());
    if let Err(e) = res {
        set_error(err, 2, &format!("Failed to stop transport: {e}"));
        return 2;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_transport_local_addr(
    transport: *mut c_void,
    out_str: *mut *mut c_char,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if transport.is_null() {
        set_error(err, 1, "transport is null");
        return 1;
    }
    if out_str.is_null() || out_len.is_null() {
        set_error(err, 1, "null out");
        return 1;
    }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() {
        set_error(err, 1, "invalid transport handle");
        return 1;
    }
    let addr = (&*handle.inner).transport.get_local_address();
    if !alloc_string(out_str, out_len, &addr) {
        set_error(err, 3, "alloc failed");
        return 3;
    }
    0
}

// Tests moved to runar-ffi/tests/ffi_transport_test.rs

#[no_mangle]
pub unsafe extern "C" fn rn_keys_ensure_symmetric_key(
    keys: *mut c_void,
    key_name: *const c_char,
    out_key: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if key_name.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "key name pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_key.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output key pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_len.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output length pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };
    let key_name_str = match std::ffi::CStr::from_ptr(key_name).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error(err, RN_ERROR_INVALID_UTF8, "invalid utf8 key_name");
            return RN_ERROR_INVALID_UTF8;
        }
    };
    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let mut node_manager = match manager.write() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let key = match node_manager.ensure_symmetric_key(key_name_str) {
        Ok(k) => k,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("ensure_symmetric_key failed: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };
    if !alloc_bytes(out_key, out_len, &key) {
        set_error(err, RN_ERROR_MEMORY_ALLOCATION, "alloc failed");
        return RN_ERROR_MEMORY_ALLOCATION;
    }
    0
}

// ============================================================================
// NEW DUAL-ROLE NODEKEYMANAGER FFI FUNCTIONS
// ============================================================================

/// Check if NodeKeyManager has keys (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_has_keys_v2(
    keys: *mut c_void,
    out_has_keys: *mut i32,
    err: *mut RnError,
) -> i32 {
    if keys.is_null() || out_has_keys.is_null() || err.is_null() {
        return -1;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };

    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let mut node_manager = match manager.write() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    match node_manager.probe_and_load_state() {
        Ok(ready) => {
            unsafe {
                *out_has_keys = if ready { 1 } else { 0 };
            }
            0
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to check key state: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// Generate keys for NodeKeyManager (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_generate_keys_v2(
    keys: *mut c_void,
    err: *mut RnError,
) -> i32 {
    if keys.is_null() || err.is_null() {
        return -1;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };

    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let mut node_manager = match manager.write() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    match node_manager.generate_keys() {
        Ok(_) => 0,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to generate keys: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

// ============================================================================
// CA NODE FFI FUNCTIONS (NEW)
// ============================================================================

/// Create new CA Node (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_keys_ca_node_new(
    logger: *mut c_void,
    out_ca_node: *mut *mut c_void,
    err: *mut RnError,
) -> i32 {
    if logger.is_null() || out_ca_node.is_null() || err.is_null() {
        return -1;
    }

    let _logger = unsafe { &*(logger as *const Arc<Logger>) };

    // Create a proper CA Node with valid certificates
    // This follows the design pattern from the tests
    let temp_key = match EcdsaKeyPair::new() {
        Ok(key) => key,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to create temporary key: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Create temporary certificates using CertificateAuthority
    // These will be replaced by install_issuing_ca with the real certificates
    let temp_ca_authority =
        match runar_keys::certificate::CertificateAuthority::new("CN=Temp CA,O=Temp,C=US") {
            Ok(ca) => ca,
            Err(e) => {
                set_error(
                    err,
                    RN_ERROR_OPERATION_FAILED,
                    &format!("Failed to create temporary CA: {e}"),
                );
                return RN_ERROR_OPERATION_FAILED;
            }
        };

    let temp_cert = temp_ca_authority.ca_certificate().clone();
    let temp_root_cert = temp_ca_authority.ca_certificate().clone();

    let ca_node = CANode::new(
        temp_key,
        temp_cert,
        temp_root_cert,
        "uninitialized".to_string(), // Will be updated by install_issuing_ca
    );

    let boxed_ca_node = Box::new(ca_node);
    unsafe {
        *out_ca_node = Box::into_raw(boxed_ca_node) as *mut c_void;
    }

    0
}

/// Free CA Node (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_keys_ca_node_free(ca_node: *mut c_void) {
    if !ca_node.is_null() {
        let _ = Box::from_raw(ca_node as *mut CANode);
    }
}

/// Install issuing CA (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_keys_ca_node_install_issuing_ca(
    ca_node: *mut c_void,
    issuing_ca_key: *const u8,
    key_len: usize,
    issuing_ca_cert: *const u8,
    cert_len: usize,
    root_ca_cert: *const u8,
    root_cert_len: usize,
    ea_public_keys: *const u8,
    ea_keys_len: usize,
    err: *mut RnError,
) -> i32 {
    if ca_node.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let ca_node = &mut *(ca_node as *mut CANode);

    // Parse the issuing CA key using runar-keys deserialization
    let key_data = std::slice::from_raw_parts(issuing_ca_key, key_len);
    let issuing_ca_key_pair = match serde_cbor::from_slice::<EcdsaKeyPair>(key_data) {
        Ok(key_pair) => key_pair,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to parse issuing CA key: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Parse the issuing CA certificate
    let cert_data = std::slice::from_raw_parts(issuing_ca_cert, cert_len);
    let issuing_ca_cert = match X509Certificate::from_der(cert_data.to_vec()) {
        Ok(cert) => cert,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to parse issuing CA certificate: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Parse the root CA certificate
    let root_cert_data = std::slice::from_raw_parts(root_ca_cert, root_cert_len);
    let root_ca_cert = match X509Certificate::from_der(root_cert_data.to_vec()) {
        Ok(cert) => cert,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to parse root CA certificate: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Parse enrollment authority public keys
    let ea_keys_data = std::slice::from_raw_parts(ea_public_keys, ea_keys_len);
    let ea_public_keys_vec = match serde_cbor::from_slice::<Vec<Vec<u8>>>(ea_keys_data) {
        Ok(keys) => keys,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to parse EA public keys: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Install the issuing CA
    match ca_node.install_issuing_ca(
        issuing_ca_key_pair,
        issuing_ca_cert,
        root_ca_cert,
        ea_public_keys_vec,
    ) {
        Ok(()) => 0,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to install issuing CA: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// Configure enrollment authority (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_keys_ca_node_configure_enrollment_authority(
    ca_node: *mut c_void,
    ea_public_keys: *const u8,
    keys_len: usize,
    err: *mut RnError,
) -> i32 {
    if ca_node.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let ca_node = &mut *(ca_node as *mut CANode);

    // Parse enrollment authority public keys
    let ea_keys_data = std::slice::from_raw_parts(ea_public_keys, keys_len);
    let ea_public_keys_vec = match serde_cbor::from_slice::<Vec<Vec<u8>>>(ea_keys_data) {
        Ok(keys) => keys,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to parse EA public keys: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Configure enrollment authorities
    match ca_node.configure_enrollment_authority(ea_public_keys_vec) {
        Ok(()) => 0,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to configure enrollment authority: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// Handle enrollment request (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_keys_ca_node_handle_enroll(
    ca_node: *mut c_void,
    request: *const u8,
    request_len: usize,
    remote_addr: *const c_char,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if ca_node.is_null()
        || request.is_null()
        || remote_addr.is_null()
        || out_response.is_null()
        || out_len.is_null()
        || err.is_null()
    {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let ca_node = &mut *(ca_node as *mut CANode);

    // Parse remote address
    let remote_addr_str = match std::ffi::CStr::from_ptr(remote_addr).to_str() {
        Ok(addr) => addr,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_INVALID_UTF8,
                &format!("Invalid remote address: {e}"),
            );
            return RN_ERROR_INVALID_UTF8;
        }
    };

    // Parse the enrollment request
    let request_data = std::slice::from_raw_parts(request, request_len);
    let enroll_request = match serde_cbor::from_slice::<CsrEnrollRequest>(request_data) {
        Ok(req) => req,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to parse enrollment request: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Handle the enrollment request
    match ca_node.handle_enroll(enroll_request, remote_addr_str) {
        Ok(response) => {
            // Serialize the response
            match serde_cbor::to_vec(&response) {
                Ok(response_data) => {
                    let response_ptr = libc::malloc(response_data.len()) as *mut u8;
                    if response_ptr.is_null() {
                        set_error(
                            err,
                            RN_ERROR_MEMORY_ALLOCATION,
                            "Failed to allocate memory for response",
                        );
                        return RN_ERROR_MEMORY_ALLOCATION;
                    }

                    std::ptr::copy_nonoverlapping(
                        response_data.as_ptr(),
                        response_ptr,
                        response_data.len(),
                    );
                    *out_response = response_ptr;
                    *out_len = response_data.len();
                    0
                }
                Err(e) => {
                    set_error(
                        err,
                        RN_ERROR_OPERATION_FAILED,
                        &format!("Failed to serialize response: {e}"),
                    );
                    RN_ERROR_OPERATION_FAILED
                }
            }
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Enrollment failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// Handle renewal request (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_keys_ca_node_handle_renew(
    ca_node: *mut c_void,
    request: *const u8,
    request_len: usize,
    peer_cert: *const u8,
    cert_len: usize,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if ca_node.is_null()
        || request.is_null()
        || peer_cert.is_null()
        || out_response.is_null()
        || out_len.is_null()
        || err.is_null()
    {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let ca_node = &mut *(ca_node as *mut CANode);

    // Parse the renewal request
    let request_data = std::slice::from_raw_parts(request, request_len);
    let renew_request = match serde_cbor::from_slice::<RenewRequest>(request_data) {
        Ok(req) => req,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to parse renewal request: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Parse peer certificate
    let peer_cert_data = std::slice::from_raw_parts(peer_cert, cert_len);

    // Handle the renewal request
    match ca_node.handle_renew(renew_request, peer_cert_data) {
        Ok(response) => {
            // Serialize the response
            match serde_cbor::to_vec(&response) {
                Ok(response_data) => {
                    let response_ptr = libc::malloc(response_data.len()) as *mut u8;
                    if response_ptr.is_null() {
                        set_error(
                            err,
                            RN_ERROR_MEMORY_ALLOCATION,
                            "Failed to allocate memory for response",
                        );
                        return RN_ERROR_MEMORY_ALLOCATION;
                    }

                    std::ptr::copy_nonoverlapping(
                        response_data.as_ptr(),
                        response_ptr,
                        response_data.len(),
                    );
                    *out_response = response_ptr;
                    *out_len = response_data.len();
                    0
                }
                Err(e) => {
                    set_error(
                        err,
                        RN_ERROR_OPERATION_FAILED,
                        &format!("Failed to serialize response: {e}"),
                    );
                    RN_ERROR_OPERATION_FAILED
                }
            }
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Renewal failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// Handle revocation request (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_keys_ca_node_handle_revoke(
    ca_node: *mut c_void,
    request: *const u8,
    request_len: usize,
    admin_ski: *const c_char,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if ca_node.is_null()
        || request.is_null()
        || admin_ski.is_null()
        || out_response.is_null()
        || out_len.is_null()
        || err.is_null()
    {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let ca_node = &mut *(ca_node as *mut CANode);

    // Parse admin SKI
    let admin_ski_str = match std::ffi::CStr::from_ptr(admin_ski).to_str() {
        Ok(ski) => ski,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_INVALID_UTF8,
                &format!("Invalid admin SKI: {e}"),
            );
            return RN_ERROR_INVALID_UTF8;
        }
    };

    // Parse the revocation request
    let request_data = std::slice::from_raw_parts(request, request_len);
    let revoke_request = match serde_cbor::from_slice::<RevokeRequest>(request_data) {
        Ok(req) => req,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to parse revocation request: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Handle the revocation request
    match ca_node.handle_revoke(revoke_request, admin_ski_str) {
        Ok(response) => {
            // Serialize the response
            match serde_cbor::to_vec(&response) {
                Ok(response_data) => {
                    let response_ptr = libc::malloc(response_data.len()) as *mut u8;
                    if response_ptr.is_null() {
                        set_error(
                            err,
                            RN_ERROR_MEMORY_ALLOCATION,
                            "Failed to allocate memory for response",
                        );
                        return RN_ERROR_MEMORY_ALLOCATION;
                    }

                    std::ptr::copy_nonoverlapping(
                        response_data.as_ptr(),
                        response_ptr,
                        response_data.len(),
                    );
                    *out_response = response_ptr;
                    *out_len = response_data.len();
                    0
                }
                Err(e) => {
                    set_error(
                        err,
                        RN_ERROR_OPERATION_FAILED,
                        &format!("Failed to serialize response: {e}"),
                    );
                    RN_ERROR_OPERATION_FAILED
                }
            }
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Revocation failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// Handle chain request (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_keys_ca_node_handle_chain(
    ca_node: *mut c_void,
    network_id: *const c_char,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if ca_node.is_null()
        || network_id.is_null()
        || out_response.is_null()
        || out_len.is_null()
        || err.is_null()
    {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let ca_node = &*(ca_node as *const CANode);

    // Parse network ID
    let network_id_str = match std::ffi::CStr::from_ptr(network_id).to_str() {
        Ok(id) => id.to_string(),
        Err(e) => {
            set_error(
                err,
                RN_ERROR_INVALID_UTF8,
                &format!("Invalid network ID: {e}"),
            );
            return RN_ERROR_INVALID_UTF8;
        }
    };

    // Handle the chain request
    match ca_node.handle_chain(network_id_str) {
        Ok(response) => {
            // Serialize the response
            match serde_cbor::to_vec(&response) {
                Ok(response_data) => {
                    let response_ptr = libc::malloc(response_data.len()) as *mut u8;
                    if response_ptr.is_null() {
                        set_error(
                            err,
                            RN_ERROR_MEMORY_ALLOCATION,
                            "Failed to allocate memory for response",
                        );
                        return RN_ERROR_MEMORY_ALLOCATION;
                    }

                    std::ptr::copy_nonoverlapping(
                        response_data.as_ptr(),
                        response_ptr,
                        response_data.len(),
                    );
                    *out_response = response_ptr;
                    *out_len = response_data.len();
                    0
                }
                Err(e) => {
                    set_error(
                        err,
                        RN_ERROR_OPERATION_FAILED,
                        &format!("Failed to serialize response: {e}"),
                    );
                    RN_ERROR_OPERATION_FAILED
                }
            }
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Chain request failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// Handle status request (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_keys_ca_node_handle_status(
    ca_node: *mut c_void,
    network_id: *const c_char,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if ca_node.is_null()
        || network_id.is_null()
        || out_response.is_null()
        || out_len.is_null()
        || err.is_null()
    {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let ca_node = &*(ca_node as *const CANode);

    // Parse network ID
    let network_id_str = match std::ffi::CStr::from_ptr(network_id).to_str() {
        Ok(id) => id.to_string(),
        Err(e) => {
            set_error(
                err,
                RN_ERROR_INVALID_UTF8,
                &format!("Invalid network ID: {e}"),
            );
            return RN_ERROR_INVALID_UTF8;
        }
    };

    // Handle the status request
    match ca_node.handle_status(network_id_str) {
        Ok(response) => {
            // Serialize the response
            match serde_cbor::to_vec(&response) {
                Ok(response_data) => {
                    let response_ptr = libc::malloc(response_data.len()) as *mut u8;
                    if response_ptr.is_null() {
                        set_error(
                            err,
                            RN_ERROR_MEMORY_ALLOCATION,
                            "Failed to allocate memory for response",
                        );
                        return RN_ERROR_MEMORY_ALLOCATION;
                    }

                    std::ptr::copy_nonoverlapping(
                        response_data.as_ptr(),
                        response_ptr,
                        response_data.len(),
                    );
                    *out_response = response_ptr;
                    *out_len = response_data.len();
                    0
                }
                Err(e) => {
                    set_error(
                        err,
                        RN_ERROR_OPERATION_FAILED,
                        &format!("Failed to serialize response: {e}"),
                    );
                    RN_ERROR_OPERATION_FAILED
                }
            }
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Status request failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// Handle CRL request (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_keys_ca_node_handle_crl(
    ca_node: *mut c_void,
    network_id: *const c_char,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if ca_node.is_null()
        || network_id.is_null()
        || out_response.is_null()
        || out_len.is_null()
        || err.is_null()
    {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let ca_node = &*(ca_node as *const CANode);

    // Parse network ID
    let network_id_str = match std::ffi::CStr::from_ptr(network_id).to_str() {
        Ok(id) => id.to_string(),
        Err(e) => {
            set_error(
                err,
                RN_ERROR_INVALID_UTF8,
                &format!("Invalid network ID: {e}"),
            );
            return RN_ERROR_INVALID_UTF8;
        }
    };

    // Handle the CRL request
    match ca_node.handle_crl(network_id_str) {
        Ok(response) => {
            // Serialize the response
            match serde_cbor::to_vec(&response) {
                Ok(response_data) => {
                    let response_ptr = libc::malloc(response_data.len()) as *mut u8;
                    if response_ptr.is_null() {
                        set_error(
                            err,
                            RN_ERROR_MEMORY_ALLOCATION,
                            "Failed to allocate memory for response",
                        );
                        return RN_ERROR_MEMORY_ALLOCATION;
                    }

                    std::ptr::copy_nonoverlapping(
                        response_data.as_ptr(),
                        response_ptr,
                        response_data.len(),
                    );
                    *out_response = response_ptr;
                    *out_len = response_data.len();
                    0
                }
                Err(e) => {
                    set_error(
                        err,
                        RN_ERROR_OPERATION_FAILED,
                        &format!("Failed to serialize response: {e}"),
                    );
                    RN_ERROR_OPERATION_FAILED
                }
            }
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("CRL request failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

// ============================================================================
// CA CREATION FFI FUNCTIONS (NEW)
// ============================================================================

/// Create Root CA certificate
#[no_mangle]
pub unsafe extern "C" fn rn_keys_ca_create_root_ca(
    subject: *const c_char,
    out_ca: *mut *mut c_void,
    err: *mut RnError,
) -> i32 {
    if subject.is_null() || out_ca.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    // Parse subject string
    let subject_str = match std::ffi::CStr::from_ptr(subject).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_INVALID_UTF8,
                &format!("Invalid subject string: {e}"),
            );
            return RN_ERROR_INVALID_UTF8;
        }
    };

    // Create Root CA
    let ca = match runar_keys::CertificateAuthority::new(subject_str) {
        Ok(ca) => ca,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_CERTIFICATE_CREATION_FAILED,
                &format!("Failed to create Root CA: {e}"),
            );
            return RN_ERROR_CERTIFICATE_CREATION_FAILED;
        }
    };

    // Box the CA and return pointer
    let boxed_ca = Box::new(ca);
    *out_ca = Box::into_raw(boxed_ca) as *mut c_void;

    0
}

/// Create Issuing CA certificate (signed by Root CA)
#[no_mangle]
pub unsafe extern "C" fn rn_keys_ca_create_issuing_ca(
    root_ca: *mut c_void,
    subject: *const c_char,
    validity_days: u32,
    serial: u64,
    out_ca: *mut *mut c_void,
    err: *mut RnError,
) -> i32 {
    if root_ca.is_null() || subject.is_null() || out_ca.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    // Parse subject string
    let subject_str = match std::ffi::CStr::from_ptr(subject).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_INVALID_UTF8,
                &format!("Invalid subject string: {e}"),
            );
            return RN_ERROR_INVALID_UTF8;
        }
    };

    // Get the root CA
    let root_ca = &*(root_ca as *const runar_keys::CertificateAuthority);

    // Generate key pair for issuing CA
    let issuing_key_pair = match runar_keys::certificate::EcdsaKeyPair::new() {
        Ok(kp) => kp,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_CERTIFICATE_CREATION_FAILED,
                &format!("Failed to generate issuing CA key pair: {e}"),
            );
            return RN_ERROR_CERTIFICATE_CREATION_FAILED;
        }
    };

    // Create CSR for issuing CA
    let csr_der =
        match runar_keys::certificate::CertificateRequest::create(&issuing_key_pair, subject_str) {
            Ok(csr) => csr,
            Err(e) => {
                set_error(
                    err,
                    RN_ERROR_CERTIFICATE_CREATION_FAILED,
                    &format!("Failed to create issuing CA CSR: {e}"),
                );
                return RN_ERROR_CERTIFICATE_CREATION_FAILED;
            }
        };

    // Sign the CSR to create issuing CA certificate
    let issuing_cert = match root_ca.sign_ca_certificate_request_with_serial(
        &csr_der,
        validity_days,
        Some(serial),
    ) {
        Ok(cert) => cert,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_CERTIFICATE_CREATION_FAILED,
                &format!("Failed to sign issuing CA certificate: {e}"),
            );
            return RN_ERROR_CERTIFICATE_CREATION_FAILED;
        }
    };

    // Create issuing CA from existing key pair and certificate
    let issuing_ca =
        runar_keys::CertificateAuthority::from_existing(issuing_key_pair, issuing_cert);

    // Box the CA and return pointer
    let boxed_ca = Box::new(issuing_ca);
    *out_ca = Box::into_raw(boxed_ca) as *mut c_void;

    0
}

/// Get CA certificate DER bytes
#[no_mangle]
pub unsafe extern "C" fn rn_keys_ca_get_certificate_der(
    ca: *mut c_void,
    out_cert: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if ca.is_null() || out_cert.is_null() || out_len.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let ca = &*(ca as *const runar_keys::CertificateAuthority);
    let cert_der = ca.ca_certificate().der_bytes();

    // Allocate memory for certificate DER
    let cert_ptr = libc::malloc(cert_der.len()) as *mut u8;
    if cert_ptr.is_null() {
        set_error(
            err,
            RN_ERROR_MEMORY_ALLOCATION,
            "Failed to allocate memory for certificate DER",
        );
        return RN_ERROR_MEMORY_ALLOCATION;
    }

    // Copy certificate data
    std::ptr::copy_nonoverlapping(cert_der.as_ptr(), cert_ptr, cert_der.len());
    *out_cert = cert_ptr;
    *out_len = cert_der.len();

    0
}

/// Get CA certificate subject
#[no_mangle]
pub unsafe extern "C" fn rn_keys_ca_get_certificate_subject(
    ca: *mut c_void,
    out_subject: *mut *mut c_char,
    err: *mut RnError,
) -> i32 {
    if ca.is_null() || out_subject.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let ca = &*(ca as *const runar_keys::CertificateAuthority);
    let subject = ca.ca_certificate().subject();

    // Convert to C string
    let subject_cstr = match std::ffi::CString::new(subject) {
        Ok(s) => s,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_INVALID_UTF8,
                &format!("Invalid subject string: {e}"),
            );
            return RN_ERROR_INVALID_UTF8;
        }
    };

    // Allocate memory for C string
    let subject_ptr = libc::malloc(subject_cstr.as_bytes_with_nul().len()) as *mut c_char;
    if subject_ptr.is_null() {
        set_error(
            err,
            RN_ERROR_MEMORY_ALLOCATION,
            "Failed to allocate memory for subject string",
        );
        return RN_ERROR_MEMORY_ALLOCATION;
    }

    // Copy string data
    std::ptr::copy_nonoverlapping(
        subject_cstr.as_ptr(),
        subject_ptr,
        subject_cstr.as_bytes_with_nul().len(),
    );
    *out_subject = subject_ptr;

    0
}

/// Free CA resources
#[no_mangle]
pub unsafe extern "C" fn rn_keys_ca_free(ca: *mut c_void) {
    if !ca.is_null() {
        let _ = Box::from_raw(ca as *mut runar_keys::CertificateAuthority);
    }
}

// ============================================================================
// CA SERVER FFI FUNCTIONS (NEW)
// ============================================================================

/// Create new CA Server (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_transport_ca_server_new(
    config: *const u8,
    _config_len: usize,
    ca_node: *mut c_void,
    logger: *mut c_void,
    out_server: *mut *mut c_void,
    err: *mut RnError,
) -> i32 {
    if config.is_null()
        || ca_node.is_null()
        || logger.is_null()
        || out_server.is_null()
        || err.is_null()
    {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let logger = unsafe { &*(logger as *const Arc<Logger>) };
    let ca_node = unsafe { &*(ca_node as *const CANode) };

    // Parse the server configuration from the provided config data
    let config_data = std::slice::from_raw_parts(config, _config_len);
    let custom_config = match serde_cbor::from_slice::<CustomCaServerConfig>(config_data) {
        Ok(config) => config,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to parse server config: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Convert custom config to CaServerConfig
    let bootstrap_bind = match custom_config.bootstrap_bind.parse() {
        Ok(addr) => addr,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Invalid bootstrap_bind: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    let authenticated_bind = match custom_config.authenticated_bind.parse() {
        Ok(addr) => addr,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Invalid authenticated_bind: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    let server_config = runar_transporter::CaServerConfig {
        bootstrap_bind,
        authenticated_bind,
        network_id: custom_config.network_id,
        rate_limit_config: runar_transporter::RateLimitConfig {
            burst_limit: custom_config.rate_limit_per_minute,
            sustained_limit: custom_config.rate_limit_per_hour,
            burst_window: std::time::Duration::from_secs(60),
            sustained_window: std::time::Duration::from_secs(3600),
        },
        admin_skis: vec![],
        additional_ca_certs: vec![],
    };

    // Create the CA server
    let ca_node_arc = Arc::new(RwLock::new(unsafe { std::ptr::read(ca_node) }));
    let server = CaServer::new(server_config, ca_node_arc, logger.clone());

    let boxed_server = Box::new(server);
    unsafe {
        *out_server = Box::into_raw(boxed_server) as *mut c_void;
    }

    0
}

/// Free CA Server (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_transport_ca_server_free(server: *mut c_void) {
    if !server.is_null() {
        let _ = Box::from_raw(server as *mut CaServer);
    }
}

/// Configure admin SKIs (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_transport_ca_server_configure_admin_skis(
    server: *mut c_void,
    admin_skis: *const u8,
    skis_len: usize,
    err: *mut RnError,
) -> i32 {
    if server.is_null() || admin_skis.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let server = &mut *(server as *mut CaServer);

    // Parse admin SKIs
    let skis_data = std::slice::from_raw_parts(admin_skis, skis_len);
    let admin_skis_vec = match serde_cbor::from_slice::<Vec<String>>(skis_data) {
        Ok(skis) => skis,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to parse admin SKIs: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Configure admin SKIs
    server.configure_admin_skis(admin_skis_vec);
    0
}

/// Start CA Server (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_transport_ca_server_start(
    server: *mut c_void,
    err: *mut RnError,
) -> i32 {
    if server.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let server = &mut *(server as *mut CaServer);

    // Create a runtime for async operations
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to create runtime: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Start the server
    match rt.block_on(server.start()) {
        Ok((_bootstrap_addr, _authenticated_addr)) => {
            // Store the addresses in the server for later retrieval
            // For now, we'll just return success
            0
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to start server: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// Stop CA Server (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_transport_ca_server_stop(
    server: *mut c_void,
    err: *mut RnError,
) -> i32 {
    if server.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let server = &mut *(server as *mut CaServer);

    // Create a runtime for async operations
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to create runtime: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Stop the server
    match rt.block_on(server.stop()) {
        Ok(()) => 0,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to stop server: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// Get bootstrap address (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_transport_ca_server_get_bootstrap_addr(
    server: *mut c_void,
    out_addr: *mut *mut c_char,
    err: *mut RnError,
) -> i32 {
    if server.is_null() || out_addr.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let server_ref = &*(server as *const CaServer);

    // Get the bootstrap address from server config
    let addr_str = server_ref.bootstrap_bind().to_string();
    let addr_cstring = match std::ffi::CString::new(addr_str) {
        Ok(cstr) => cstr,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to create C string: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    *out_addr = addr_cstring.into_raw();
    0
}

/// Get authenticated address (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_transport_ca_server_get_authenticated_addr(
    server: *mut c_void,
    out_addr: *mut *mut c_char,
    err: *mut RnError,
) -> i32 {
    if server.is_null() || out_addr.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let server_ref = &*(server as *const CaServer);

    // Get the authenticated address from server config
    let addr_str = server_ref.authenticated_bind().to_string();
    let addr_cstring = match std::ffi::CString::new(addr_str) {
        Ok(cstr) => cstr,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to create C string: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    *out_addr = addr_cstring.into_raw();
    0
}

// ============================================================================
// PROFILE KEY MANAGEMENT FFI FUNCTIONS (PHASE 2)
// ============================================================================

/// Derive user profile key (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_derive_user_profile_key(
    keys: *mut c_void,
    label: *const c_char,
    out_public_key: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if keys.is_null()
        || label.is_null()
        || out_public_key.is_null()
        || out_len.is_null()
        || err.is_null()
    {
        if !err.is_null() {
            set_error(err, RN_ERROR_NULL_ARGUMENT, "Null argument provided");
        }
        return -1;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };

    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let label_str = match unsafe { std::ffi::CStr::from_ptr(label).to_str() } {
        Ok(s) => s,
        Err(_) => {
            set_error(err, RN_ERROR_INVALID_UTF8, "invalid utf8 in label");
            return RN_ERROR_INVALID_UTF8;
        }
    };

    match manager.write().unwrap().derive_user_profile_key(label_str) {
        Ok(public_key) => {
            let public_key_len = public_key.len();
            let public_key_ptr = Box::into_raw(public_key.into_boxed_slice()) as *mut u8;
            unsafe {
                *out_public_key = public_key_ptr;
                *out_len = public_key_len;
            }
            0
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to derive profile key: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// Decrypt envelope data using profile key (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_decrypt_with_profile(
    keys: *mut c_void,
    envelope_data: *const u8,
    envelope_len: usize,
    profile_id: *const c_char,
    out_data: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if keys.is_null()
        || envelope_data.is_null()
        || profile_id.is_null()
        || out_data.is_null()
        || out_len.is_null()
        || err.is_null()
    {
        if !err.is_null() {
            set_error(err, RN_ERROR_NULL_ARGUMENT, "Null argument provided");
        }
        return -1;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };

    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let profile_id_str = match unsafe { std::ffi::CStr::from_ptr(profile_id).to_str() } {
        Ok(s) => s,
        Err(_) => {
            set_error(err, RN_ERROR_INVALID_UTF8, "invalid utf8 in profile_id");
            return RN_ERROR_INVALID_UTF8;
        }
    };

    // Parse envelope data from CBOR
    let envelope_bytes = unsafe { std::slice::from_raw_parts(envelope_data, envelope_len) };
    let envelope_data: runar_keys::mobile::EnvelopeEncryptedData =
        match serde_cbor::from_slice(envelope_bytes) {
            Ok(env) => env,
            Err(e) => {
                set_error(
                    err,
                    RN_ERROR_SERIALIZATION_FAILED,
                    &format!("Failed to parse envelope data: {e}"),
                );
                return RN_ERROR_SERIALIZATION_FAILED;
            }
        };

    match manager
        .read()
        .unwrap()
        .decrypt_with_profile(&envelope_data, profile_id_str)
    {
        Ok(decrypted) => {
            let decrypted_len = decrypted.len();
            let decrypted_ptr = Box::into_raw(decrypted.into_boxed_slice()) as *mut u8;
            unsafe {
                *out_data = decrypted_ptr;
                *out_len = decrypted_len;
            }
            0
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to decrypt with profile: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// Install profile public key (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_install_profile_public_key(
    keys: *mut c_void,
    public_key: *const u8,
    public_key_len: usize,
    err: *mut RnError,
) -> i32 {
    if keys.is_null() || public_key.is_null() || err.is_null() {
        if !err.is_null() {
            set_error(err, RN_ERROR_NULL_ARGUMENT, "Null argument provided");
        }
        return -1;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };

    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let public_key_bytes =
        unsafe { std::slice::from_raw_parts(public_key, public_key_len) }.to_vec();

    manager
        .write()
        .unwrap()
        .install_profile_public_key(public_key_bytes);
    0
}

/// Get profile public key by label (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_get_profile_public_key_by_label(
    keys: *mut c_void,
    label: *const c_char,
    out_public_key: *mut *mut u8,
    out_public_key_len: *mut usize,
    out_has_key: *mut i32,
    err: *mut RnError,
) -> i32 {
    if keys.is_null()
        || label.is_null()
        || out_public_key.is_null()
        || out_public_key_len.is_null()
        || out_has_key.is_null()
        || err.is_null()
    {
        if !err.is_null() {
            set_error(err, RN_ERROR_NULL_ARGUMENT, "Null argument provided");
        }
        return -1;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };

    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let label_str = match unsafe { std::ffi::CStr::from_ptr(label).to_str() } {
        Ok(s) => s,
        Err(_) => {
            set_error(err, RN_ERROR_INVALID_UTF8, "invalid utf8 in label");
            return RN_ERROR_INVALID_UTF8;
        }
    };

    // Get profile public key by label
    if let Some(public_key) = manager
        .read()
        .unwrap()
        .get_profile_public_key_by_label(label_str)
    {
        let public_key_len = public_key.len();
        let public_key_ptr = Box::into_raw(public_key.clone().into_boxed_slice()) as *mut u8;
        unsafe {
            *out_public_key = public_key_ptr;
            *out_public_key_len = public_key_len;
            *out_has_key = 1;
        }
        return 0;
    }

    unsafe {
        *out_public_key = ptr::null_mut();
        *out_public_key_len = 0;
        *out_has_key = 0;
    }
    0
}

// ============================================================================
// CERTIFICATE MANAGEMENT FFI FUNCTIONS (PHASE 2)
// ============================================================================

/// Get certificate status
#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_get_certificate_status(
    keys: *mut c_void,
    out_status: *mut i32,
    err: *mut RnError,
) -> i32 {
    if keys.is_null() || out_status.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };

    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let status = manager.read().unwrap().get_certificate_status();
    let status_code = match status {
        runar_keys::node::CertificateStatus::None => 0,
        runar_keys::node::CertificateStatus::Pending => 1,
        runar_keys::node::CertificateStatus::Valid => 2,
        runar_keys::node::CertificateStatus::Invalid => 3,
    };

    unsafe {
        *out_status = status_code;
    }
    0
}

/// Get certificate serial number
#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_get_certificate_serial(
    keys: *mut c_void,
    out_serial: *mut *mut c_char,
    err: *mut RnError,
) -> i32 {
    if keys.is_null() || out_serial.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };

    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    match manager.read().unwrap().get_node_certificate() {
        Some(cert) => match cert.parsed() {
            Ok(parsed_cert) => {
                let serial_hex = parsed_cert.serial.to_string();
                if alloc_string_simple(out_serial, &serial_hex) {
                    0
                } else {
                    set_error(
                        err,
                        RN_ERROR_MEMORY_ALLOCATION,
                        "Failed to allocate serial string",
                    );
                    RN_ERROR_MEMORY_ALLOCATION
                }
            }
            Err(e) => {
                set_error(
                    err,
                    RN_ERROR_OPERATION_FAILED,
                    &format!("Failed to parse certificate: {e}"),
                );
                RN_ERROR_OPERATION_FAILED
            }
        },
        None => {
            set_error(err, RN_ERROR_OPERATION_FAILED, "No certificate installed");
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// Get QUIC certificate configuration
#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_get_quic_certificate_config(
    keys: *mut c_void,
    out_config: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if keys.is_null() || out_config.is_null() || out_len.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };

    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let _config = match manager.read().unwrap().get_quic_certificate_config() {
        Ok(config) => config,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to get QUIC config: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // For now, return a simple success indicator since QuicCertificateConfig doesn't implement Serialize
    // In a real implementation, you might want to create a serializable wrapper or extract specific fields
    let config_bytes = b"QUIC_CERT_CONFIG_AVAILABLE".to_vec();

    let config_len = config_bytes.len();
    let config_ptr = Box::into_raw(config_bytes.into_boxed_slice()) as *mut u8;

    unsafe {
        *out_config = config_ptr;
        *out_len = config_len;
    }
    0
}

/// Validate peer certificate
#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_validate_peer_certificate(
    keys: *mut c_void,
    peer_cert: *const u8,
    cert_len: usize,
    err: *mut RnError,
) -> i32 {
    if keys.is_null() || peer_cert.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    if cert_len == 0 {
        set_error(err, RN_ERROR_INVALID_ARGUMENT, "certificate length is zero");
        return RN_ERROR_INVALID_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };

    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    // Parse the peer certificate
    let cert_der = unsafe { std::slice::from_raw_parts(peer_cert, cert_len) };
    let cert_der_vec = cert_der.to_vec();
    let peer_cert = match runar_keys::certificate::X509Certificate::from_der(cert_der_vec) {
        Ok(cert) => cert,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to parse certificate: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Validate the certificate
    match manager
        .read()
        .unwrap()
        .validate_peer_certificate(&peer_cert)
    {
        Ok(()) => 0,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Certificate validation failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

// ============================================================================
// NETWORK KEY MANAGEMENT FFI FUNCTIONS (PHASE 2)
// ============================================================================

/// Install network key (v2 API)
#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_install_network_key(
    keys: *mut c_void,
    network_key_message: *const u8,
    message_len: usize,
    err: *mut RnError,
) -> i32 {
    if keys.is_null() || network_key_message.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    if message_len == 0 {
        set_error(err, RN_ERROR_INVALID_ARGUMENT, "message length is zero");
        return RN_ERROR_INVALID_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };

    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    // Parse the network key message
    let message_bytes = unsafe { std::slice::from_raw_parts(network_key_message, message_len) };
    let network_key_message =
        match serde_cbor::from_slice::<runar_keys::mobile::NetworkKeyMessage>(message_bytes) {
            Ok(msg) => msg,
            Err(e) => {
                set_error(
                    err,
                    RN_ERROR_SERIALIZATION_FAILED,
                    &format!("Failed to parse network key message: {e}"),
                );
                return RN_ERROR_SERIALIZATION_FAILED;
            }
        };

    // Install the network key
    match manager
        .write()
        .unwrap()
        .install_network_key(network_key_message)
    {
        Ok(()) => 0,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to install network key: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// Get network agreement
#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_get_network_agreement(
    keys: *mut c_void,
    network_public_key: *const u8,
    key_len: usize,
    out_agreement: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if keys.is_null()
        || network_public_key.is_null()
        || out_agreement.is_null()
        || out_len.is_null()
        || err.is_null()
    {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    if key_len == 0 {
        set_error(
            err,
            RN_ERROR_INVALID_ARGUMENT,
            "network public key length is zero",
        );
        return RN_ERROR_INVALID_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };

    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let network_public_key_bytes =
        unsafe { std::slice::from_raw_parts(network_public_key, key_len) };

    // Get the network agreement
    let manager_guard = manager.read().unwrap();
    let agreement = match manager_guard.get_network_agreement(network_public_key_bytes) {
        Ok(agreement) => agreement,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to get network agreement: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Convert the secret key to bytes
    let agreement_bytes = agreement.to_bytes().to_vec();
    let agreement_len = agreement_bytes.len();
    let agreement_ptr = Box::into_raw(agreement_bytes.into_boxed_slice()) as *mut u8;

    unsafe {
        *out_agreement = agreement_ptr;
        *out_len = agreement_len;
    }
    0
}

/// Check if node has network private key
#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_has_network_private_key(
    keys: *mut c_void,
    network_public_key: *const u8,
    key_len: usize,
    out_has_key: *mut i32,
    err: *mut RnError,
) -> i32 {
    if keys.is_null() || network_public_key.is_null() || out_has_key.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    if key_len == 0 {
        set_error(
            err,
            RN_ERROR_INVALID_ARGUMENT,
            "network public key length is zero",
        );
        return RN_ERROR_INVALID_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };

    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let network_public_key_bytes =
        unsafe { std::slice::from_raw_parts(network_public_key, key_len) };

    // Check if we have the network private key
    match manager
        .read()
        .unwrap()
        .has_network_private_key(network_public_key_bytes)
    {
        Ok(_) => {
            unsafe {
                *out_has_key = 1;
            }
            0
        }
        Err(_) => {
            unsafe {
                *out_has_key = 0;
            }
            0
        }
    }
}

// ============================================================================
// CA CLIENT FFI FUNCTIONS (NEW)
// ============================================================================

/// Create new CA Client (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_transport_ca_client_new(
    logger: *mut c_void,
    out_client: *mut *mut c_void,
    err: *mut RnError,
) -> i32 {
    if logger.is_null() || out_client.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let logger = unsafe { &*(logger as *const Arc<Logger>) };

    // Create a new CA Client with default configuration
    let config = runar_transporter::CaClientConfig::default();
    let client = CaClient::new(config.clone(), logger.clone());

    let wrapper = CaClientWrapper {
        client,
        config,
        logger: logger.clone(),
        root_ca_cert: None,
        issuing_ca_cert: None,
        node_key_manager: None,
    };

    let boxed_wrapper = Box::new(wrapper);
    unsafe {
        *out_client = Box::into_raw(boxed_wrapper) as *mut c_void;
    }

    0
}

/// Free CA Client (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_transport_ca_client_free(client: *mut c_void) {
    if !client.is_null() {
        let _ = Box::from_raw(client as *mut CaClientWrapper);
    }
}

/// CA Client enroll (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_transport_ca_client_enroll(
    client: *mut c_void,
    bootstrap_addr: *const c_char,
    request: *const u8,
    request_len: usize,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if client.is_null()
        || bootstrap_addr.is_null()
        || request.is_null()
        || out_response.is_null()
        || out_len.is_null()
        || err.is_null()
    {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let wrapper = &*(client as *const CaClientWrapper);
    let client = &wrapper.client;

    // Parse bootstrap address
    let _bootstrap_addr_str = match std::ffi::CStr::from_ptr(bootstrap_addr).to_str() {
        Ok(addr) => addr,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_INVALID_UTF8,
                &format!("Invalid bootstrap address: {e}"),
            );
            return RN_ERROR_INVALID_UTF8;
        }
    };

    // Parse the enrollment request
    let request_data = std::slice::from_raw_parts(request, request_len);
    let enroll_request = match serde_cbor::from_slice::<CsrEnrollRequest>(request_data) {
        Ok(req) => req,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to parse enrollment request: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Create a runtime for async operations
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to create runtime: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Perform enrollment
    match rt.block_on(client.enroll(enroll_request)) {
        Ok(response) => {
            // Serialize the response
            match serde_cbor::to_vec(&response) {
                Ok(response_data) => {
                    let response_ptr = libc::malloc(response_data.len()) as *mut u8;
                    if response_ptr.is_null() {
                        set_error(
                            err,
                            RN_ERROR_MEMORY_ALLOCATION,
                            "Failed to allocate memory for response",
                        );
                        return RN_ERROR_MEMORY_ALLOCATION;
                    }

                    std::ptr::copy_nonoverlapping(
                        response_data.as_ptr(),
                        response_ptr,
                        response_data.len(),
                    );
                    *out_response = response_ptr;
                    *out_len = response_data.len();
                    0
                }
                Err(e) => {
                    set_error(
                        err,
                        RN_ERROR_OPERATION_FAILED,
                        &format!("Failed to serialize response: {e}"),
                    );
                    RN_ERROR_OPERATION_FAILED
                }
            }
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Enrollment failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// CA Client renew (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_transport_ca_client_renew(
    client: *mut c_void,
    authenticated_addr: *const c_char,
    request: *const u8,
    request_len: usize,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if client.is_null()
        || authenticated_addr.is_null()
        || request.is_null()
        || out_response.is_null()
        || out_len.is_null()
        || err.is_null()
    {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let wrapper = &*(client as *const CaClientWrapper);
    let client = &wrapper.client;

    // Parse the renewal request
    let request_data = std::slice::from_raw_parts(request, request_len);
    let renew_request = match serde_cbor::from_slice::<RenewRequest>(request_data) {
        Ok(req) => req,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to parse renewal request: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Create a runtime for async operations
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to create runtime: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Perform renewal
    match rt.block_on(client.renew(renew_request)) {
        Ok(response) => {
            // Serialize the response
            match serde_cbor::to_vec(&response) {
                Ok(response_data) => {
                    let response_ptr = libc::malloc(response_data.len()) as *mut u8;
                    if response_ptr.is_null() {
                        set_error(
                            err,
                            RN_ERROR_MEMORY_ALLOCATION,
                            "Failed to allocate memory for response",
                        );
                        return RN_ERROR_MEMORY_ALLOCATION;
                    }

                    std::ptr::copy_nonoverlapping(
                        response_data.as_ptr(),
                        response_ptr,
                        response_data.len(),
                    );
                    *out_response = response_ptr;
                    *out_len = response_data.len();
                    0
                }
                Err(e) => {
                    set_error(
                        err,
                        RN_ERROR_OPERATION_FAILED,
                        &format!("Failed to serialize response: {e}"),
                    );
                    RN_ERROR_OPERATION_FAILED
                }
            }
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Renewal failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// CA Client revoke (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_transport_ca_client_revoke(
    client: *mut c_void,
    authenticated_addr: *const c_char,
    request: *const u8,
    request_len: usize,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if client.is_null()
        || authenticated_addr.is_null()
        || request.is_null()
        || out_response.is_null()
        || out_len.is_null()
        || err.is_null()
    {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let wrapper = &*(client as *const CaClientWrapper);
    let client = &wrapper.client;

    // Parse the revocation request
    let request_data = std::slice::from_raw_parts(request, request_len);
    let revoke_request = match serde_cbor::from_slice::<RevokeRequest>(request_data) {
        Ok(req) => req,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to parse revocation request: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Create a runtime for async operations
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to create runtime: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Perform revocation
    match rt.block_on(client.revoke(revoke_request)) {
        Ok(response) => {
            // Serialize the response
            match serde_cbor::to_vec(&response) {
                Ok(response_data) => {
                    let response_ptr = libc::malloc(response_data.len()) as *mut u8;
                    if response_ptr.is_null() {
                        set_error(
                            err,
                            RN_ERROR_MEMORY_ALLOCATION,
                            "Failed to allocate memory for response",
                        );
                        return RN_ERROR_MEMORY_ALLOCATION;
                    }

                    std::ptr::copy_nonoverlapping(
                        response_data.as_ptr(),
                        response_ptr,
                        response_data.len(),
                    );
                    *out_response = response_ptr;
                    *out_len = response_data.len();
                    0
                }
                Err(e) => {
                    set_error(
                        err,
                        RN_ERROR_OPERATION_FAILED,
                        &format!("Failed to serialize response: {e}"),
                    );
                    RN_ERROR_OPERATION_FAILED
                }
            }
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Revocation failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// CA Client get chain (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_transport_ca_client_get_chain(
    client: *mut c_void,
    bootstrap_addr: *const c_char,
    network_id: *const c_char,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if client.is_null()
        || bootstrap_addr.is_null()
        || network_id.is_null()
        || out_response.is_null()
        || out_len.is_null()
        || err.is_null()
    {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let wrapper = &*(client as *const CaClientWrapper);
    let client = &wrapper.client;

    // Create a runtime for async operations
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to create runtime: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Fetch chain
    match rt.block_on(client.fetch_chain()) {
        Ok(response) => {
            // Serialize the response
            match serde_cbor::to_vec(&response) {
                Ok(response_data) => {
                    let response_ptr = libc::malloc(response_data.len()) as *mut u8;
                    if response_ptr.is_null() {
                        set_error(
                            err,
                            RN_ERROR_MEMORY_ALLOCATION,
                            "Failed to allocate memory for response",
                        );
                        return RN_ERROR_MEMORY_ALLOCATION;
                    }

                    std::ptr::copy_nonoverlapping(
                        response_data.as_ptr(),
                        response_ptr,
                        response_data.len(),
                    );
                    *out_response = response_ptr;
                    *out_len = response_data.len();
                    0
                }
                Err(e) => {
                    set_error(
                        err,
                        RN_ERROR_OPERATION_FAILED,
                        &format!("Failed to serialize response: {e}"),
                    );
                    RN_ERROR_OPERATION_FAILED
                }
            }
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Chain fetch failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// CA Client get status (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_transport_ca_client_get_status(
    client: *mut c_void,
    authenticated_addr: *const c_char,
    network_id: *const c_char,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if client.is_null()
        || authenticated_addr.is_null()
        || network_id.is_null()
        || out_response.is_null()
        || out_len.is_null()
        || err.is_null()
    {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let wrapper = &*(client as *const CaClientWrapper);
    let client = &wrapper.client;

    // Create a runtime for async operations
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to create runtime: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Get status
    match rt.block_on(client.get_status()) {
        Ok(response) => {
            // Serialize the response
            match serde_cbor::to_vec(&response) {
                Ok(response_data) => {
                    let response_ptr = libc::malloc(response_data.len()) as *mut u8;
                    if response_ptr.is_null() {
                        set_error(
                            err,
                            RN_ERROR_MEMORY_ALLOCATION,
                            "Failed to allocate memory for response",
                        );
                        return RN_ERROR_MEMORY_ALLOCATION;
                    }

                    std::ptr::copy_nonoverlapping(
                        response_data.as_ptr(),
                        response_ptr,
                        response_data.len(),
                    );
                    *out_response = response_ptr;
                    *out_len = response_data.len();
                    0
                }
                Err(e) => {
                    set_error(
                        err,
                        RN_ERROR_OPERATION_FAILED,
                        &format!("Failed to serialize response: {e}"),
                    );
                    RN_ERROR_OPERATION_FAILED
                }
            }
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Status fetch failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// CA Client get CRL (new API)
#[no_mangle]
pub unsafe extern "C" fn rn_transport_ca_client_get_crl(
    client: *mut c_void,
    authenticated_addr: *const c_char,
    network_id: *const c_char,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if client.is_null()
        || authenticated_addr.is_null()
        || network_id.is_null()
        || out_response.is_null()
        || out_len.is_null()
        || err.is_null()
    {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let wrapper = &*(client as *const CaClientWrapper);
    let client = &wrapper.client;

    // Create a runtime for async operations
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to create runtime: {e}"),
            );
            return RN_ERROR_OPERATION_FAILED;
        }
    };

    // Fetch CRL
    match rt.block_on(client.fetch_crl()) {
        Ok(response) => {
            // Serialize the response
            match serde_cbor::to_vec(&response) {
                Ok(response_data) => {
                    let response_ptr = libc::malloc(response_data.len()) as *mut u8;
                    if response_ptr.is_null() {
                        set_error(
                            err,
                            RN_ERROR_MEMORY_ALLOCATION,
                            "Failed to allocate memory for response",
                        );
                        return RN_ERROR_MEMORY_ALLOCATION;
                    }

                    std::ptr::copy_nonoverlapping(
                        response_data.as_ptr(),
                        response_ptr,
                        response_data.len(),
                    );
                    *out_response = response_ptr;
                    *out_len = response_data.len();
                    0
                }
                Err(e) => {
                    set_error(
                        err,
                        RN_ERROR_OPERATION_FAILED,
                        &format!("Failed to serialize response: {e}"),
                    );
                    RN_ERROR_OPERATION_FAILED
                }
            }
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("CRL fetch failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// Generate CSR for certificate enrollment (v2)
#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_generate_csr_v2(
    keys: *mut c_void,
    out_csr: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if keys.is_null() || out_csr.is_null() || out_len.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };

    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    match manager.write().unwrap().generate_csr() {
        Ok(csr) => {
            let csr_data = csr.csr_der;
            let csr_ptr = libc::malloc(csr_data.len()) as *mut u8;
            if csr_ptr.is_null() {
                set_error(
                    err,
                    RN_ERROR_MEMORY_ALLOCATION,
                    "Failed to allocate memory for CSR",
                );
                return RN_ERROR_MEMORY_ALLOCATION;
            }

            std::ptr::copy_nonoverlapping(csr_data.as_ptr(), csr_ptr, csr_data.len());
            unsafe {
                *out_csr = csr_ptr;
                *out_len = csr_data.len();
            }
            0
        }
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to generate CSR: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// Generate keys for node
#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_generate_keys(keys: *mut c_void, err: *mut RnError) -> i32 {
    if keys.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };

    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    match manager.write().unwrap().generate_keys() {
        Ok(_) => 0,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to generate keys: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

/// Install certificate for node key manager
#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_install_certificate_v2(
    keys: *mut c_void,
    certificate_data: *const u8,
    cert_len: usize,
    err: *mut RnError,
) -> i32 {
    if keys.is_null() || certificate_data.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid keys handle");
        return RN_ERROR_INVALID_HANDLE;
    };

    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code(), &e.message());
            return e.code();
        }
    };

    let cert_data = std::slice::from_raw_parts(certificate_data, cert_len);

    // Parse the certificate message
    match serde_cbor::from_slice::<NodeCertificateMessage>(cert_data) {
        Ok(cert_message) => match manager.write().unwrap().install_certificate(cert_message) {
            Ok(_) => 0,
            Err(e) => {
                set_error(
                    err,
                    RN_ERROR_OPERATION_FAILED,
                    &format!("Failed to install certificate: {e}"),
                );
                RN_ERROR_OPERATION_FAILED
            }
        },
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("Failed to parse certificate message: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

// ============================================================================
// CA Client Configuration APIs
// ============================================================================

/// Configure CA Client with server addresses and settings
#[no_mangle]
pub unsafe extern "C" fn rn_transport_ca_client_configure(
    client: *mut c_void,
    bootstrap_server: *const c_char,
    authenticated_server: *const c_char,
    network_id: *const c_char,
    request_timeout_seconds: u32,
    max_retries: u32,
    err: *mut RnError,
) -> i32 {
    if client.is_null()
        || bootstrap_server.is_null()
        || authenticated_server.is_null()
        || network_id.is_null()
        || err.is_null()
    {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    // Parse server addresses
    let bootstrap_addr_str = match std::ffi::CStr::from_ptr(bootstrap_server).to_str() {
        Ok(addr) => addr,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_INVALID_UTF8,
                &format!("Invalid bootstrap server address: {e}"),
            );
            return RN_ERROR_INVALID_UTF8;
        }
    };

    let authenticated_addr_str = match std::ffi::CStr::from_ptr(authenticated_server).to_str() {
        Ok(addr) => addr,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_INVALID_UTF8,
                &format!("Invalid authenticated server address: {e}"),
            );
            return RN_ERROR_INVALID_UTF8;
        }
    };

    let network_id_str = match std::ffi::CStr::from_ptr(network_id).to_str() {
        Ok(id) => id,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_INVALID_UTF8,
                &format!("Invalid network ID: {e}"),
            );
            return RN_ERROR_INVALID_UTF8;
        }
    };

    // Parse addresses
    let bootstrap_addr = match bootstrap_addr_str.parse::<std::net::SocketAddr>() {
        Ok(addr) => addr,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_INVALID_ARGUMENT,
                &format!("Invalid bootstrap server address format: {e}"),
            );
            return RN_ERROR_INVALID_ARGUMENT;
        }
    };

    let authenticated_addr = match authenticated_addr_str.parse::<std::net::SocketAddr>() {
        Ok(addr) => addr,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_INVALID_ARGUMENT,
                &format!("Invalid authenticated server address format: {e}"),
            );
            return RN_ERROR_INVALID_ARGUMENT;
        }
    };

    // Create new configuration
    let config = runar_transporter::CaClientConfig {
        bootstrap_server: bootstrap_addr,
        authenticated_server: authenticated_addr,
        network_id: network_id_str.to_string(),
        request_timeout: std::time::Duration::from_secs(request_timeout_seconds as u64),
        max_retries,
    };

    // Update the existing wrapper's configuration
    let wrapper = &mut *(client as *mut CaClientWrapper);
    wrapper.config = config;

    0
}

/// Set root CA certificate for client
#[no_mangle]
pub unsafe extern "C" fn rn_transport_ca_client_set_root_ca_cert(
    client: *mut c_void,
    cert: *const u8,
    cert_len: usize,
    err: *mut RnError,
) -> i32 {
    if client.is_null() || cert.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    // Copy certificate data
    let cert_data = std::slice::from_raw_parts(cert, cert_len).to_vec();

    // Update the existing wrapper's root CA certificate
    let wrapper = &mut *(client as *mut CaClientWrapper);
    wrapper.root_ca_cert = Some(cert_data);

    0
}

/// Set issuing CA certificate for client
#[no_mangle]
pub unsafe extern "C" fn rn_transport_ca_client_set_issuing_ca_cert(
    client: *mut c_void,
    cert: *const u8,
    cert_len: usize,
    err: *mut RnError,
) -> i32 {
    if client.is_null() || cert.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    // Copy certificate data
    let cert_data = std::slice::from_raw_parts(cert, cert_len).to_vec();

    // Update the existing wrapper's issuing CA certificate
    let wrapper = &mut *(client as *mut CaClientWrapper);
    wrapper.issuing_ca_cert = Some(cert_data);

    0
}

/// Set node key manager for client
#[no_mangle]
pub unsafe extern "C" fn rn_transport_ca_client_set_node_key_manager(
    client: *mut c_void,
    node_keys: *mut c_void,
    err: *mut RnError,
) -> i32 {
    if client.is_null() || node_keys.is_null() || err.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "null argument");
        return RN_ERROR_NULL_ARGUMENT;
    }

    let node_key_manager_arc =
        &*(node_keys as *const std::sync::Arc<std::sync::RwLock<NodeKeyManager>>);

    // Update the existing wrapper's node key manager
    let wrapper = &mut *(client as *mut CaClientWrapper);
    wrapper.node_key_manager = Some(node_key_manager_arc.clone());

    0
}
