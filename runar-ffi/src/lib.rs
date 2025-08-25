#![allow(clippy::missing_safety_doc)]

use std::{
    ffi::{c_void, CString},
    os::raw::c_char,
    sync::{Arc, RwLock},
};

use arc_swap::ArcSwap;
use once_cell::sync::OnceCell;
use runar_common::logging::{Component, Logger};
use runar_keys::keystore;

use runar_keys::{
    mobile::{MobileKeyManager, NetworkKeyMessage, NodeCertificateMessage, SetupToken},
    node::NodeKeyManager,
    EnvelopeCrypto,
};
use runar_schemas::NodeInfo;
use runar_serializer::traits::{LabelKeyInfo, LabelResolver};
use runar_transporter::discovery::multicast_discovery::PeerInfo;
use runar_transporter::discovery::{DiscoveryEvent, DiscoveryOptions, MulticastDiscovery};
use runar_transporter::{NetworkTransport, NodeDiscovery, QuicTransport, QuicTransportOptions};
use serde_cbor as _; // keep dependency linked for now
                     // panic handling imports removed - no longer needed without ffi_guard
use std::sync::atomic::AtomicU64;
use std::sync::Mutex as StdMutex;
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot, Mutex};

#[repr(C)]
pub struct RnError {
    pub code: i32,
    pub message: *const c_char,
}

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

    // Optional platform-provided label resolver
    label_resolver: Option<Arc<dyn LabelResolver>>,
    // Local NodeInfo holder (push-updated from FFI)
    local_node_info: Arc<ArcSwap<Option<NodeInfo>>>,
    // Shared device keystore registered at FFI level
    device_keystore: Option<Arc<dyn keystore::DeviceKeystore>>,
    // Persistence directory and auto-persist flag
    persistence_dir: Option<std::path::PathBuf>,
    auto_persist: bool,
}

// Error types for validation
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum RnErrorType {
    NullArgument(String),
    InvalidHandle(String),
    NotInitialized,
    WrongManagerType(String),
    OperationFailed(String),
    SerializationFailed(String),
    KeystoreFailed(String),
    MemoryAllocation(String),
    LockError(String),
    InvalidUtf8(String),
    InvalidArgument(String),
}

impl RnErrorType {
    fn code(&self) -> i32 {
        match self {
            RnErrorType::NullArgument(_) => RN_ERROR_NULL_ARGUMENT,
            RnErrorType::InvalidHandle(_) => RN_ERROR_INVALID_HANDLE,
            RnErrorType::NotInitialized => RN_ERROR_NOT_INITIALIZED,
            RnErrorType::WrongManagerType(_) => RN_ERROR_WRONG_MANAGER_TYPE,
            RnErrorType::OperationFailed(_) => RN_ERROR_OPERATION_FAILED,
            RnErrorType::SerializationFailed(_) => RN_ERROR_SERIALIZATION_FAILED,
            RnErrorType::KeystoreFailed(_) => RN_ERROR_KEYSTORE_FAILED,
            RnErrorType::MemoryAllocation(_) => RN_ERROR_MEMORY_ALLOCATION,
            RnErrorType::LockError(_) => RN_ERROR_LOCK_ERROR,
            RnErrorType::InvalidUtf8(_) => RN_ERROR_INVALID_UTF8,
            RnErrorType::InvalidArgument(_) => RN_ERROR_INVALID_ARGUMENT,
        }
    }

    fn message(&self) -> String {
        match self {
            RnErrorType::NullArgument(msg) => msg.clone(),
            RnErrorType::InvalidHandle(msg) => msg.clone(),
            RnErrorType::NotInitialized => "key manager not initialized".to_string(),
            RnErrorType::WrongManagerType(msg) => msg.clone(),
            RnErrorType::OperationFailed(msg) => msg.clone(),
            RnErrorType::SerializationFailed(msg) => msg.clone(),
            RnErrorType::KeystoreFailed(msg) => msg.clone(),
            RnErrorType::MemoryAllocation(msg) => msg.clone(),
            RnErrorType::LockError(msg) => msg.clone(),
            RnErrorType::InvalidUtf8(msg) => msg.clone(),
            RnErrorType::InvalidArgument(msg) => msg.clone(),
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

/// Helper to work with validated mobile manager
#[allow(dead_code)]
fn with_validated_mobile_manager<F>(inner: &KeysInner, f: F) -> Result<(), RnErrorType>
where
    F: FnOnce(&mut MobileKeyManager) -> Result<(), RnErrorType>,
{
    let manager = validate_mobile_manager(inner)?;
    let mut mgr = manager
        .write()
        .map_err(|_| RnErrorType::LockError("failed to acquire mobile manager lock".into()))?;
    f(&mut mgr)
}

/// Helper to work with validated node manager
#[allow(dead_code)]
fn with_validated_node_manager<F>(inner: &KeysInner, f: F) -> Result<(), RnErrorType>
where
    F: FnOnce(&mut NodeKeyManager) -> Result<(), RnErrorType>,
{
    let manager = validate_node_manager(inner)?;
    let mut mgr = manager
        .write()
        .map_err(|_| RnErrorType::LockError("failed to acquire node manager lock".into()))?;
    f(&mut mgr)
}

// Common keystore registration helpers
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

/// Common feature disabled error handling
fn handle_feature_disabled_error(err: *mut RnError, feature_name: &str) -> i32 {
    set_error(
        err,
        RN_ERROR_KEYSTORE_FAILED,
        &format!("{feature_name} feature not enabled or unsupported target OS"),
    );
    RN_ERROR_KEYSTORE_FAILED
}

#[allow(dead_code)]
struct TransportInner {
    #[allow(dead_code)]
    logger: Arc<Logger>,
    transport: Arc<QuicTransport>,
    events_tx: mpsc::Sender<Vec<u8>>,
    events_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    pending: Arc<
        Mutex<
            std::collections::HashMap<
                String,
                oneshot::Sender<runar_transporter::transport::ResponseMessage>,
            >,
        >,
    >,
    #[allow(dead_code)]
    request_id_seq: Arc<AtomicU64>,
    local_node_info: Arc<ArcSwap<Option<NodeInfo>>>,
}

#[allow(dead_code)]
struct DiscoveryInner {
    #[allow(dead_code)]
    logger: Arc<Logger>,
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

// ------------------------------
// LabelResolver mapping hydration (CBOR-based)
// ------------------------------

/// Set label mapping from a CBOR-encoded HashMap<String, LabelKeyInfo>.
///
/// Returns 0 on success.
/// Returns 1 on null/invalid arguments.
/// Returns 2 on CBOR decode error; call `rn_last_error` to retrieve the error message.
#[no_mangle]
pub unsafe extern "C" fn rn_keys_set_label_mapping(
    keys: *mut c_void,
    mapping_cbor: *const u8,
    len: usize,
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        return 1;
    };
    if mapping_cbor.is_null() || len == 0 {
        return 1;
    }
    let slice = std::slice::from_raw_parts(mapping_cbor, len);
    let mapping: std::collections::HashMap<String, LabelKeyInfo> =
        match serde_cbor::from_slice(slice) {
            Ok(m) => m,
            Err(e) => {
                set_error(
                    std::ptr::null_mut(),
                    2,
                    &format!("decode label mapping: {e}"),
                );
                return 2;
            }
        };
    let resolver = runar_serializer::traits::ConfigurableLabelResolver::from_map(mapping);
    inner.label_resolver = Some(Arc::new(resolver));
    0
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
            let node_id = mgr.get_node_id();
            let _ = runar_keys::keystore::persistence::wipe(
                &cfg,
                &runar_keys::keystore::persistence::Role::Node { node_id: &node_id },
            );
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_get_keystore_state(
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

    let ready = match node_manager.probe_and_load_state() {
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

#[no_mangle]
pub unsafe extern "C" fn rn_keys_register_apple_device_keystore(
    keys: *mut c_void,
    label: *const c_char,
    err: *mut RnError,
) -> i32 {
    // Common validation
    let _inner = match validate_keystore_params(keys, err) {
        Ok(inner) => inner,
        Err(code) => return code,
    };
    let _label_str = match validate_utf8_string(label, err, "label") {
        Ok(s) => s,
        Err(code) => return code,
    };

    #[cfg(all(
        feature = "apple-keystore",
        any(target_os = "macos", target_os = "ios")
    ))]
    {
        match runar_keys::keystore::apple::AppleDeviceKeystore::new(&label_str) {
            Ok(ks) => {
                let keystore = Arc::new(ks);
                register_keystore_with_managers(inner, keystore);
                0
            }
            Err(e) => handle_keystore_creation_error(err, "AppleDeviceKeystore", e),
        }
    }
    #[cfg(not(all(
        feature = "apple-keystore",
        any(target_os = "macos", target_os = "ios")
    )))]
    {
        handle_feature_disabled_error(err, "apple-keystore")
    }
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_register_linux_device_keystore(
    keys: *mut c_void,
    _service: *const c_char,
    _account: *const c_char,
    err: *mut RnError,
) -> i32 {
    #[cfg(all(feature = "linux-keystore", target_os = "linux"))]
    {
        // Common validation - only when feature is enabled
        let inner = match validate_keystore_params(keys, err) {
            Ok(inner) => inner,
            Err(code) => return code,
        };
        let svc = match validate_utf8_string(_service, err, "service") {
            Ok(s) => s,
            Err(code) => return code,
        };
        let acc = match validate_utf8_string(_account, err, "account") {
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
    #[cfg(not(all(feature = "linux-keystore", target_os = "linux")))]
    {
        // Minimal validation when feature is disabled
        if keys.is_null() {
            set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
            return RN_ERROR_INVALID_HANDLE;
        }
        handle_feature_disabled_error(err, "linux-keystore")
    }
}

// Envelope helpers (CBOR EED)
// Legacy function removed - replaced by rn_keys_node_encrypt_with_envelope and rn_keys_mobile_encrypt_with_envelope

#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_encrypt_with_envelope(
    keys: *mut c_void,
    data: *const u8,
    data_len: usize,
    network_id: *const c_char,
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
    let network_id_opt = if network_id.is_null() {
        None
    } else {
        match std::ffi::CStr::from_ptr(network_id).to_str() {
            Ok(s) => Some(s.to_string()),
            Err(_) => {
                set_error(err, RN_ERROR_INVALID_UTF8, "invalid utf8 network id");
                return RN_ERROR_INVALID_UTF8;
            }
        }
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

    match node_manager.encrypt_with_envelope(data_slice, network_id_opt.as_ref(), profiles) {
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
    network_id: *const c_char,
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
    let network_id_opt = if network_id.is_null() {
        None
    } else {
        match std::ffi::CStr::from_ptr(network_id).to_str() {
            Ok(s) => Some(s.to_string()),
            Err(_) => {
                set_error(err, RN_ERROR_INVALID_UTF8, "invalid utf8 network id");
                return RN_ERROR_INVALID_UTF8;
            }
        }
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

    match mobile_manager.encrypt_with_envelope(data_slice, network_id_opt.as_deref(), profiles) {
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
    out_str: *mut *mut c_char,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_str.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output string pointer is null");
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
        Ok(network_id) => {
            if !alloc_string(out_str, out_len, &network_id) {
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
pub unsafe extern "C" fn rn_keys_mobile_get_network_public_key(
    keys: *mut c_void,
    network_id: *const c_char,
    out_pk: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if network_id.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "network_id pointer is null");
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

    let nid = match std::ffi::CStr::from_ptr(network_id).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error(err, RN_ERROR_INVALID_UTF8, "invalid utf8 network_id");
            return RN_ERROR_INVALID_UTF8;
        }
    };

    match mobile_manager.get_network_public_key(nid) {
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
                &format!("get_network_public_key failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_mobile_create_network_key_message(
    keys: *mut c_void,
    network_id: *const c_char,
    node_agreement_pk: *const u8,
    node_agreement_pk_len: usize,
    out_msg_cbor: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, 1, "keys handle is null");
        return 1;
    };
    if network_id.is_null()
        || node_agreement_pk.is_null()
        || out_msg_cbor.is_null()
        || out_len.is_null()
    {
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

    let mobile_manager = match manager.read() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let nid = match std::ffi::CStr::from_ptr(network_id).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error(err, RN_ERROR_INVALID_UTF8, "invalid utf8 network_id");
            return RN_ERROR_INVALID_UTF8;
        }
    };

    let pk = std::slice::from_raw_parts(node_agreement_pk, node_agreement_pk_len);
    let msg = match mobile_manager.create_network_key_message(nid, pk) {
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
            set_error(err, 2, &format!("encode NetworkKeyMessage failed: {e}"));
            return 2;
        }
    };
    if !alloc_bytes(out_msg_cbor, out_len, &cbor) {
        set_error(err, 3, "alloc failed");
        return 3;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_install_network_key(
    keys: *mut c_void,
    nkm_cbor: *const u8,
    nkm_len: usize,
    err: *mut RnError,
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, 1, "keys handle is null");
        return 1;
    };
    if nkm_cbor.is_null() || nkm_len == 0 {
        set_error(err, 1, "null argument");
        return 1;
    }
    let slice = std::slice::from_raw_parts(nkm_cbor, nkm_len);
    let msg: NetworkKeyMessage = match serde_cbor::from_slice(slice) {
        Ok(m) => m,
        Err(e) => {
            set_error(err, 2, &format!("decode NetworkKeyMessage failed: {e}"));
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

    match node_manager.install_network_key(msg) {
        Ok(_) => 0,
        Err(e) => {
            set_error(
                err,
                RN_ERROR_OPERATION_FAILED,
                &format!("install_network_key failed: {e}"),
            );
            RN_ERROR_OPERATION_FAILED
        }
    }
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
    network_id: *const c_char,
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
    if network_id.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "network_id pointer is null");
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
    let nid = match std::ffi::CStr::from_ptr(network_id).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error(err, RN_ERROR_INVALID_UTF8, "invalid utf8 network id");
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

    let node_manager = match manager.read() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    let eed = match node_manager.encrypt_for_network(data_slice, nid) {
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

    let node_pk = node_manager.get_node_public_key();

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
        logger: keys_inner.logger.clone(),
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
        label_resolver: None,
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

    // Initialize node manager
    match NodeKeyManager::new(inner.logger.clone()) {
        Ok(mut manager) => {
            // Apply existing configuration
            if let Some(ks) = &inner.device_keystore {
                manager.register_device_keystore(ks.clone());
            }
            if let Some(dir) = &inner.persistence_dir {
                manager.set_persistence_dir(dir.clone());
            }
            manager.enable_auto_persist(inner.auto_persist);

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

    let pk = node_manager.get_node_public_key();
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
pub extern "C" fn rn_keys_node_get_node_id(
    keys: *mut c_void,
    out_str: *mut *mut c_char,
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

    let node_id = node_manager.get_node_id();
    if !alloc_string(out_str, out_len, &node_id) {
        set_error(err, 3, "invalid out pointers or string alloc failed");
        return 3;
    }
    0
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

    // Get node ID first
    #[allow(unused_variables)]
    let node_id = {
        let mgr = match manager.read() {
            Ok(mgr) => mgr,
            Err(_) => {
                set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
                return RN_ERROR_LOCK_ERROR;
            }
        };
        mgr.get_node_id()
    };
    let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
    let _ = rx; // Suppress unused variable warning - used in future implementation

    // Build callbacks to emit events
    let pc_tx = tx.clone();
    #[allow(unused_variables)]
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
    #[allow(unused_variables)]
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
                oneshot::Sender<runar_transporter::transport::ResponseMessage>,
            >,
        >,
    > = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let pending_cb = pending.clone();
    #[allow(unused_variables)]
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
                serde_cbor::Value::Text(req.path),
            );
            map.insert(
                serde_cbor::Value::Text("correlation_id".into()),
                serde_cbor::Value::Text(req.correlation_id),
            );
            map.insert(
                serde_cbor::Value::Text("payload".into()),
                serde_cbor::Value::Bytes(req.payload_bytes),
            );
            map.insert(
                serde_cbor::Value::Text("profile_public_key".into()),
                serde_cbor::Value::Bytes(req.profile_public_key),
            );
            let _ = req_tx
                .send(serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap_or_default())
                .await;

            match rx_resp.await {
                Ok(resp) => Ok(resp),
                Err(_) => Ok(runar_transporter::transport::ResponseMessage {
                    correlation_id: String::new(),
                    payload_bytes: Vec::new(),
                    profile_public_key: Vec::new(),
                }),
            }
        })
    });

    let ev_tx = tx.clone();
    #[allow(unused_variables)]
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
                serde_cbor::Value::Text(ev.path),
            );
            map.insert(
                serde_cbor::Value::Text("correlation_id".into()),
                serde_cbor::Value::Text(ev.correlation_id),
            );
            map.insert(
                serde_cbor::Value::Text("payload".into()),
                serde_cbor::Value::Bytes(ev.payload_bytes),
            );
            let _ = ev_tx
                .send(serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap_or_default())
                .await;
            Ok(())
        })
    });

    // Attach platform-provided LabelResolver if present
    if let Some(resolver) = keys_inner.label_resolver.clone() {
        let _ = options.with_label_resolver(resolver);
    }
    // Require local NodeInfo to be set before initializing transport
    if keys_inner.local_node_info.load().as_ref().is_none() {
        set_error(
            err,
            1,
            "local NodeInfo is required; call rn_keys_set_local_node_info() before creating the transport",
        );
        return 1;
    }
    // Note: This is a temporary workaround for the transport API mismatch
    // The transport expects Arc<NodeKeyManager> but we have Arc<RwLock<NodeKeyManager>>
    // This should be addressed in a future architectural update
    #[allow(unused_variables)]
    let node_manager_for_transport = {
        let _mgr = match manager.read() {
            Ok(mgr) => mgr,
            Err(_) => {
                set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
                return RN_ERROR_LOCK_ERROR;
            }
        };
        // We can't easily extract the inner manager without ownership issues
        // For now, we'll create a dummy manager - this needs proper architectural resolution
        // This todo!() is a placeholder for future implementation when the transport API is updated
        // to work with the new key manager structure. The code after this prepares the necessary
        // variables for that future implementation.
        todo!("Transport integration needs architectural update for new key manager structure")
    };

    // This code block is unreachable due to the todo!() above, but it prepares variables
    // for future implementation when the transport integration is completed.
    #[allow(unreachable_code)]
    {
        options = options
            .with_key_manager(node_manager_for_transport)
            .with_local_node_public_key(node_manager_for_transport.get_node_public_key())
            .with_logger_from_node_id(node_id)
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
    // Construct transport
    let transport = match QuicTransport::new(options) {
        Ok(t) => Arc::new(t),
        Err(e) => {
            set_error(err, 2, &format!("Failed to create transport: {e}"));
            return 2;
        }
    };
    let inner = TransportInner {
        logger: keys_inner.logger.clone(),
        transport,
        events_tx: tx,
        events_rx: Mutex::new(rx),
        pending,
        request_id_seq: Arc::new(AtomicU64::new(1)),
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
    path: *const c_char,
    correlation_id: *const c_char,
    payload: *const u8,
    payload_len: usize,
    dest_peer_id: *const c_char,
    profile_pk: *const u8,
    pk_len: usize,
    err: *mut RnError,
) -> i32 {
    if transport.is_null()
        || path.is_null()
        || correlation_id.is_null()
        || payload.is_null()
        || dest_peer_id.is_null()
        || profile_pk.is_null()
    {
        set_error(err, 1, "null argument");
        return 1;
    }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() {
        set_error(err, 1, "invalid transport handle");
        return 1;
    }
    let path = match std::ffi::CStr::from_ptr(path).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_error(err, 2, "invalid utf8");
            return 2;
        }
    };
    let cid = match std::ffi::CStr::from_ptr(correlation_id).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_error(err, 2, "invalid utf8");
            return 2;
        }
    };
    let peer = match std::ffi::CStr::from_ptr(dest_peer_id).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_error(err, 2, "invalid utf8");
            return 2;
        }
    };
    let data = std::slice::from_raw_parts(payload, payload_len).to_vec();
    let pk = std::slice::from_raw_parts(profile_pk, pk_len).to_vec();
    let t = (&*handle.inner).transport.clone();
    let events = (&*handle.inner).events_tx.clone();
    runtime().spawn(async move {
        match t.request(&path, &cid, data, &peer, pk).await {
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
                    serde_cbor::Value::Text(cid),
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
    path: *const c_char,
    correlation_id: *const c_char,
    payload: *const u8,
    payload_len: usize,
    dest_peer_id: *const c_char,
    err: *mut RnError,
) -> i32 {
    if transport.is_null()
        || path.is_null()
        || correlation_id.is_null()
        || payload.is_null()
        || dest_peer_id.is_null()
    {
        set_error(err, 1, "null argument");
        return 1;
    }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() {
        set_error(err, 1, "invalid transport handle");
        return 1;
    }
    let path = match std::ffi::CStr::from_ptr(path).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_error(err, 2, "invalid utf8");
            return 2;
        }
    };
    let cid = match std::ffi::CStr::from_ptr(correlation_id).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_error(err, 2, "invalid utf8");
            return 2;
        }
    };
    let peer = match std::ffi::CStr::from_ptr(dest_peer_id).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_error(err, 2, "invalid utf8");
            return 2;
        }
    };
    let data = std::slice::from_raw_parts(payload, payload_len).to_vec();
    let t = (&*handle.inner).transport.clone();
    runtime().spawn(async move {
        let _ = t.publish(&path, &cid, data, &peer).await;
    });
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_transport_complete_request(
    transport: *mut c_void,
    request_id: *const c_char,
    response_payload: *const u8,
    len: usize,
    profile_pk: *const u8,
    pk_len: usize,
    err: *mut RnError,
) -> i32 {
    if transport.is_null()
        || request_id.is_null()
        || response_payload.is_null()
        || profile_pk.is_null()
    {
        set_error(err, 1, "null argument");
        return 1;
    }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() {
        set_error(err, 1, "invalid transport handle");
        return 1;
    }
    let req_id = match std::ffi::CStr::from_ptr(request_id).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_error(err, 2, "invalid utf8");
            return 2;
        }
    };
    let data = std::slice::from_raw_parts(response_payload, len).to_vec();
    let pk = std::slice::from_raw_parts(profile_pk, pk_len).to_vec();
    let mut map = runtime().block_on((&*handle.inner).pending.lock());
    if let Some(sender) = map.remove(&req_id) {
        let _ = sender.send(runar_transporter::transport::ResponseMessage {
            correlation_id: String::new(),
            payload_bytes: data,
            profile_public_key: pk,
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
