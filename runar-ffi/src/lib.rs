#![allow(clippy::missing_safety_doc)]

use std::{
    ffi::{c_void, CString},
    os::raw::c_char,
    sync::Arc,
};

use runar_common::logging::{Component, Logger};
use runar_keys::{
    mobile::{MobileKeyManager, NodeCertificateMessage, SetupToken},
    node::{NodeKeyManager, NodeKeyManagerState},
};
use runar_transporter::{NetworkTransport, QuicTransport, QuicTransportOptions};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot, Mutex};
use once_cell::sync::OnceCell;
use serde_cbor as _; // keep dependency linked for now

#[repr(C)]
pub struct RnError {
    pub code: i32,
    pub message: *const c_char,
}

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
    node_owned: Option<NodeKeyManager>,
    node_shared: Option<Arc<NodeKeyManager>>, // set after transport construction
    mobile: Option<MobileKeyManager>,
}

#[allow(dead_code)]
struct TransportInner {
    logger: Arc<Logger>,
    transport: Arc<QuicTransport>,
    events_tx: mpsc::Sender<Vec<u8>>,
    events_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    pending: Mutex<std::collections::HashMap<String, oneshot::Sender<runar_transporter::transport::ResponseMessage>>>,
}

#[repr(C)]
pub struct FfiKeysHandle { inner: *mut KeysInner }

fn set_error(err: *mut RnError, code: i32, message: &str) {
    if err.is_null() {
        return;
    }
    let c_msg = CString::new(message).unwrap_or_else(|_| CString::new("ffi error").unwrap());
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

#[no_mangle]
pub unsafe extern "C" fn rn_keys_new(out_keys: *mut *mut c_void, err: *mut RnError) -> i32 {
    if out_keys.is_null() {
        set_error(err, 1, "out_keys is null");
        return 1;
    }
    let logger = Arc::new(Logger::new_root(Component::Keys));
    let node = match NodeKeyManager::new(logger.clone()) {
        Ok(n) => n,
        Err(e) => {
            set_error(err, 2, &format!("Failed to create NodeKeyManager: {e}"));
            return 2;
        }
    };
    // Set node id for logger context
    let node_id = node.get_node_id();
    logger.set_node_id(node_id);

    let inner = KeysInner { logger, node_owned: Some(node), node_shared: None, mobile: None };
    let boxed = Box::new(inner);
    let handle = FfiKeysHandle {
        inner: Box::into_raw(boxed),
    };
    *out_keys = Box::into_raw(Box::new(handle)) as *mut c_void;
    0
}

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
    let pk = if let Some(node) = inner.node_owned.as_ref() {
        node.get_node_public_key()
    } else if let Some(shared) = inner.node_shared.as_ref() {
        shared.get_node_public_key()
    } else {
        set_error(err, 1, "node not initialized");
        return 1;
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
    let node_id = if let Some(node) = inner.node_owned.as_ref() {
        node.get_node_id()
    } else if let Some(shared) = inner.node_shared.as_ref() {
        shared.get_node_id()
    } else {
        set_error(err, 1, "node not initialized");
        return 1;
    };
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
    let token = match inner.node_owned.as_mut() {
        Some(n) => match n.generate_csr() {
            Ok(t) => t,
            Err(e) => {
                set_error(err, 2, &format!("Failed to generate CSR: {e}"));
                return 2;
            }
        },
        None => {
            set_error(err, 1, "node is shared; CSR not available");
            return 1;
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
    if inner.mobile.is_none() {
        // Lazily create a MobileKeyManager to act as CA
        match MobileKeyManager::new(inner.logger.clone()) {
            Ok(m) => inner.mobile = Some(m),
            Err(e) => {
                set_error(err, 2, &format!("Failed to create MobileKeyManager: {e}"));
                return 2;
            }
        }
    }
    let mobile = inner.mobile.as_mut().expect("mobile just created");
    let msg = match mobile.process_setup_token(&token) {
        Ok(m) => m,
        Err(e) => {
            set_error(err, 2, &format!("Failed to process setup token: {e}"));
            return 2;
        }
    };
    let cbor = match serde_cbor::to_vec(&msg) {
        Ok(v) => v,
        Err(e) => {
            set_error(err, 2, &format!("Failed to encode NodeCertificateMessage: {e}"));
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
            set_error(err, 2, &format!("Failed to decode NodeCertificateMessage: {e}"));
            return 2;
        }
    };
    let res = if let Some(n) = inner.node_owned.as_mut() {
        n.install_certificate(msg)
    } else {
        set_error(err, 1, "node is shared; install_certificate not available");
        return 1;
    };
    if let Err(e) = res {
        set_error(err, 2, &format!("Failed to install certificate: {e}"));
        return 2;
    }
    0
}

#[no_mangle]
pub extern "C" fn rn_keys_node_export_state(
    keys: *mut c_void,
    out_state_cbor: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, 1, "keys handle is null");
        return 1;
    };
    let state = if let Some(node) = inner.node_owned.as_ref() {
        node.export_state()
    } else if let Some(shared) = inner.node_shared.as_ref() {
        shared.export_state()
    } else {
        set_error(err, 1, "node not initialized");
        return 1;
    };
    let cbor = match serde_cbor::to_vec(&state) {
        Ok(v) => v,
        Err(e) => {
            set_error(err, 2, &format!("Failed to encode state: {e}"));
            return 2;
        }
    };
    if !alloc_bytes(out_state_cbor, out_len, &cbor) {
        set_error(err, 3, "invalid out pointers");
        return 3;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_import_state(
    keys: *mut c_void,
    state_cbor: *const u8,
    state_len: usize,
    err: *mut RnError,
) -> i32 {
    if keys.is_null() {
        set_error(err, 1, "keys handle is null");
        return 1;
    }
    if state_cbor.is_null() {
        set_error(err, 4, "state_cbor is null");
        return 4;
    }
    let logger = Arc::new(Logger::new_root(Component::Keys));
    let slice = std::slice::from_raw_parts(state_cbor, state_len);
    let state: NodeKeyManagerState = match serde_cbor::from_slice(slice) {
        Ok(s) => s,
        Err(e) => {
            set_error(err, 2, &format!("Failed to decode state: {e}"));
            return 2;
        }
    };
    let node = match NodeKeyManager::from_state(state, logger.clone()) {
        Ok(n) => n,
        Err(e) => {
            set_error(err, 2, &format!("Failed to import state: {e}"));
            return 2;
        }
    };
    let node_id = node.get_node_id();
    logger.set_node_id(node_id);
    // Replace inner
    let handle = &mut *(keys as *mut FfiKeysHandle);
    if !handle.inner.is_null() {
        let _old = Box::from_raw(handle.inner);
    }
    handle.inner = Box::into_raw(Box::new(KeysInner { logger, node_owned: Some(node), node_shared: None, mobile: None }));
    0
}

#[no_mangle]
pub extern "C" fn rn_keys_mobile_export_state(
    keys: *mut c_void,
    out_state_cbor: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, 1, "keys handle is null");
        return 1;
    };
    if inner.mobile.is_none() {
        match MobileKeyManager::new(inner.logger.clone()) {
            Ok(m) => inner.mobile = Some(m),
            Err(e) => {
                set_error(err, 2, &format!("Failed to create MobileKeyManager: {e}"));
                return 2;
            }
        }
    }
    let mobile = inner.mobile.as_ref().expect("mobile ensured");
    let state = mobile.export_state();
    let cbor = match serde_cbor::to_vec(&state) {
        Ok(v) => v,
        Err(e) => {
            set_error(err, 2, &format!("Failed to encode mobile state: {e}"));
            return 2;
        }
    };
    if !alloc_bytes(out_state_cbor, out_len, &cbor) {
        set_error(err, 3, "invalid out pointers");
        return 3;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_mobile_import_state(
    keys: *mut c_void,
    state_cbor: *const u8,
    state_len: usize,
    err: *mut RnError,
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, 1, "keys handle is null");
        return 1;
    };
    if state_cbor.is_null() {
        set_error(err, 4, "state_cbor is null");
        return 4;
    }
    let slice = std::slice::from_raw_parts(state_cbor, state_len);
    let state: runar_keys::mobile::MobileKeyManagerState = match serde_cbor::from_slice(slice) {
        Ok(s) => s,
        Err(e) => {
            set_error(err, 2, &format!("Failed to decode mobile state: {e}"));
            return 2;
        }
    };
    let mobile = match MobileKeyManager::from_state(state, inner.logger.clone()) {
        Ok(m) => m,
        Err(e) => {
            set_error(err, 2, &format!("Failed to import mobile state: {e}"));
            return 2;
        }
    };
    inner.mobile = Some(mobile);
    0
}

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
                    "handshake_timeout_ms" => if let serde_cbor::Value::Integer(ms) = v { if ms > 0 { options = options.with_handshake_response_timeout(std::time::Duration::from_millis(ms as u64)); } },
                    "open_stream_timeout_ms" => if let serde_cbor::Value::Integer(ms) = v { if ms > 0 { options = options.with_open_stream_timeout(std::time::Duration::from_millis(ms as u64)); } },
                    "max_message_size" => if let serde_cbor::Value::Integer(sz) = v { if sz > 0 { options = options.with_max_message_size(sz as usize); } },
                    _ => {}
                }
            }
        }
    }
    // Wire key manager and local pk/logger
    let node_arc = if let Some(n) = keys_inner.node_owned.take() {
        let arc = Arc::new(n);
        keys_inner.node_shared = Some(arc.clone());
        arc
    } else if let Some(arc) = keys_inner.node_shared.as_ref() {
        arc.clone()
    } else { set_error(err, 1, "node not initialized"); return 1; };
    let node_id = node_arc.get_node_id();
    let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);

    // For now, we don't wire callbacks here; will enable in later iteration
    options = options
        .with_key_manager(node_arc.clone())
        .with_local_node_public_key(node_arc.get_node_public_key())
        .with_logger_from_node_id(node_id);
    // Construct transport
    let transport = match QuicTransport::new(options) {
        Ok(t) => Arc::new(t),
        Err(e) => {
            set_error(err, 2, &format!("Failed to create transport: {e}"));
            return 2;
        }
    };
    let inner = TransportInner { logger: keys_inner.logger.clone(), transport, events_tx: tx, events_rx: Mutex::new(rx), pending: Mutex::new(std::collections::HashMap::new()) };
    let handle = FfiTransportHandle { inner: Box::into_raw(Box::new(inner)) };
    *out_transport = Box::into_raw(Box::new(handle)) as *mut c_void;
    0
}

#[no_mangle]
pub extern "C" fn rn_transport_free(transport: *mut c_void) {
    if transport.is_null() { return; }
    unsafe {
        let handle = Box::from_raw(transport as *mut FfiTransportHandle);
        if !handle.inner.is_null() { let _ = Box::from_raw(handle.inner); }
    }
}
// Shared runtime (Option C)
static RUNTIME: OnceCell<Runtime> = OnceCell::new();
fn runtime() -> &'static Runtime { RUNTIME.get_or_init(|| Runtime::new().expect("tokio runtime")) }

#[no_mangle]
pub unsafe extern "C" fn rn_transport_start(transport: *mut c_void, err: *mut RnError) -> i32 {
    if transport.is_null() { set_error(err, 1, "transport is null"); return 1; }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() { set_error(err, 1, "invalid transport handle"); return 1; }
    let t = (&*handle.inner).transport.clone();
    let res = runtime().block_on(async move { Arc::clone(&t).start().await });
    if let Err(e) = res { set_error(err, 2, &format!("Failed to start transport: {e}")); return 2; }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_transport_stop(transport: *mut c_void, err: *mut RnError) -> i32 {
    if transport.is_null() { set_error(err, 1, "transport is null"); return 1; }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() { set_error(err, 1, "invalid transport handle"); return 1; }
    let res = runtime().block_on((&*handle.inner).transport.stop());
    if let Err(e) = res { set_error(err, 2, &format!("Failed to stop transport: {e}")); return 2; }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_transport_local_addr(
    transport: *mut c_void,
    out_str: *mut *mut c_char,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if transport.is_null() { set_error(err, 1, "transport is null"); return 1; }
    if out_str.is_null() || out_len.is_null() { set_error(err, 1, "null out"); return 1; }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() { set_error(err, 1, "invalid transport handle"); return 1; }
    let addr = (&*handle.inner).transport.get_local_address();
    if !alloc_string(out_str, out_len, &addr) { set_error(err, 3, "alloc failed"); return 3; }
    0
}
