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
use runar_transporter::discovery::multicast_discovery::PeerInfo;
use runar_schemas::NodeInfo;
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot, Mutex};
use once_cell::sync::OnceCell;
use std::sync::atomic::AtomicU64;
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
    pending: Arc<Mutex<std::collections::HashMap<String, oneshot::Sender<runar_transporter::transport::ResponseMessage>>>>,
    request_id_seq: Arc<AtomicU64>,
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

    // Build callbacks to emit events
    let pc_tx = tx.clone();
    let pc_cb: runar_transporter::transport::PeerConnectedCallback = Arc::new(move |peer_id, node_info| {
        let pc_tx = pc_tx.clone();
        Box::pin(async move {
            let mut map = std::collections::BTreeMap::new();
            map.insert(serde_cbor::Value::Text("type".into()), serde_cbor::Value::Text("PeerConnected".into()));
            map.insert(serde_cbor::Value::Text("v".into()), serde_cbor::Value::Integer(1));
            map.insert(serde_cbor::Value::Text("peer_node_id".into()), serde_cbor::Value::Text(peer_id));
            let ni = serde_cbor::to_vec(&node_info).unwrap_or_default();
            map.insert(serde_cbor::Value::Text("node_info".into()), serde_cbor::Value::Bytes(ni));
            let _ = pc_tx.send(serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap_or_default()).await;
        })
    });

    let pd_tx = tx.clone();
    let pd_cb: runar_transporter::transport::PeerDisconnectedCallback = Arc::new(move |peer_id| {
        let pd_tx = pd_tx.clone();
        Box::pin(async move {
            let mut map = std::collections::BTreeMap::new();
            map.insert(serde_cbor::Value::Text("type".into()), serde_cbor::Value::Text("PeerDisconnected".into()));
            map.insert(serde_cbor::Value::Text("v".into()), serde_cbor::Value::Integer(1));
            map.insert(serde_cbor::Value::Text("peer_node_id".into()), serde_cbor::Value::Text(peer_id));
            let _ = pd_tx.send(serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap_or_default()).await;
        })
    });

    let req_tx = tx.clone();
    let pending: Arc<Mutex<std::collections::HashMap<String, oneshot::Sender<runar_transporter::transport::ResponseMessage>>>> = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let pending_cb = pending.clone();
    let rq_cb: runar_transporter::transport::RequestCallback = Arc::new(move |req| {
        let req_tx = req_tx.clone();
        let pending_cb = pending_cb.clone();
        Box::pin(async move {
            let request_id = uuid::Uuid::new_v4().to_string();
            let (tx_resp, rx_resp) = oneshot::channel();
            pending_cb.lock().await.insert(request_id.clone(), tx_resp);

            let mut map = std::collections::BTreeMap::new();
            map.insert(serde_cbor::Value::Text("type".into()), serde_cbor::Value::Text("RequestReceived".into()));
            map.insert(serde_cbor::Value::Text("v".into()), serde_cbor::Value::Integer(1));
            map.insert(serde_cbor::Value::Text("request_id".into()), serde_cbor::Value::Text(request_id));
            map.insert(serde_cbor::Value::Text("path".into()), serde_cbor::Value::Text(req.path));
            map.insert(serde_cbor::Value::Text("correlation_id".into()), serde_cbor::Value::Text(req.correlation_id));
            map.insert(serde_cbor::Value::Text("payload".into()), serde_cbor::Value::Bytes(req.payload_bytes));
            map.insert(serde_cbor::Value::Text("profile_public_key".into()), serde_cbor::Value::Bytes(req.profile_public_key));
            let _ = req_tx.send(serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap_or_default()).await;

            match rx_resp.await {
                Ok(resp) => Ok(resp),
                Err(_) => Ok(runar_transporter::transport::ResponseMessage { correlation_id: String::new(), payload_bytes: Vec::new(), profile_public_key: Vec::new() }),
            }
        })
    });

    let ev_tx = tx.clone();
    let ev_cb: runar_transporter::transport::EventCallback = Arc::new(move |ev| {
        let ev_tx = ev_tx.clone();
        Box::pin(async move {
            let mut map = std::collections::BTreeMap::new();
            map.insert(serde_cbor::Value::Text("type".into()), serde_cbor::Value::Text("EventReceived".into()));
            map.insert(serde_cbor::Value::Text("v".into()), serde_cbor::Value::Integer(1));
            map.insert(serde_cbor::Value::Text("path".into()), serde_cbor::Value::Text(ev.path));
            map.insert(serde_cbor::Value::Text("correlation_id".into()), serde_cbor::Value::Text(ev.correlation_id));
            map.insert(serde_cbor::Value::Text("payload".into()), serde_cbor::Value::Bytes(ev.payload_bytes));
            let _ = ev_tx.send(serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap_or_default()).await;
            Ok(())
        })
    });

    options = options
        .with_key_manager(node_arc.clone())
        .with_local_node_public_key(node_arc.get_node_public_key())
        .with_logger_from_node_id(node_id)
        .with_peer_connected_callback(pc_cb)
        .with_peer_disconnected_callback(pd_cb)
        .with_request_callback(rq_cb)
        .with_event_callback(ev_cb);
    // Construct transport
    let transport = match QuicTransport::new(options) {
        Ok(t) => Arc::new(t),
        Err(e) => {
            set_error(err, 2, &format!("Failed to create transport: {e}"));
            return 2;
        }
    };
    let inner = TransportInner { logger: keys_inner.logger.clone(), transport, events_tx: tx, events_rx: Mutex::new(rx), pending, request_id_seq: Arc::new(AtomicU64::new(1)) };
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
pub unsafe extern "C" fn rn_transport_poll_event(
    transport: *mut c_void,
    out_event: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    if transport.is_null() { set_error(err, 1, "transport is null"); return 1; }
    if out_event.is_null() || out_len.is_null() { set_error(err, 1, "null out"); return 1; }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() { set_error(err, 1, "invalid transport handle"); return 1; }
    let inner = &*handle.inner;
    let mut rx = runtime().block_on(inner.events_rx.lock());
    match rx.try_recv() {
        Ok(buf) => {
            if !alloc_bytes(out_event, out_len, &buf) { set_error(err, 3, "alloc failed"); return 3; }
            0
        }
        Err(mpsc::error::TryRecvError::Empty) => {
            *out_event = std::ptr::null_mut();
            *out_len = 0;
            0
        }
        Err(_) => { set_error(err, 2, "event channel closed"); 2 }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rn_transport_connect_peer(
    transport: *mut c_void,
    peer_info_cbor: *const u8,
    len: usize,
    err: *mut RnError,
) -> i32 {
    if transport.is_null() || peer_info_cbor.is_null() { set_error(err, 1, "null argument"); return 1; }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() { set_error(err, 1, "invalid transport handle"); return 1; }
    let slice = std::slice::from_raw_parts(peer_info_cbor, len);
    let peer: PeerInfo = match serde_cbor::from_slice(slice) { Ok(p) => p, Err(e) => { set_error(err, 2, &format!("decode PeerInfo: {e}")); return 2; } };
    let t = (&*handle.inner).transport.clone();
    let res = runtime().block_on(async move { Arc::clone(&t).connect_peer(peer).await });
    if let Err(e) = res { set_error(err, 2, &format!("connect_peer failed: {e}")); return 2; }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_transport_disconnect_peer(
    transport: *mut c_void,
    peer_node_id: *const c_char,
    err: *mut RnError,
) -> i32 {
    if transport.is_null() || peer_node_id.is_null() { set_error(err, 1, "null argument"); return 1; }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() { set_error(err, 1, "invalid transport handle"); return 1; }
    let id = match std::ffi::CStr::from_ptr(peer_node_id).to_str() { Ok(s) => s.to_string(), Err(_) => { set_error(err, 2, "invalid utf8"); return 2; } };
    let res = runtime().block_on((&*handle.inner).transport.disconnect(&id));
    if let Err(e) = res { set_error(err, 2, &format!("disconnect failed: {e}")); return 2; }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rn_transport_is_connected(
    transport: *mut c_void,
    peer_node_id: *const c_char,
    out_connected: *mut bool,
    err: *mut RnError,
) -> i32 {
    if transport.is_null() || peer_node_id.is_null() || out_connected.is_null() { set_error(err, 1, "null argument"); return 1; }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() { set_error(err, 1, "invalid transport handle"); return 1; }
    let id = match std::ffi::CStr::from_ptr(peer_node_id).to_str() { Ok(s) => s.to_string(), Err(_) => { set_error(err, 2, "invalid utf8"); return 2; } };
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
    if transport.is_null() || node_info_cbor.is_null() { set_error(err, 1, "null argument"); return 1; }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() { set_error(err, 1, "invalid transport handle"); return 1; }
    let slice = std::slice::from_raw_parts(node_info_cbor, len);
    let node_info: NodeInfo = match serde_cbor::from_slice(slice) { Ok(v) => v, Err(e) => { set_error(err, 2, &format!("decode NodeInfo: {e}")); return 2; } };
    let res = runtime().block_on((&*handle.inner).transport.update_peers(node_info));
    if let Err(e) = res { set_error(err, 2, &format!("update_peers failed: {e}")); return 2; }
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
    if transport.is_null() || path.is_null() || correlation_id.is_null() || payload.is_null() || dest_peer_id.is_null() || profile_pk.is_null() { set_error(err, 1, "null argument"); return 1; }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() { set_error(err, 1, "invalid transport handle"); return 1; }
    let path = match std::ffi::CStr::from_ptr(path).to_str() { Ok(s) => s.to_string(), Err(_) => { set_error(err, 2, "invalid utf8"); return 2; } };
    let cid = match std::ffi::CStr::from_ptr(correlation_id).to_str() { Ok(s) => s.to_string(), Err(_) => { set_error(err, 2, "invalid utf8"); return 2; } };
    let peer = match std::ffi::CStr::from_ptr(dest_peer_id).to_str() { Ok(s) => s.to_string(), Err(_) => { set_error(err, 2, "invalid utf8"); return 2; } };
    let data = std::slice::from_raw_parts(payload, payload_len).to_vec();
    let pk = std::slice::from_raw_parts(profile_pk, pk_len).to_vec();
    let t = (&*handle.inner).transport.clone();
    let events = (&*handle.inner).events_tx.clone();
    runtime().spawn(async move {
        match t.request(&path, &cid, data, &peer, pk).await {
            Ok(resp) => {
                let mut map = std::collections::BTreeMap::new();
                map.insert(serde_cbor::Value::Text("type".into()), serde_cbor::Value::Text("ResponseReceived".into()));
                map.insert(serde_cbor::Value::Text("v".into()), serde_cbor::Value::Integer(1));
                map.insert(serde_cbor::Value::Text("correlation_id".into()), serde_cbor::Value::Text(cid));
                map.insert(serde_cbor::Value::Text("payload".into()), serde_cbor::Value::Bytes(resp));
                let _ = events.send(serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap_or_default()).await;
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
    if transport.is_null() || path.is_null() || correlation_id.is_null() || payload.is_null() || dest_peer_id.is_null() { set_error(err, 1, "null argument"); return 1; }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() { set_error(err, 1, "invalid transport handle"); return 1; }
    let path = match std::ffi::CStr::from_ptr(path).to_str() { Ok(s) => s.to_string(), Err(_) => { set_error(err, 2, "invalid utf8"); return 2; } };
    let cid = match std::ffi::CStr::from_ptr(correlation_id).to_str() { Ok(s) => s.to_string(), Err(_) => { set_error(err, 2, "invalid utf8"); return 2; } };
    let peer = match std::ffi::CStr::from_ptr(dest_peer_id).to_str() { Ok(s) => s.to_string(), Err(_) => { set_error(err, 2, "invalid utf8"); return 2; } };
    let data = std::slice::from_raw_parts(payload, payload_len).to_vec();
    let t = (&*handle.inner).transport.clone();
    runtime().spawn(async move { let _ = t.publish(&path, &cid, data, &peer).await; });
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
    if transport.is_null() || request_id.is_null() || response_payload.is_null() || profile_pk.is_null() { set_error(err, 1, "null argument"); return 1; }
    let handle = &mut *(transport as *mut FfiTransportHandle);
    if handle.inner.is_null() { set_error(err, 1, "invalid transport handle"); return 1; }
    let req_id = match std::ffi::CStr::from_ptr(request_id).to_str() { Ok(s) => s.to_string(), Err(_) => { set_error(err, 2, "invalid utf8"); return 2; } };
    let data = std::slice::from_raw_parts(response_payload, len).to_vec();
    let pk = std::slice::from_raw_parts(profile_pk, pk_len).to_vec();
    let mut map = runtime().block_on((&*handle.inner).pending.lock());
    if let Some(sender) = map.remove(&req_id) {
        let _ = sender.send(runar_transporter::transport::ResponseMessage { correlation_id: String::new(), payload_bytes: data, profile_public_key: pk });
        0
    } else {
        set_error(err, 2, "unknown request_id");
        2
    }
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
