#![allow(clippy::missing_safety_doc)]

use std::{
    ffi::{c_void, CString},
    os::raw::c_char,
    sync::Arc,
};

use once_cell::sync::OnceCell;
use runar_common::logging::{Component, Logger};
use runar_keys::EnvelopeCrypto;
use runar_keys::{
    mobile::{MobileKeyManager, NodeCertificateMessage, SetupToken},
    node::{NodeKeyManager, NodeKeyManagerState},
};
use runar_schemas::NodeInfo;
use runar_serializer::traits::{LabelKeyInfo, LabelResolver};
use runar_transporter::discovery::multicast_discovery::PeerInfo;
use runar_transporter::discovery::{DiscoveryEvent, DiscoveryOptions, MulticastDiscovery};
use runar_transporter::{NetworkTransport, NodeDiscovery, QuicTransport, QuicTransportOptions};
use serde_cbor as _; // keep dependency linked for now
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::AtomicU64;
use std::sync::Mutex as StdMutex;
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot, Mutex};

#[repr(C)]
pub struct RnError {
    pub code: i32,
    pub message: *const c_char,
}

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
    node_owned: Option<NodeKeyManager>,
    node_shared: Option<Arc<NodeKeyManager>>, // set after transport construction
    mobile: Option<MobileKeyManager>,
    // Optional platform-provided label resolver
    label_resolver: Option<Arc<dyn LabelResolver>>,
    // Optional platform-provided local NodeInfo callback
    get_local_node_info_cb: Option<RnGetLocalNodeInfoFn>,
}

#[allow(dead_code)]
struct TransportInner {
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
    request_id_seq: Arc<AtomicU64>,
}

#[allow(dead_code)]
struct DiscoveryInner {
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
            Err(_) => return 2,
        };
    let resolver = runar_serializer::traits::ConfigurableLabelResolver::from_map(mapping);
    inner.label_resolver = Some(Arc::new(resolver));
    0
}

type RnGetLocalNodeInfoFn =
    unsafe extern "C" fn(out_cbor_ptr: *mut *mut u8, out_cbor_len: *mut usize) -> i32;

#[no_mangle]
pub extern "C" fn rn_keys_set_get_local_node_info(
    keys: *mut c_void,
    cb: RnGetLocalNodeInfoFn,
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        return 1;
    };
    inner.get_local_node_info_cb = Some(cb);
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

// Envelope helpers (CBOR EED)
#[no_mangle]
pub unsafe extern "C" fn rn_keys_encrypt_with_envelope(
    keys: *mut c_void,
    data: *const u8,
    data_len: usize,
    network_id_or_null: *const c_char,
    profile_pks: *const *const u8,
    profile_lens: *const usize,
    profiles_count: usize,
    out_eed_cbor: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    ffi_guard(err, || {
        if keys.is_null() || data.is_null() || out_eed_cbor.is_null() || out_len.is_null() {
            set_error(err, 1, "null argument");
            return 1;
        }
        let Some(inner) = with_keys_inner(keys) else {
            set_error(err, 1, "invalid keys handle");
            return 1;
        };
        let data_slice = std::slice::from_raw_parts(data, data_len);
        let network_id_opt = if network_id_or_null.is_null() {
            None
        } else {
            match std::ffi::CStr::from_ptr(network_id_or_null).to_str() {
                Ok(s) => Some(s.to_string()),
                Err(_) => {
                    set_error(err, 2, "invalid utf8 network id");
                    return 2;
                }
            }
        };
        // Collect profile keys
        let mut profiles: Vec<Vec<u8>> = Vec::new();
        if profiles_count > 0 && !profile_pks.is_null() && !profile_lens.is_null() {
            for i in 0..profiles_count {
                let pk_ptr = unsafe { *profile_pks.add(i) };
                let len = unsafe { *profile_lens.add(i) };
                if pk_ptr.is_null() {
                    continue;
                }
                let pk = unsafe { std::slice::from_raw_parts(pk_ptr, len) };
                profiles.push(pk.to_vec());
            }
        }
        // Prefer node-owned crypto trait
        let eed = if let Some(node) = inner.node_owned.as_ref() {
            match node.encrypt_with_envelope(data_slice, network_id_opt.as_ref(), profiles) {
                Ok(e) => e,
                Err(e) => {
                    set_error(err, 2, &format!("encrypt_with_envelope failed: {e}"));
                    return 2;
                }
            }
        } else if let Some(shared) = inner.node_shared.as_ref() {
            match shared.encrypt_with_envelope(data_slice, network_id_opt.as_ref(), profiles) {
                Ok(e) => e,
                Err(e) => {
                    set_error(err, 2, &format!("encrypt_with_envelope failed: {e}"));
                    return 2;
                }
            }
        } else if let Some(m) = inner.mobile.as_ref() {
            match m.encrypt_with_envelope(data_slice, network_id_opt.as_deref(), profiles) {
                Ok(e) => e,
                Err(e) => {
                    set_error(err, 2, &format!("encrypt_with_envelope failed: {e}"));
                    return 2;
                }
            }
        } else {
            set_error(err, 1, "no key manager available");
            return 1;
        };
        let cbor = match serde_cbor::to_vec(&eed) {
            Ok(v) => v,
            Err(e) => {
                set_error(err, 2, &format!("encode EED failed: {e}"));
                return 2;
            }
        };
        if !alloc_bytes(out_eed_cbor, out_len, &cbor) {
            set_error(err, 3, "alloc failed");
            return 3;
        }
        0
    })
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_decrypt_envelope(
    keys: *mut c_void,
    eed_cbor: *const u8,
    eed_len: usize,
    out_plain: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    ffi_guard(err, || {
        if keys.is_null() || eed_cbor.is_null() || out_plain.is_null() || out_len.is_null() {
            set_error(err, 1, "null argument");
            return 1;
        }
        let Some(inner) = with_keys_inner(keys) else {
            set_error(err, 1, "invalid keys handle");
            return 1;
        };
        let slice = std::slice::from_raw_parts(eed_cbor, eed_len);
        let eed: runar_keys::mobile::EnvelopeEncryptedData = match serde_cbor::from_slice(slice) {
            Ok(v) => v,
            Err(e) => {
                set_error(err, 2, &format!("decode EED failed: {e}"));
                return 2;
            }
        };
        let plain = if let Some(node) = inner.node_owned.as_ref() {
            match node.decrypt_envelope_data(&eed) {
                Ok(p) => p,
                Err(e) => {
                    set_error(err, 2, &format!("decrypt failed: {e}"));
                    return 2;
                }
            }
        } else if let Some(shared) = inner.node_shared.as_ref() {
            match shared.decrypt_envelope_data(&eed) {
                Ok(p) => p,
                Err(e) => {
                    set_error(err, 2, &format!("decrypt failed: {e}"));
                    return 2;
                }
            }
        } else if let Some(m) = inner.mobile.as_ref() {
            match m.decrypt_envelope_data(&eed) {
                Ok(p) => p,
                Err(e) => {
                    set_error(err, 2, &format!("decrypt failed: {e}"));
                    return 2;
                }
            }
        } else {
            set_error(err, 1, "no key manager available");
            return 1;
        };
        if !alloc_bytes(out_plain, out_len, &plain) {
            set_error(err, 3, "alloc failed");
            return 3;
        }
        0
    })
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

fn ffi_guard<F>(err: *mut RnError, f: F) -> i32
where
    F: FnOnce() -> i32,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(code) => code,
        Err(_) => {
            set_error(err, 1000, "panic in FFI call");
            1000
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rn_discovery_new_with_multicast(
    keys: *mut c_void,
    options_cbor: *const u8,
    options_len: usize,
    out_discovery: *mut *mut c_void,
    err: *mut RnError,
) -> i32 {
    ffi_guard(err, || {
        if keys.is_null() || options_cbor.is_null() || out_discovery.is_null() {
            set_error(err, 1, "null argument");
            return 1;
        }
        let Some(keys_inner) = with_keys_inner(keys) else {
            set_error(err, 1, "invalid keys handle");
            return 1;
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

        let node_pk = if let Some(n) = keys_inner.node_owned.as_ref() {
            n.get_node_public_key()
        } else if let Some(shared) = keys_inner.node_shared.as_ref() {
            shared.get_node_public_key()
        } else {
            set_error(err, 1, "node not initialized");
            return 1;
        };

        let local_peer = PeerInfo {
            public_key: node_pk,
            addresses,
        };
        let logger = keys_inner.logger.as_ref().clone();
        let disc = match runtime().block_on(MulticastDiscovery::new(local_peer, opts, logger)) {
            Ok(d) => Arc::new(d),
            Err(e) => {
                set_error(err, 2, &format!("Failed to create discovery: {e}"));
                return 2;
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
    })
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
    ffi_guard(err, || {
        if discovery.is_null() || options_cbor.is_null() {
            set_error(err, 1, "null argument");
            return 1;
        }
        let Some(inner) = with_discovery_inner(discovery) else {
            set_error(err, 1, "invalid discovery handle");
            return 1;
        };
        let slice = std::slice::from_raw_parts(options_cbor, options_len);
        let opts = parse_discovery_options(slice);
        if let Err(e) = runtime().block_on(inner.discovery.init(opts)) {
            set_error(err, 2, &format!("init failed: {e}"));
            return 2;
        }
        0
    })
}

#[no_mangle]
pub unsafe extern "C" fn rn_discovery_bind_events_to_transport(
    discovery: *mut c_void,
    transport: *mut c_void,
    err: *mut RnError,
) -> i32 {
    ffi_guard(err, || {
        let Some(disc) = with_discovery_inner(discovery) else {
            set_error(err, 1, "invalid discovery handle");
            return 1;
        };
        if transport.is_null() {
            set_error(err, 1, "null transport");
            return 1;
        }
        let t = &mut *(transport as *mut FfiTransportHandle);
        if t.inner.is_null() {
            set_error(err, 1, "invalid transport handle");
            return 1;
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
            set_error(err, 2, &format!("subscribe failed: {e}"));
            return 2;
        }
        0
    })
}

#[no_mangle]
pub unsafe extern "C" fn rn_discovery_start_announcing(
    discovery: *mut c_void,
    err: *mut RnError,
) -> i32 {
    ffi_guard(err, || {
        let Some(inner) = with_discovery_inner(discovery) else {
            set_error(err, 1, "invalid discovery handle");
            return 1;
        };
        if let Err(e) = runtime().block_on(inner.discovery.start_announcing()) {
            set_error(err, 2, &format!("start_announcing failed: {e}"));
            return 2;
        }
        0
    })
}

#[no_mangle]
pub unsafe extern "C" fn rn_discovery_stop_announcing(
    discovery: *mut c_void,
    err: *mut RnError,
) -> i32 {
    ffi_guard(err, || {
        let Some(inner) = with_discovery_inner(discovery) else {
            set_error(err, 1, "invalid discovery handle");
            return 1;
        };
        if let Err(e) = runtime().block_on(inner.discovery.stop_announcing()) {
            set_error(err, 2, &format!("stop_announcing failed: {e}"));
            return 2;
        }
        0
    })
}

#[no_mangle]
pub unsafe extern "C" fn rn_discovery_shutdown(discovery: *mut c_void, err: *mut RnError) -> i32 {
    ffi_guard(err, || {
        let Some(inner) = with_discovery_inner(discovery) else {
            set_error(err, 1, "invalid discovery handle");
            return 1;
        };
        if let Err(e) = runtime().block_on(inner.discovery.shutdown()) {
            set_error(err, 2, &format!("shutdown failed: {e}"));
            return 2;
        }
        0
    })
}

#[no_mangle]
pub unsafe extern "C" fn rn_discovery_update_local_peer_info(
    discovery: *mut c_void,
    peer_info_cbor: *const u8,
    len: usize,
    err: *mut RnError,
) -> i32 {
    ffi_guard(err, || {
        if discovery.is_null() || peer_info_cbor.is_null() {
            set_error(err, 1, "null argument");
            return 1;
        }
        let Some(inner) = with_discovery_inner(discovery) else {
            set_error(err, 1, "invalid discovery handle");
            return 1;
        };
        let slice = std::slice::from_raw_parts(peer_info_cbor, len);
        let peer: PeerInfo = match serde_cbor::from_slice(slice) {
            Ok(p) => p,
            Err(e) => {
                set_error(err, 2, &format!("decode PeerInfo: {e}"));
                return 2;
            }
        };
        if let Err(e) = runtime().block_on(inner.discovery.update_local_peer_info(peer)) {
            set_error(err, 2, &format!("update_local_peer_info failed: {e}"));
            return 2;
        }
        0
    })
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

    let inner = KeysInner {
        logger,
        node_owned: Some(node),
        node_shared: None,
        mobile: None,
        label_resolver: None,
        get_local_node_info_cb: None,
    };
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
    handle.inner = Box::into_raw(Box::new(KeysInner {
        logger,
        node_owned: Some(node),
        node_shared: None,
        mobile: None,
        label_resolver: None,
        get_local_node_info_cb: None,
    }));
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
    let node_arc = if let Some(n) = keys_inner.node_owned.take() {
        let arc = Arc::new(n);
        keys_inner.node_shared = Some(arc.clone());
        arc
    } else if let Some(arc) = keys_inner.node_shared.as_ref() {
        arc.clone()
    } else {
        set_error(err, 1, "node not initialized");
        return 1;
    };
    let node_id = node_arc.get_node_id();
    let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);

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
                oneshot::Sender<runar_transporter::transport::ResponseMessage>,
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
        options = options.with_label_resolver(resolver);
    }
    options = options
        .with_key_manager(node_arc.clone())
        .with_local_node_public_key(node_arc.get_node_public_key())
        .with_logger_from_node_id(node_id)
        .with_peer_connected_callback(pc_cb)
        .with_peer_disconnected_callback(pd_cb)
        .with_request_callback(rq_cb)
        .with_event_callback(ev_cb);

    // Wire platform-provided get_local_node_info if set
    if let Some(cb) = keys_inner.get_local_node_info_cb {
        let get_local_node_info_cb: runar_transporter::transport::GetLocalNodeInfoCallback =
            Arc::new(move || {
                let cb = cb;
                Box::pin(async move {
                    let mut ptr: *mut u8 = std::ptr::null_mut();
                    let mut len: usize = 0;
                    let rc = unsafe { cb(&mut ptr as *mut *mut u8, &mut len as *mut usize) };
                    if rc != 0 || ptr.is_null() || len == 0 {
                        return Err(anyhow::anyhow!("get_local_node_info failed"));
                    }
                    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
                    let info: runar_schemas::NodeInfo = serde_cbor::from_slice(slice)
                        .map_err(|e| anyhow::anyhow!("decode NodeInfo: {e}"))?;
                    Ok(info)
                })
            });
        options = options.with_get_local_node_info(get_local_node_info_cb);
    }
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
