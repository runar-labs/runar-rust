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
    _priv: *mut c_void,
}

struct KeysInner {
    logger: Arc<Logger>,
    node: NodeKeyManager,
    mobile: Option<MobileKeyManager>,
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

    let inner = KeysInner {
        logger,
        node,
        mobile: None,
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
    let pk = inner.node.get_node_public_key();
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
    let node_id = inner.node.get_node_id();
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
    let token = match inner.node.generate_csr() {
        Ok(t) => t,
        Err(e) => {
            set_error(err, 2, &format!("Failed to generate CSR: {e}"));
            return 2;
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
    if let Err(e) = inner.node.install_certificate(msg) {
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
    let state = inner.node.export_state();
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
    handle.inner = Box::into_raw(Box::new(KeysInner { logger, node, mobile: None }));
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
pub extern "C" fn rn_transport_new_with_keys(
    _keys: *mut c_void,
    _options_cbor: *const u8,
    _options_len: usize,
    _out_transport: *mut *mut c_void,
    _err: *mut RnError,
) -> i32 {
    -1
}

#[no_mangle]
pub extern "C" fn rn_transport_free(_transport: *mut c_void) {}


