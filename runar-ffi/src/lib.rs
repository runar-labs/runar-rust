#![allow(clippy::missing_safety_doc)]

use std::ffi::c_void;

#[repr(C)]
pub struct RnError {
    pub code: i32,
    pub message: *const i8,
}

// Minimal memory helpers (placeholders; to be filled during implementation)
#[no_mangle]
pub extern "C" fn rn_free(_p: *mut u8, _len: usize) {}

#[no_mangle]
pub extern "C" fn rn_string_free(_s: *const i8) {}

// Placeholders for handles to satisfy linkage while we implement
#[repr(C)]
pub struct FfiKeysHandle {
    _priv: *mut c_void,
}
#[repr(C)]
pub struct FfiTransportHandle {
    _priv: *mut c_void,
}

#[no_mangle]
pub extern "C" fn rn_keys_new(_out_keys: *mut *mut c_void, _err: *mut RnError) -> i32 {
    -1
}

#[no_mangle]
pub extern "C" fn rn_keys_free(_keys: *mut c_void) {}

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


