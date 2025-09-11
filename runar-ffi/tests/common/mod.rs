//! Common test utilities for FFI tests
//!
//! This module provides shared helper functions and test utilities that can be used
//! across all test files, eliminating duplication and ensuring consistency.

use runar_ffi::*;
use std::ffi::c_void;
use std::ptr;

// Allow dead code warnings since these functions are used across different test files
// but the compiler doesn't recognize this due to separate compilation
/// Create a fresh keys handle for testing
#[allow(dead_code)]
pub fn create_keys_handle() -> *mut c_void {
    let mut keys: *mut c_void = ptr::null_mut();
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let result = unsafe { rn_keys_new(&mut keys as *mut *mut c_void, &mut error) };
    assert_eq!(result, 0, "Failed to create keys handle");
    assert!(!keys.is_null(), "Keys handle should not be null");

    keys
}

/// Destroy keys handle and free memory
#[allow(dead_code)]
pub fn destroy_keys_handle(keys: *mut c_void) {
    if !keys.is_null() {
        rn_keys_free(keys);
    }
}

/// Initialize keys handle as mobile key manager
///
/// # Safety
///
/// The `keys` parameter must be a valid, non-null pointer to a keys handle.
/// The caller is responsible for ensuring the pointer is valid and properly aligned.
#[allow(dead_code)]
pub unsafe fn init_as_mobile(keys: *mut c_void) {
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };
    let result = unsafe { rn_keys_init_as_mobile(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully initialize as mobile");
}

/// Initialize keys handle as node key manager
///
/// # Safety
///
/// The `keys` parameter must be a valid, non-null pointer to a keys handle.
/// The caller is responsible for ensuring the pointer is valid and properly aligned.
#[allow(dead_code)]
pub unsafe fn init_as_node(keys: *mut c_void) {
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };
    let result = unsafe { rn_keys_init_as_node(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully initialize as node");
}

/// Create a test error structure
#[allow(dead_code)]
pub fn create_test_error() -> RnError {
    RnError {
        code: 0,
        message: ptr::null(),
    }
}

/// Helper to create a CString from a string slice
#[allow(dead_code)]
pub fn create_cstring(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s).expect("Failed to create CString")
}

/// Create a test logger for CA operations
#[allow(dead_code)]
pub fn create_test_logger() -> *mut c_void {
    use runar_common::logging::{Component, Logger};
    use std::sync::Arc;

    let logger = Arc::new(Logger::new_root(Component::Custom("test")));
    Box::into_raw(Box::new(logger)) as *mut c_void
}

/// Create test ECDSA key pair data
#[allow(dead_code)]
pub fn create_test_ecdsa_key_pair() -> Vec<u8> {
    use runar_keys::certificate::EcdsaKeyPair;
    use serde_cbor;

    let key_pair = EcdsaKeyPair::new().expect("Failed to create test key pair");
    serde_cbor::to_vec(&key_pair).expect("Failed to serialize key pair")
}

/// Create test certificate data
#[allow(dead_code)]
pub fn create_test_certificate() -> Vec<u8> {
    use runar_keys::certificate::CertificateAuthority;

    let ca = CertificateAuthority::new("CN=Test CA,O=Test,C=US").expect("Failed to create test CA");
    ca.ca_certificate().der_bytes().to_vec()
}

/// Create test EA public keys data
#[allow(dead_code)]
pub fn create_test_ea_public_keys() -> Vec<u8> {
    use runar_keys::certificate::EcdsaKeyPair;
    use serde_cbor;

    let key_pair = EcdsaKeyPair::new().expect("Failed to create test key pair");
    let public_key = key_pair.public_key().as_bytes().to_vec();
    let ea_keys = vec![public_key];
    serde_cbor::to_vec(&ea_keys).expect("Failed to serialize EA keys")
}
