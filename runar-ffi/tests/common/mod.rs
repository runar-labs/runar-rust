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
