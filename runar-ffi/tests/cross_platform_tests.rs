//! Cross-platform FFI tests
//!
//! These tests ensure that core FFI functionality works correctly on ALL platforms
//! regardless of keystore implementation. They test the fundamental API contracts
//! and error handling that should be consistent across platforms.

use runar_ffi::*;

use std::ptr;

// Import common utilities
mod common;
use common::*;

// ============================================================================
// CORE FUNCTIONALITY TESTS - These should run on ALL platforms
// ============================================================================

#[test]
fn test_core_handle_creation_and_cleanup() {
    // Test basic handle lifecycle - should work on all platforms
    let keys = create_keys_handle();
    assert!(!keys.is_null(), "Keys handle should not be null");
    destroy_keys_handle(keys);
}

#[test]
fn test_core_initialization_flow() {
    // Test initialization flow - should work on all platforms
    let keys = create_keys_handle();

    // Initialize as mobile
    unsafe { init_as_mobile(keys) };

    // Verify mobile functions work (may fail if no key generated yet, which is expected)
    let mut error = create_test_error();
    let mut user_pk_ptr: *mut u8 = ptr::null_mut();
    let mut user_pk_len: usize = 0;

    let result = unsafe {
        rn_keys_mobile_get_user_public_key(keys, &mut user_pk_ptr, &mut user_pk_len, &mut error)
    };
    // This may fail with OPERATION_FAILED if no key generated yet, which is expected
    assert!(
        result == 0 || result == RN_ERROR_OPERATION_FAILED,
        "Mobile function should either succeed or fail with OPERATION_FAILED, got {result}"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_core_node_initialization_flow() {
    // Test node initialization flow - should work on all platforms
    let keys = create_keys_handle();

    // Initialize as node
    unsafe { init_as_node(keys) };

    // Verify node functions work
    let mut error = create_test_error();
    let mut id_ptr: *mut i8 = ptr::null_mut();
    let mut id_len: usize = 0;

    let result = rn_keys_node_get_node_id(keys, &mut id_ptr, &mut id_len, &mut error);
    assert_eq!(result, 0, "Node function should work after node init");

    destroy_keys_handle(keys);
}

#[test]
fn test_core_error_handling_consistency() {
    // Test that error handling is consistent across platforms
    let mut error = create_test_error();

    // Test null handle errors
    let result = unsafe { rn_keys_init_as_mobile(ptr::null_mut(), &mut error) };
    assert_eq!(
        result, RN_ERROR_INVALID_HANDLE,
        "Null handle should return INVALID_HANDLE error"
    );

    let result = unsafe { rn_keys_init_as_node(ptr::null_mut(), &mut error) };
    assert_eq!(
        result, RN_ERROR_INVALID_HANDLE,
        "Null handle should return INVALID_HANDLE error"
    );
}

#[test]
fn test_core_manager_type_isolation() {
    // Test that manager types are properly isolated
    let keys = create_keys_handle();

    // Initialize as mobile
    unsafe { init_as_mobile(keys) };

    // Try to call node function - should fail with wrong manager type
    let mut error = create_test_error();
    let mut id_ptr: *mut i8 = ptr::null_mut();
    let mut id_len: usize = 0;

    let result = rn_keys_node_get_node_id(keys, &mut id_ptr, &mut id_len, &mut error);
    assert_eq!(
        result, RN_ERROR_WRONG_MANAGER_TYPE,
        "Node function should fail with mobile init"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_core_error_code_uniqueness() {
    // Ensure all error codes are unique (platform-independent)
    let error_codes = [
        RN_ERROR_NULL_ARGUMENT,
        RN_ERROR_INVALID_HANDLE,
        RN_ERROR_NOT_INITIALIZED,
        RN_ERROR_WRONG_MANAGER_TYPE,
        RN_ERROR_OPERATION_FAILED,
        RN_ERROR_SERIALIZATION_FAILED,
        RN_ERROR_KEYSTORE_FAILED,
        RN_ERROR_MEMORY_ALLOCATION,
        RN_ERROR_LOCK_ERROR,
        RN_ERROR_INVALID_UTF8,
        RN_ERROR_INVALID_ARGUMENT,
    ];

    for (i, &code1) in error_codes.iter().enumerate() {
        for (j, &code2) in error_codes.iter().enumerate() {
            if i != j {
                assert_ne!(code1, code2, "Error codes {i} and {j} are not unique");
            }
        }
    }
}

#[test]
fn test_core_basic_encryption_operations() {
    // Test basic encryption operations that should work on all platforms
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };

    let mut error = create_test_error();

    // Test local data encryption
    let data = b"test data";
    let mut cipher_ptr: *mut u8 = ptr::null_mut();
    let mut cipher_len: usize = 0;

    let result = unsafe {
        rn_keys_encrypt_local_data(
            keys,
            data.as_ptr(),
            data.len(),
            &mut cipher_ptr,
            &mut cipher_len,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Local data encryption should work");
    assert!(!cipher_ptr.is_null(), "Cipher output should not be null");
    assert!(cipher_len > 0, "Cipher length should be > 0");

    // Clean up
    if !cipher_ptr.is_null() {
        rn_free(cipher_ptr, cipher_len);
    }

    destroy_keys_handle(keys);
}

#[test]
fn test_core_basic_decryption_operations() {
    // Test basic decryption operations that should work on all platforms
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };

    let mut error = create_test_error();

    // First encrypt some data
    let data = b"test data for decryption";
    let mut cipher_ptr: *mut u8 = ptr::null_mut();
    let mut cipher_len: usize = 0;

    let result = unsafe {
        rn_keys_encrypt_local_data(
            keys,
            data.as_ptr(),
            data.len(),
            &mut cipher_ptr,
            &mut cipher_len,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Local data encryption should work");

    // Now decrypt it
    let mut plain_ptr: *mut u8 = ptr::null_mut();
    let mut plain_len: usize = 0;

    let result = unsafe {
        rn_keys_decrypt_local_data(
            keys,
            cipher_ptr,
            cipher_len,
            &mut plain_ptr,
            &mut plain_len,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Local data decryption should work");

    // Verify the decrypted data matches the original
    let decrypted = unsafe { std::slice::from_raw_parts(plain_ptr, plain_len) };
    assert_eq!(decrypted, data, "Decrypted data should match original");

    // Clean up
    if !cipher_ptr.is_null() {
        rn_free(cipher_ptr, cipher_len);
    }
    if !plain_ptr.is_null() {
        rn_free(plain_ptr, plain_len);
    }

    destroy_keys_handle(keys);
}

// ============================================================================
// PLATFORM-INDEPENDENT VALIDATION TESTS
// ============================================================================

#[test]
fn test_core_parameter_validation() {
    // Test parameter validation that should be consistent across platforms
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };

    let mut error = create_test_error();
    let mut output_ptr: *mut u8 = ptr::null_mut();
    let mut output_len: usize = 0;

    // Test null data pointer
    let result = unsafe {
        rn_keys_encrypt_local_data(
            keys,
            ptr::null(),
            10,
            &mut output_ptr,
            &mut output_len,
            &mut error,
        )
    };
    assert_eq!(
        result, RN_ERROR_NULL_ARGUMENT,
        "Null data should return NULL_ARGUMENT error"
    );

    // Test null output pointer
    let data = b"test";
    let result = unsafe {
        rn_keys_encrypt_local_data(
            keys,
            data.as_ptr(),
            data.len(),
            ptr::null_mut(),
            &mut output_len,
            &mut error,
        )
    };
    assert_eq!(
        result, RN_ERROR_NULL_ARGUMENT,
        "Null output should return NULL_ARGUMENT error"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_core_handle_validation() {
    // Test handle validation that should be consistent across platforms
    let mut error = create_test_error();
    let mut output_ptr: *mut u8 = ptr::null_mut();
    let mut output_len: usize = 0;

    // Test with null handle
    let result = unsafe {
        rn_keys_encrypt_local_data(
            ptr::null_mut(),
            b"test".as_ptr(),
            4,
            &mut output_ptr,
            &mut output_len,
            &mut error,
        )
    };
    assert_eq!(
        result, RN_ERROR_NULL_ARGUMENT,
        "Null handle should return NULL_ARGUMENT error"
    );

    // Test with invalid handle (uninitialized)
    let keys = create_keys_handle();
    let result = unsafe {
        rn_keys_encrypt_local_data(
            keys,
            b"test".as_ptr(),
            4,
            &mut output_ptr,
            &mut output_len,
            &mut error,
        )
    };
    assert_eq!(
        result, RN_ERROR_NOT_INITIALIZED,
        "Uninitialized handle should return NOT_INITIALIZED error"
    );

    destroy_keys_handle(keys);
}
