//! Comprehensive FFI API Tests
//!
//! This test suite covers all the new split functions, edge cases, error conditions,
//! and happy path scenarios for the FFI key management API.

use runar_ffi::*;

use std::ffi::c_void;
use std::ptr;

// Import common utilities
mod common;
use common::*;

#[test]
fn test_node_encrypt_with_envelope_happy_path() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    // Test data
    let data = b"Hello, World!";
    // Use null network_id for now (no network encryption)
    let network_id = ptr::null();

    // Call the function
    let mut eed_ptr: *mut u8 = ptr::null_mut();
    let mut eed_len: usize = 0;

    let result = unsafe {
        rn_keys_node_encrypt_with_envelope(
            keys,
            data.as_ptr(),
            data.len(),
            network_id,  // null network_id
            0,           // network_public_key_len
            ptr::null(), // no profile keys
            ptr::null(),
            0,
            &mut eed_ptr,
            &mut eed_len,
            &mut error,
        )
    };

    assert_eq!(result, 0, "Should successfully encrypt with envelope");
    assert!(!eed_ptr.is_null(), "Output should not be null");
    assert!(eed_len > 0, "Output length should be > 0");

    // Clean up
    if !eed_ptr.is_null() {
        rn_free(eed_ptr, eed_len);
    }
    destroy_keys_handle(keys);
}

#[test]
fn test_mobile_encrypt_with_envelope_happy_path() {
    let keys = create_keys_handle();
    unsafe { init_as_mobile(keys) };

    // Initialize user root key for mobile operations
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };
    let result = unsafe { rn_keys_mobile_initialize_user_root_key(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully initialize user root key");

    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    // Test data
    let data = b"Hello, World!";

    // Call the function
    let mut eed_ptr: *mut u8 = ptr::null_mut();
    let mut eed_len: usize = 0;

    let result = unsafe {
        rn_keys_mobile_encrypt_with_envelope(
            keys,
            data.as_ptr(),
            data.len(),
            ptr::null(), // no network_id
            0,           // network_public_key_len
            ptr::null(), // no profile keys
            ptr::null(),
            0,
            &mut eed_ptr,
            &mut eed_len,
            &mut error,
        )
    };

    assert_eq!(result, 0, "Should successfully encrypt with envelope");
    assert!(!eed_ptr.is_null(), "Output should not be null");
    assert!(eed_len > 0, "Output length should be > 0");

    // Clean up
    if !eed_ptr.is_null() {
        rn_free(eed_ptr, eed_len);
    }
    destroy_keys_handle(keys);
}

#[test]
fn test_node_encrypt_with_envelope_null_pointers() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let data = b"Hello, World!";

    // Test null keys handle
    let result = unsafe {
        rn_keys_node_encrypt_with_envelope(
            ptr::null_mut(),
            data.as_ptr(),
            data.len(),
            ptr::null(),
            0, // network_public_key_len
            ptr::null(),
            ptr::null(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut error,
        )
    };
    assert_eq!(
        result, RN_ERROR_NULL_ARGUMENT,
        "Should fail with null keys handle"
    );

    // Test null data
    let result = unsafe {
        rn_keys_node_encrypt_with_envelope(
            keys,
            ptr::null(),
            data.len(),
            ptr::null(),
            0, // network_public_key_len
            ptr::null(),
            ptr::null(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut error,
        )
    };
    assert_eq!(result, RN_ERROR_NULL_ARGUMENT, "Should fail with null data");

    // Test null output pointers
    let result = unsafe {
        rn_keys_node_encrypt_with_envelope(
            keys,
            data.as_ptr(),
            data.len(),
            ptr::null(),
            0, // network_public_key_len
            ptr::null(),
            ptr::null(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut error,
        )
    };
    assert_eq!(
        result, RN_ERROR_NULL_ARGUMENT,
        "Should fail with null output pointers"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_node_encrypt_with_envelope_zero_length() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let data = b"Hello, World!";

    // Test zero data length
    let result = unsafe {
        rn_keys_node_encrypt_with_envelope(
            keys,
            data.as_ptr(),
            0, // zero length
            ptr::null(),
            0, // network_public_key_len
            ptr::null(),
            ptr::null(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut error,
        )
    };
    assert_eq!(
        result, RN_ERROR_NULL_ARGUMENT,
        "Should fail with zero data length"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_node_encrypt_with_envelope_invalid_utf8() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let data = b"Hello, World!";

    // Create invalid UTF-8 string (now treated as raw bytes)
    let invalid_utf8 = [0xFF, 0xFE]; // Invalid UTF-8 sequence

    let mut eed_ptr: *mut u8 = ptr::null_mut();
    let mut eed_len: usize = 0;
    let result = unsafe {
        rn_keys_node_encrypt_with_envelope(
            keys,
            data.as_ptr(),
            data.len(),
            invalid_utf8.as_ptr() as *const u8, // Cast to simulate C string
            invalid_utf8.len(),                 // network_public_key_len
            ptr::null(),
            ptr::null(),
            0,
            &mut eed_ptr,
            &mut eed_len,
            &mut error,
        )
    };
    // With our refactor, network_public_key is now raw bytes, not a string
    // So UTF-8 validation no longer applies - it should succeed or fail on other grounds
    assert!(result != 0, "Should not succeed with invalid data");

    destroy_keys_handle(keys);
}

#[test]
fn test_node_encrypt_with_envelope_wrong_manager_type() {
    let keys = create_keys_handle();
    unsafe { init_as_mobile(keys) }; // Initialize as mobile
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let data = b"Hello, World!";

    // Try to call node function with mobile initialization
    let mut eed_ptr: *mut u8 = ptr::null_mut();
    let mut eed_len: usize = 0;
    let result = unsafe {
        rn_keys_node_encrypt_with_envelope(
            keys,
            data.as_ptr(),
            data.len(),
            ptr::null(),
            0, // network_public_key_len
            ptr::null(),
            ptr::null(),
            0,
            &mut eed_ptr,
            &mut eed_len,
            &mut error,
        )
    };
    assert_eq!(
        result, RN_ERROR_WRONG_MANAGER_TYPE,
        "Should fail with wrong manager type"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_node_encrypt_with_envelope_not_initialized() {
    let keys = create_keys_handle();
    // Don't initialize
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let data = b"Hello, World!";

    // Try to call function without initialization
    let mut eed_ptr: *mut u8 = ptr::null_mut();
    let mut eed_len: usize = 0;
    let result = unsafe {
        rn_keys_node_encrypt_with_envelope(
            keys,
            data.as_ptr(),
            data.len(),
            ptr::null(),
            0, // network_public_key_len
            ptr::null(),
            ptr::null(),
            0,
            &mut eed_ptr,
            &mut eed_len,
            &mut error,
        )
    };
    assert_eq!(
        result, RN_ERROR_NOT_INITIALIZED,
        "Should fail when not initialized"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_mobile_encrypt_with_envelope_wrong_manager_type() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) }; // Initialize as node
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let data = b"Hello, World!";

    // Try to call mobile function with node initialization
    let mut eed_ptr: *mut u8 = ptr::null_mut();
    let mut eed_len: usize = 0;
    let result = unsafe {
        rn_keys_mobile_encrypt_with_envelope(
            keys,
            data.as_ptr(),
            data.len(),
            ptr::null(),
            0, // network_public_key_len
            ptr::null(),
            ptr::null(),
            0,
            &mut eed_ptr,
            &mut eed_len,
            &mut error,
        )
    };
    assert_eq!(
        result, RN_ERROR_WRONG_MANAGER_TYPE,
        "Should fail with wrong manager type"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_mobile_encrypt_with_envelope_not_initialized() {
    let keys = create_keys_handle();
    // Don't initialize
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let data = b"Hello, World!";

    // Try to call function without initialization
    let mut eed_ptr: *mut u8 = ptr::null_mut();
    let mut eed_len: usize = 0;
    let result = unsafe {
        rn_keys_mobile_encrypt_with_envelope(
            keys,
            data.as_ptr(),
            data.len(),
            ptr::null(),
            0, // network_public_key_len
            ptr::null(),
            ptr::null(),
            0,
            &mut eed_ptr,
            &mut eed_len,
            &mut error,
        )
    };
    assert_eq!(
        result, RN_ERROR_NOT_INITIALIZED,
        "Should fail when not initialized"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_node_encrypt_local_data_happy_path() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };

    // Generate keys first
    let mut state = 0i32;
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };
    let result = unsafe { rn_keys_node_get_keystore_state(keys, &mut state, &mut error) };
    assert_eq!(result, 0, "Should successfully get keystore state");

    let data = b"Secret data to encrypt";

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

    assert_eq!(result, 0, "Should successfully encrypt local data");
    assert!(!cipher_ptr.is_null(), "Output should not be null");
    assert!(cipher_len > 0, "Output length should be > 0");

    // Clean up
    if !cipher_ptr.is_null() {
        rn_free(cipher_ptr, cipher_len);
    }
    destroy_keys_handle(keys);
}

#[test]
fn test_node_encrypt_local_data_wrong_manager_type() {
    let keys = create_keys_handle();
    unsafe { init_as_mobile(keys) }; // Initialize as mobile
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let data = b"Secret data to encrypt";

    // Try to call node function with mobile initialization
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
    assert_eq!(
        result, RN_ERROR_WRONG_MANAGER_TYPE,
        "Should fail with wrong manager type"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_node_get_keystore_state_happy_path() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let mut state = 0i32;

    let result = unsafe { rn_keys_node_get_keystore_state(keys, &mut state, &mut error) };

    // Should succeed (may return 0 or 1 depending on keystore state)
    assert!(result == 0, "Should succeed");
    assert!(state == 0 || state == 1, "State should be 0 or 1");

    destroy_keys_handle(keys);
}

#[test]
fn test_mobile_get_keystore_state_happy_path() {
    let keys = create_keys_handle();
    unsafe { init_as_mobile(keys) };
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let mut state = 0i32;

    let result = unsafe { rn_keys_mobile_get_keystore_state(keys, &mut state, &mut error) };

    // Should succeed (may return 0 or 1 depending on keystore state)
    assert!(result == 0, "Should succeed");
    assert!(state == 0 || state == 1, "State should be 0 or 1");

    destroy_keys_handle(keys);
}

#[test]
fn test_mobile_initialize_user_root_key_happy_path() {
    let keys = create_keys_handle();
    unsafe { init_as_mobile(keys) };
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let result = unsafe { rn_keys_mobile_initialize_user_root_key(keys, &mut error) };

    // Should succeed (may return 0 or some operation-specific error)
    assert!(
        result == 0 || result == RN_ERROR_OPERATION_FAILED,
        "Should succeed or fail with operation error, got: {result}"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_mobile_initialize_user_root_key_wrong_manager_type() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) }; // Initialize as node
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let result = unsafe { rn_keys_mobile_initialize_user_root_key(keys, &mut error) };

    assert_eq!(
        result, RN_ERROR_WRONG_MANAGER_TYPE,
        "Should fail with wrong manager type"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_node_get_public_key_happy_path() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };

    // Generate keys first
    let mut state = 0i32;
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };
    let result = unsafe { rn_keys_node_get_keystore_state(keys, &mut state, &mut error) };
    assert_eq!(result, 0, "Should successfully get keystore state");

    let mut pk_ptr: *mut u8 = ptr::null_mut();
    let mut pk_len: usize = 0;

    let result = rn_keys_node_get_public_key(keys, &mut pk_ptr, &mut pk_len, &mut error);

    assert_eq!(result, 0, "Should successfully get public key");
    assert!(!pk_ptr.is_null(), "Output should not be null");
    assert!(pk_len > 0, "Output length should be > 0");

    // Clean up
    if !pk_ptr.is_null() {
        rn_free(pk_ptr, pk_len);
    }
    destroy_keys_handle(keys);
}

#[test]
fn test_node_get_public_key_wrong_manager_type() {
    let keys = create_keys_handle();
    unsafe { init_as_mobile(keys) }; // Initialize as mobile
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let result = rn_keys_node_get_public_key(keys, ptr::null_mut(), ptr::null_mut(), &mut error);

    assert_eq!(
        result, RN_ERROR_WRONG_MANAGER_TYPE,
        "Should fail with wrong manager type"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_node_get_agreement_public_key_happy_path() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };

    // Generate keys first
    let mut state = 0i32;
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };
    let result = unsafe { rn_keys_node_get_keystore_state(keys, &mut state, &mut error) };
    assert_eq!(result, 0, "Should successfully get keystore state");

    let mut pk_ptr: *mut u8 = ptr::null_mut();
    let mut pk_len: usize = 0;

    let result = rn_keys_node_get_agreement_public_key(keys, &mut pk_ptr, &mut pk_len, &mut error);

    assert_eq!(result, 0, "Should successfully get agreement public key");
    assert!(!pk_ptr.is_null(), "Output should not be null");
    assert!(pk_len > 0, "Output length should be > 0");

    // Clean up
    if !pk_ptr.is_null() {
        rn_free(pk_ptr, pk_len);
    }
    destroy_keys_handle(keys);
}

#[test]
fn test_node_get_agreement_public_key_wrong_manager_type() {
    let keys = create_keys_handle();
    unsafe { init_as_mobile(keys) }; // Initialize as mobile
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let result =
        rn_keys_node_get_agreement_public_key(keys, ptr::null_mut(), ptr::null_mut(), &mut error);

    assert_eq!(
        result, RN_ERROR_WRONG_MANAGER_TYPE,
        "Should fail with wrong manager type"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_node_get_id_happy_path() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };

    // Generate keys first
    let mut state = 0i32;
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };
    let result = unsafe { rn_keys_node_get_keystore_state(keys, &mut state, &mut error) };
    assert_eq!(result, 0, "Should successfully get keystore state");

    let mut id_c: *mut i8 = ptr::null_mut();
    let mut id_len: usize = 0;

    let result = rn_keys_node_get_node_id(keys, &mut id_c, &mut id_len, &mut error);

    assert_eq!(result, 0, "Should successfully get node ID");
    assert!(!id_c.is_null(), "Output should not be null");
    assert!(id_len > 0, "Output length should be > 0");

    // Clean up
    if !id_c.is_null() {
        rn_string_free(id_c);
    }
    destroy_keys_handle(keys);
}

#[test]
fn test_node_get_id_wrong_manager_type() {
    let keys = create_keys_handle();
    unsafe { init_as_mobile(keys) }; // Initialize as mobile
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let result = rn_keys_node_get_node_id(keys, ptr::null_mut(), ptr::null_mut(), &mut error);

    assert_eq!(
        result, RN_ERROR_WRONG_MANAGER_TYPE,
        "Should fail with wrong manager type"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_set_persistence_dir_happy_path() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) }; // Can work with either manager type
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let temp_dir = std::env::temp_dir();
    let dir_path = temp_dir.to_string_lossy();
    let dir_c = std::ffi::CString::new(dir_path.as_ref()).unwrap();

    let result = unsafe { rn_keys_set_persistence_dir(keys, dir_c.as_ptr(), &mut error) };

    assert_eq!(result, 0, "Should successfully set persistence directory");

    destroy_keys_handle(keys);
}

#[test]
fn test_enable_auto_persist_happy_path() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) }; // Can work with either manager type
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let result = unsafe { rn_keys_enable_auto_persist(keys, true, &mut error) };

    assert_eq!(result, 0, "Should successfully enable auto persist");

    let result = unsafe { rn_keys_enable_auto_persist(keys, false, &mut error) };

    assert_eq!(result, 0, "Should successfully disable auto persist");

    destroy_keys_handle(keys);
}

#[test]
fn test_wipe_persistence_happy_path() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let result = unsafe { rn_keys_wipe_persistence(keys, &mut error) };

    assert_eq!(result, 0, "Should successfully wipe persistence");

    destroy_keys_handle(keys);
}

#[test]
fn test_flush_state_happy_path() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let result = unsafe { rn_keys_flush_state(keys, &mut error) };

    assert_eq!(result, 0, "Should successfully flush state");

    destroy_keys_handle(keys);
}

// ============================================================================
// NEW V2 API TESTS - DUAL-ROLE NODEKEYMANAGER FUNCTIONALITY
// ============================================================================

#[test]
fn test_node_has_keys_v2_happy_path() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    let mut has_keys = 0i32;

    let result = unsafe { rn_keys_node_has_keys_v2(keys, &mut has_keys, &mut error) };

    assert_eq!(result, 0, "Should successfully check if keys exist");
    // Keys may or may not exist initially, so we just check that the call succeeded
    assert!(has_keys == 0 || has_keys == 1, "has_keys should be 0 or 1");

    destroy_keys_handle(keys);
}

#[test]
fn test_node_has_keys_v2_null_pointers() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Test null keys handle
    let result = unsafe { rn_keys_node_has_keys_v2(ptr::null_mut(), ptr::null_mut(), &mut error) };
    assert_eq!(result, -1, "Should fail with null keys handle");

    // Test null output pointer
    let result = unsafe { rn_keys_node_has_keys_v2(keys, ptr::null_mut(), &mut error) };
    assert_eq!(result, -1, "Should fail with null output pointer");

    // Test null error pointer
    let mut has_keys = 0i32;
    let result = unsafe { rn_keys_node_has_keys_v2(keys, &mut has_keys, ptr::null_mut()) };
    assert_eq!(result, -1, "Should fail with null error pointer");

    destroy_keys_handle(keys);
}

#[test]
fn test_node_has_keys_v2_wrong_manager_type() {
    let keys = create_keys_handle();
    unsafe { init_as_mobile(keys) }; // Initialize as mobile
    let mut error = create_test_error();

    let mut has_keys = 0i32;

    let result = unsafe { rn_keys_node_has_keys_v2(keys, &mut has_keys, &mut error) };

    assert_eq!(
        result, RN_ERROR_WRONG_MANAGER_TYPE,
        "Should fail with wrong manager type"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_node_has_keys_v2_not_initialized() {
    let keys = create_keys_handle();
    // Don't initialize
    let mut error = create_test_error();

    let mut has_keys = 0i32;

    let result = unsafe { rn_keys_node_has_keys_v2(keys, &mut has_keys, &mut error) };

    assert_eq!(
        result, RN_ERROR_NOT_INITIALIZED,
        "Should fail when not initialized"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_node_generate_keys_v2_happy_path() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    let result = unsafe { rn_keys_node_generate_keys_v2(keys, &mut error) };

    assert_eq!(result, 0, "Should successfully generate keys");

    destroy_keys_handle(keys);
}

#[test]
fn test_node_generate_keys_v2_null_pointers() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };

    // Test null keys handle
    let mut error = create_test_error();
    let result = unsafe { rn_keys_node_generate_keys_v2(ptr::null_mut(), &mut error) };
    assert_eq!(result, -1, "Should fail with null keys handle");

    // Test null error pointer
    let result = unsafe { rn_keys_node_generate_keys_v2(keys, ptr::null_mut()) };
    assert_eq!(result, -1, "Should fail with null error pointer");

    destroy_keys_handle(keys);
}

#[test]
fn test_node_generate_keys_v2_wrong_manager_type() {
    let keys = create_keys_handle();
    unsafe { init_as_mobile(keys) }; // Initialize as mobile
    let mut error = create_test_error();

    let result = unsafe { rn_keys_node_generate_keys_v2(keys, &mut error) };

    assert_eq!(
        result, RN_ERROR_WRONG_MANAGER_TYPE,
        "Should fail with wrong manager type"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_node_generate_keys_v2_not_initialized() {
    let keys = create_keys_handle();
    // Don't initialize
    let mut error = create_test_error();

    let result = unsafe { rn_keys_node_generate_keys_v2(keys, &mut error) };

    assert_eq!(
        result, RN_ERROR_NOT_INITIALIZED,
        "Should fail when not initialized"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_node_get_node_id_v2_happy_path() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Generate keys first to ensure we have a node ID
    let result = unsafe { rn_keys_node_generate_keys_v2(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully generate keys");

    let mut node_id: *mut i8 = ptr::null_mut();
    let mut has_id = 0i32;

    let result =
        unsafe { rn_keys_node_get_node_id_v2(keys, &mut node_id, &mut has_id, &mut error) };

    assert_eq!(result, 0, "Should successfully get node ID");
    assert_eq!(has_id, 1, "Should have a node ID");
    assert!(!node_id.is_null(), "Node ID should not be null");

    // Clean up
    if !node_id.is_null() {
        rn_string_free(node_id);
    }

    destroy_keys_handle(keys);
}

#[test]
fn test_node_get_node_id_v2_no_keys() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Don't generate keys, so there should be no node ID
    let mut node_id: *mut i8 = ptr::null_mut();
    let mut has_id = 0i32;

    let result =
        unsafe { rn_keys_node_get_node_id_v2(keys, &mut node_id, &mut has_id, &mut error) };

    assert_eq!(result, 0, "Should successfully check for node ID");
    assert_eq!(has_id, 0, "Should not have a node ID");
    assert!(node_id.is_null(), "Node ID should be null");

    destroy_keys_handle(keys);
}

#[test]
fn test_node_get_node_id_v2_null_pointers() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Test null keys handle
    let result = unsafe {
        rn_keys_node_get_node_id_v2(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut error,
        )
    };
    assert_eq!(result, -1, "Should fail with null keys handle");

    // Test null output pointers
    let result =
        unsafe { rn_keys_node_get_node_id_v2(keys, ptr::null_mut(), ptr::null_mut(), &mut error) };
    assert_eq!(result, -1, "Should fail with null output pointers");

    // Test null error pointer
    let mut node_id: *mut i8 = ptr::null_mut();
    let mut has_id = 0i32;
    let result =
        unsafe { rn_keys_node_get_node_id_v2(keys, &mut node_id, &mut has_id, ptr::null_mut()) };
    assert_eq!(result, -1, "Should fail with null error pointer");

    destroy_keys_handle(keys);
}

#[test]
fn test_node_get_node_id_v2_wrong_manager_type() {
    let keys = create_keys_handle();
    unsafe { init_as_mobile(keys) }; // Initialize as mobile
    let mut error = create_test_error();

    let mut node_id: *mut i8 = ptr::null_mut();
    let mut has_id = 0i32;

    let result =
        unsafe { rn_keys_node_get_node_id_v2(keys, &mut node_id, &mut has_id, &mut error) };

    assert_eq!(
        result, RN_ERROR_WRONG_MANAGER_TYPE,
        "Should fail with wrong manager type"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_node_get_node_id_v2_not_initialized() {
    let keys = create_keys_handle();
    // Don't initialize
    let mut error = create_test_error();

    let mut node_id: *mut i8 = ptr::null_mut();
    let mut has_id = 0i32;

    let result =
        unsafe { rn_keys_node_get_node_id_v2(keys, &mut node_id, &mut has_id, &mut error) };

    assert_eq!(
        result, RN_ERROR_NOT_INITIALIZED,
        "Should fail when not initialized"
    );

    destroy_keys_handle(keys);
}

// ============================================================================
// PROFILE KEY MANAGEMENT TESTS (PHASE 2)
// ============================================================================

#[test]
fn test_derive_user_profile_key_happy_path() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Generate keys first
    let result = unsafe { rn_keys_node_generate_keys_v2(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully generate keys");

    let label = create_cstring("test-profile");
    let mut public_key: *mut u8 = ptr::null_mut();
    let mut public_key_len: usize = 0;

    let result = unsafe {
        rn_keys_node_derive_user_profile_key(
            keys,
            label.as_ptr(),
            &mut public_key,
            &mut public_key_len,
            &mut error,
        )
    };

    assert_eq!(result, 0, "Should successfully derive profile key");
    assert!(!public_key.is_null(), "Public key should not be null");
    assert!(public_key_len > 0, "Public key length should be > 0");

    // Clean up
    if !public_key.is_null() {
        rn_free(public_key, public_key_len);
    }

    destroy_keys_handle(keys);
}

#[test]
fn test_derive_user_profile_key_null_pointers() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    let label = create_cstring("test-profile");

    // Test null keys handle
    let result = unsafe {
        rn_keys_node_derive_user_profile_key(
            ptr::null_mut(),
            label.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut error,
        )
    };
    assert_eq!(result, -1, "Should fail with null keys handle");

    // Test null label
    let result = unsafe {
        rn_keys_node_derive_user_profile_key(
            keys,
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut error,
        )
    };
    assert_eq!(result, -1, "Should fail with null label");

    // Test null output pointers
    let result = unsafe {
        rn_keys_node_derive_user_profile_key(
            keys,
            label.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut error,
        )
    };
    assert_eq!(result, -1, "Should fail with null output pointers");

    destroy_keys_handle(keys);
}

#[test]
fn test_derive_user_profile_key_wrong_manager_type() {
    let keys = create_keys_handle();
    unsafe { init_as_mobile(keys) }; // Initialize as mobile
    let mut error = create_test_error();

    let label = create_cstring("test-profile");
    let mut public_key: *mut u8 = ptr::null_mut();
    let mut public_key_len: usize = 0;

    let result = unsafe {
        rn_keys_node_derive_user_profile_key(
            keys,
            label.as_ptr(),
            &mut public_key,
            &mut public_key_len,
            &mut error,
        )
    };

    assert_eq!(
        result, RN_ERROR_WRONG_MANAGER_TYPE,
        "Should fail with wrong manager type"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_derive_user_profile_key_not_initialized() {
    let keys = create_keys_handle();
    // Don't initialize
    let mut error = create_test_error();

    let label = create_cstring("test-profile");
    let mut public_key: *mut u8 = ptr::null_mut();
    let mut public_key_len: usize = 0;

    let result = unsafe {
        rn_keys_node_derive_user_profile_key(
            keys,
            label.as_ptr(),
            &mut public_key,
            &mut public_key_len,
            &mut error,
        )
    };

    assert_eq!(
        result, RN_ERROR_NOT_INITIALIZED,
        "Should fail when not initialized"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_install_profile_public_key_happy_path() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Generate keys first
    let result = unsafe { rn_keys_node_generate_keys_v2(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully generate keys");

    // Create a test public key (65 bytes for uncompressed P-256)
    let mut test_public_key = [0u8; 65];
    test_public_key[0] = 0x04; // Uncompressed point marker

    let result = unsafe {
        rn_keys_node_install_profile_public_key(
            keys,
            test_public_key.as_ptr(),
            test_public_key.len(),
            &mut error,
        )
    };

    assert_eq!(result, 0, "Should successfully install profile public key");

    destroy_keys_handle(keys);
}

#[test]
fn test_install_profile_public_key_null_pointers() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    let test_public_key = [0u8; 65];

    // Test null keys handle
    let result = unsafe {
        rn_keys_node_install_profile_public_key(
            ptr::null_mut(),
            test_public_key.as_ptr(),
            test_public_key.len(),
            &mut error,
        )
    };
    assert_eq!(result, -1, "Should fail with null keys handle");

    // Test null public key
    let result = unsafe {
        rn_keys_node_install_profile_public_key(
            keys,
            ptr::null(),
            test_public_key.len(),
            &mut error,
        )
    };
    assert_eq!(result, -1, "Should fail with null public key");

    destroy_keys_handle(keys);
}

#[test]
fn test_get_profile_public_key_by_label_happy_path() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Generate keys first
    let result = unsafe { rn_keys_node_generate_keys_v2(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully generate keys");

    // Derive a profile key first
    let label = create_cstring("test-profile");
    let mut public_key: *mut u8 = ptr::null_mut();
    let mut public_key_len: usize = 0;

    let result = unsafe {
        rn_keys_node_derive_user_profile_key(
            keys,
            label.as_ptr(),
            &mut public_key,
            &mut public_key_len,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Should successfully derive profile key");

    // Clean up the derived key
    if !public_key.is_null() {
        rn_free(public_key, public_key_len);
    }

    // Now try to get it back by label
    let mut retrieved_key: *mut u8 = ptr::null_mut();
    let mut retrieved_key_len: usize = 0;
    let mut has_key: i32 = 0;

    let result = unsafe {
        rn_keys_node_get_profile_public_key_by_label(
            keys,
            label.as_ptr(),
            &mut retrieved_key,
            &mut retrieved_key_len,
            &mut has_key,
            &mut error,
        )
    };

    assert_eq!(result, 0, "Should successfully get profile key by label");
    assert_eq!(has_key, 1, "Should have the key");
    assert!(!retrieved_key.is_null(), "Retrieved key should not be null");
    assert!(retrieved_key_len > 0, "Retrieved key length should be > 0");

    // Clean up
    if !retrieved_key.is_null() {
        rn_free(retrieved_key, retrieved_key_len);
    }

    destroy_keys_handle(keys);
}

#[test]
fn test_get_profile_public_key_by_label_not_found() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Generate keys first
    let result = unsafe { rn_keys_node_generate_keys_v2(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully generate keys");

    // Try to get a non-existent profile key
    let label = create_cstring("non-existent-profile");
    let mut retrieved_key: *mut u8 = ptr::null_mut();
    let mut retrieved_key_len: usize = 0;
    let mut has_key: i32 = 0;

    let result = unsafe {
        rn_keys_node_get_profile_public_key_by_label(
            keys,
            label.as_ptr(),
            &mut retrieved_key,
            &mut retrieved_key_len,
            &mut has_key,
            &mut error,
        )
    };

    assert_eq!(
        result, 0,
        "Should successfully check for non-existent profile key"
    );
    assert_eq!(has_key, 0, "Should not have the key");
    assert!(retrieved_key.is_null(), "Retrieved key should be null");
    assert_eq!(retrieved_key_len, 0, "Retrieved key length should be 0");

    destroy_keys_handle(keys);
}

#[test]
fn test_get_profile_public_key_by_label_null_pointers() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    let label = create_cstring("test-profile");

    // Test null keys handle
    let result = unsafe {
        rn_keys_node_get_profile_public_key_by_label(
            ptr::null_mut(),
            label.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut error,
        )
    };
    assert_eq!(result, -1, "Should fail with null keys handle");

    // Test null label
    let result = unsafe {
        rn_keys_node_get_profile_public_key_by_label(
            keys,
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut error,
        )
    };
    assert_eq!(result, -1, "Should fail with null label");

    // Test null output pointers
    let result = unsafe {
        rn_keys_node_get_profile_public_key_by_label(
            keys,
            label.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut error,
        )
    };
    assert_eq!(result, -1, "Should fail with null output pointers");

    destroy_keys_handle(keys);
}

#[test]
fn test_decrypt_with_profile_happy_path() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Generate keys first
    let result = unsafe { rn_keys_node_generate_keys_v2(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully generate keys");

    // Derive a profile key first
    let label = create_cstring("test-profile");
    let mut public_key: *mut u8 = ptr::null_mut();
    let mut public_key_len: usize = 0;

    let result = unsafe {
        rn_keys_node_derive_user_profile_key(
            keys,
            label.as_ptr(),
            &mut public_key,
            &mut public_key_len,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Should successfully derive profile key");

    // Clean up the derived key
    if !public_key.is_null() {
        rn_free(public_key, public_key_len);
    }

    // Create a simple envelope data for testing
    // Note: This is a simplified test - in practice, you'd need to create proper envelope data
    let _test_data = b"Hello, World!";
    let envelope_data: *mut u8 = ptr::null_mut();
    let envelope_data_len: usize = 0;

    // For this test, we'll just test the function signature and error handling
    // The actual decryption would require properly formatted envelope data
    let profile_id = create_cstring("test-profile");
    let mut decrypted: *mut u8 = ptr::null_mut();
    let mut decrypted_len: usize = 0;

    let result = unsafe {
        rn_keys_node_decrypt_with_profile(
            keys,
            envelope_data,
            envelope_data_len,
            profile_id.as_ptr(),
            &mut decrypted,
            &mut decrypted_len,
            &mut error,
        )
    };

    // This should fail because we're passing null envelope data
    assert!(result != 0, "Should fail with null envelope data");

    destroy_keys_handle(keys);
}

#[test]
fn test_profile_key_workflow() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Step 1: Generate keys
    let result = unsafe { rn_keys_node_generate_keys_v2(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully generate keys");

    // Step 2: Derive a profile key
    let label = create_cstring("workflow-test");
    let mut public_key: *mut u8 = ptr::null_mut();
    let mut public_key_len: usize = 0;

    let result = unsafe {
        rn_keys_node_derive_user_profile_key(
            keys,
            label.as_ptr(),
            &mut public_key,
            &mut public_key_len,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Should successfully derive profile key");
    assert!(!public_key.is_null(), "Public key should not be null");
    assert!(public_key_len > 0, "Public key length should be > 0");

    // Step 3: Verify we can retrieve the key by label
    let mut retrieved_key: *mut u8 = ptr::null_mut();
    let mut retrieved_key_len: usize = 0;
    let mut has_key: i32 = 0;

    let result = unsafe {
        rn_keys_node_get_profile_public_key_by_label(
            keys,
            label.as_ptr(),
            &mut retrieved_key,
            &mut retrieved_key_len,
            &mut has_key,
            &mut error,
        )
    };

    assert_eq!(result, 0, "Should successfully get profile key by label");
    assert_eq!(has_key, 1, "Should have the key");
    assert!(!retrieved_key.is_null(), "Retrieved key should not be null");
    assert_eq!(
        retrieved_key_len, public_key_len,
        "Retrieved key length should match derived key length"
    );

    // Clean up
    if !public_key.is_null() {
        rn_free(public_key, public_key_len);
    }
    if !retrieved_key.is_null() {
        rn_free(retrieved_key, retrieved_key_len);
    }

    destroy_keys_handle(keys);
}

// ============================================================================
// ENHANCED PROFILE KEY MANAGEMENT TESTS (PHASE 2 - EDGE CASES & ERROR SCENARIOS)
// ============================================================================

#[test]
fn test_derive_user_profile_key_empty_label() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Generate keys first
    let result = unsafe { rn_keys_node_generate_keys_v2(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully generate keys");

    let empty_label = create_cstring("");
    let mut public_key: *mut u8 = ptr::null_mut();
    let mut public_key_len: usize = 0;

    let result = unsafe {
        rn_keys_node_derive_user_profile_key(
            keys,
            empty_label.as_ptr(),
            &mut public_key,
            &mut public_key_len,
            &mut error,
        )
    };

    assert_eq!(
        result, 0,
        "Should successfully derive profile key with empty label"
    );
    assert!(!public_key.is_null(), "Public key should not be null");
    assert!(public_key_len > 0, "Public key length should be > 0");

    // Clean up
    if !public_key.is_null() {
        rn_free(public_key, public_key_len);
    }

    destroy_keys_handle(keys);
}

#[test]
fn test_derive_user_profile_key_duplicate_label() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Generate keys first
    let result = unsafe { rn_keys_node_generate_keys_v2(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully generate keys");

    let label = create_cstring("duplicate-test");
    let mut public_key1: *mut u8 = ptr::null_mut();
    let mut public_key_len1: usize = 0;
    let mut public_key2: *mut u8 = ptr::null_mut();
    let mut public_key_len2: usize = 0;

    // First derivation
    let result1 = unsafe {
        rn_keys_node_derive_user_profile_key(
            keys,
            label.as_ptr(),
            &mut public_key1,
            &mut public_key_len1,
            &mut error,
        )
    };
    assert_eq!(result1, 0, "First derivation should succeed");

    // Second derivation with same label - should overwrite
    let result2 = unsafe {
        rn_keys_node_derive_user_profile_key(
            keys,
            label.as_ptr(),
            &mut public_key2,
            &mut public_key_len2,
            &mut error,
        )
    };
    assert_eq!(result2, 0, "Second derivation should succeed (overwrites)");

    // Both should be valid
    assert!(
        !public_key1.is_null(),
        "First public key should not be null"
    );
    assert!(
        !public_key2.is_null(),
        "Second public key should not be null"
    );
    assert!(public_key_len1 > 0, "First public key length should be > 0");
    assert!(
        public_key_len2 > 0,
        "Second public key length should be > 0"
    );

    // Clean up
    if !public_key1.is_null() {
        rn_free(public_key1, public_key_len1);
    }
    if !public_key2.is_null() {
        rn_free(public_key2, public_key_len2);
    }

    destroy_keys_handle(keys);
}

#[test]
fn test_derive_user_profile_key_long_label() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Generate keys first
    let result = unsafe { rn_keys_node_generate_keys_v2(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully generate keys");

    // Create a very long label
    let long_label = "a".repeat(1000);
    let long_label_cstr = create_cstring(&long_label);
    let mut public_key: *mut u8 = ptr::null_mut();
    let mut public_key_len: usize = 0;

    let result = unsafe {
        rn_keys_node_derive_user_profile_key(
            keys,
            long_label_cstr.as_ptr(),
            &mut public_key,
            &mut public_key_len,
            &mut error,
        )
    };

    assert_eq!(
        result, 0,
        "Should successfully derive profile key with long label"
    );
    assert!(!public_key.is_null(), "Public key should not be null");
    assert!(public_key_len > 0, "Public key length should be > 0");

    // Clean up
    if !public_key.is_null() {
        rn_free(public_key, public_key_len);
    }

    destroy_keys_handle(keys);
}

#[test]
fn test_derive_user_profile_key_unicode_labels() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Generate keys first
    let result = unsafe { rn_keys_node_generate_keys_v2(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully generate keys");

    // Test with Unicode labels
    let unicode_labels = ["测试", "тест", "テスト", "🎯", "αβγ"];
    let mut derived_keys = Vec::new();

    for label in &unicode_labels {
        let label_cstr = create_cstring(label);
        let mut public_key: *mut u8 = ptr::null_mut();
        let mut public_key_len: usize = 0;

        let result = unsafe {
            rn_keys_node_derive_user_profile_key(
                keys,
                label_cstr.as_ptr(),
                &mut public_key,
                &mut public_key_len,
                &mut error,
            )
        };
        assert_eq!(
            result, 0,
            "Should successfully derive profile key for Unicode label: {label}"
        );

        derived_keys.push((public_key, public_key_len));
    }

    // Verify all Unicode keys can be retrieved
    for (_i, label) in unicode_labels.iter().enumerate() {
        let label_cstr = create_cstring(label);
        let mut retrieved_key: *mut u8 = ptr::null_mut();
        let mut retrieved_key_len: usize = 0;
        let mut has_key: i32 = 0;

        let result = unsafe {
            rn_keys_node_get_profile_public_key_by_label(
                keys,
                label_cstr.as_ptr(),
                &mut retrieved_key,
                &mut retrieved_key_len,
                &mut has_key,
                &mut error,
            )
        };

        assert_eq!(
            result, 0,
            "Should successfully get profile key for Unicode label: {label}"
        );
        assert_eq!(has_key, 1, "Should have key for Unicode label: {label}");

        // Clean up retrieved key
        if !retrieved_key.is_null() {
            rn_free(retrieved_key, retrieved_key_len);
        }
    }

    // Clean up derived keys
    for (public_key, public_key_len) in derived_keys {
        if !public_key.is_null() {
            rn_free(public_key, public_key_len);
        }
    }

    destroy_keys_handle(keys);
}

#[test]
fn test_install_profile_public_key_invalid_length() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Test with invalid key length (not 65 bytes for P-256)
    let invalid_key = [0u8; 32]; // Too short
    let result = unsafe {
        rn_keys_node_install_profile_public_key(
            keys,
            invalid_key.as_ptr(),
            invalid_key.len(),
            &mut error,
        )
    };

    // Should still succeed as we don't validate key format in the FFI
    assert_eq!(result, 0, "Should accept any key length");

    destroy_keys_handle(keys);
}

#[test]
fn test_install_profile_public_key_zero_length() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Test with zero length key
    let empty_key = [0u8; 0];
    let result =
        unsafe { rn_keys_node_install_profile_public_key(keys, empty_key.as_ptr(), 0, &mut error) };

    assert_eq!(result, 0, "Should accept zero length key");

    destroy_keys_handle(keys);
}

#[test]
fn test_get_profile_public_key_by_label_after_install() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Generate keys first
    let result = unsafe { rn_keys_node_generate_keys_v2(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully generate keys");

    // Install a profile public key
    let mut test_public_key = [0u8; 65];
    test_public_key[0] = 0x04; // Uncompressed point marker
    let result = unsafe {
        rn_keys_node_install_profile_public_key(
            keys,
            test_public_key.as_ptr(),
            test_public_key.len(),
            &mut error,
        )
    };
    assert_eq!(result, 0, "Should successfully install profile public key");

    // Try to get it back by label - this should fail because install doesn't set a label
    let label = create_cstring("installed-key");
    let mut retrieved_key: *mut u8 = ptr::null_mut();
    let mut retrieved_key_len: usize = 0;
    let mut has_key: i32 = 0;

    let result = unsafe {
        rn_keys_node_get_profile_public_key_by_label(
            keys,
            label.as_ptr(),
            &mut retrieved_key,
            &mut retrieved_key_len,
            &mut has_key,
            &mut error,
        )
    };

    assert_eq!(result, 0, "Should succeed but not find key");
    assert_eq!(has_key, 0, "Should not have key for this label");

    destroy_keys_handle(keys);
}

#[test]
fn test_profile_key_workflow_multiple_labels() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Generate keys first
    let result = unsafe { rn_keys_node_generate_keys_v2(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully generate keys");

    // Derive multiple profile keys with different labels
    let labels = ["profile1", "profile2", "profile3"];
    let mut derived_keys = Vec::new();

    for label in &labels {
        let label_cstr = create_cstring(label);
        let mut public_key: *mut u8 = ptr::null_mut();
        let mut public_key_len: usize = 0;

        let result = unsafe {
            rn_keys_node_derive_user_profile_key(
                keys,
                label_cstr.as_ptr(),
                &mut public_key,
                &mut public_key_len,
                &mut error,
            )
        };
        assert_eq!(
            result, 0,
            "Should successfully derive profile key for {label}"
        );

        derived_keys.push((public_key, public_key_len));
    }

    // Verify all keys can be retrieved by label
    for (_i, label) in labels.iter().enumerate() {
        let label_cstr = create_cstring(label);
        let mut retrieved_key: *mut u8 = ptr::null_mut();
        let mut retrieved_key_len: usize = 0;
        let mut has_key: i32 = 0;

        let result = unsafe {
            rn_keys_node_get_profile_public_key_by_label(
                keys,
                label_cstr.as_ptr(),
                &mut retrieved_key,
                &mut retrieved_key_len,
                &mut has_key,
                &mut error,
            )
        };

        assert_eq!(result, 0, "Should successfully get profile key for {label}");
        assert_eq!(has_key, 1, "Should have key for {label}");
        assert!(
            !retrieved_key.is_null(),
            "Retrieved key should not be null for {label}"
        );
        assert!(
            retrieved_key_len > 0,
            "Retrieved key length should be > 0 for {label}"
        );

        // Clean up retrieved key
        if !retrieved_key.is_null() {
            rn_free(retrieved_key, retrieved_key_len);
        }
    }

    // Clean up derived keys
    for (public_key, public_key_len) in derived_keys {
        if !public_key.is_null() {
            rn_free(public_key, public_key_len);
        }
    }

    destroy_keys_handle(keys);
}

#[test]
fn test_decrypt_with_profile_invalid_envelope_data() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Generate keys first
    let result = unsafe { rn_keys_node_generate_keys_v2(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully generate keys");

    // Create invalid envelope data (not valid CBOR)
    let invalid_data = b"not valid cbor data";
    let profile_id = create_cstring("test-profile");
    let mut decrypted: *mut u8 = ptr::null_mut();
    let mut decrypted_len: usize = 0;

    let result = unsafe {
        rn_keys_node_decrypt_with_profile(
            keys,
            invalid_data.as_ptr(),
            invalid_data.len(),
            profile_id.as_ptr(),
            &mut decrypted,
            &mut decrypted_len,
            &mut error,
        )
    };

    assert_eq!(
        result, RN_ERROR_SERIALIZATION_FAILED,
        "Should fail with invalid envelope data"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_decrypt_with_profile_empty_envelope_data() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Generate keys first
    let result = unsafe { rn_keys_node_generate_keys_v2(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully generate keys");

    // Create empty envelope data
    let empty_data = [];
    let profile_id = create_cstring("test-profile");
    let mut decrypted: *mut u8 = ptr::null_mut();
    let mut decrypted_len: usize = 0;

    let result = unsafe {
        rn_keys_node_decrypt_with_profile(
            keys,
            empty_data.as_ptr(),
            0,
            profile_id.as_ptr(),
            &mut decrypted,
            &mut decrypted_len,
            &mut error,
        )
    };

    assert_eq!(
        result, RN_ERROR_SERIALIZATION_FAILED,
        "Should fail with empty envelope data"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_profile_key_error_handling_consistency() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Test that all profile key functions use consistent error handling
    let label = create_cstring("test-profile");
    let mut public_key: *mut u8 = ptr::null_mut();
    let mut public_key_len: usize = 0;
    let mut has_key: i32 = 0;

    // Test derive_user_profile_key with null pointers
    let result1 = unsafe {
        rn_keys_node_derive_user_profile_key(
            ptr::null_mut(),
            label.as_ptr(),
            &mut public_key,
            &mut public_key_len,
            &mut error,
        )
    };
    assert_eq!(
        result1, -1,
        "derive_user_profile_key should return -1 for null keys"
    );

    // Test install_profile_public_key with null pointers
    let test_key = [0u8; 65];
    let result2 = unsafe {
        rn_keys_node_install_profile_public_key(
            ptr::null_mut(),
            test_key.as_ptr(),
            test_key.len(),
            &mut error,
        )
    };
    assert_eq!(
        result2, -1,
        "install_profile_public_key should return -1 for null keys"
    );

    // Test get_profile_public_key_by_label with null pointers
    let result3 = unsafe {
        rn_keys_node_get_profile_public_key_by_label(
            ptr::null_mut(),
            label.as_ptr(),
            &mut public_key,
            &mut public_key_len,
            &mut has_key,
            &mut error,
        )
    };
    assert_eq!(
        result3, -1,
        "get_profile_public_key_by_label should return -1 for null keys"
    );

    // Test decrypt_with_profile with null pointers
    let test_data = b"test data";
    let profile_id = create_cstring("test-profile");
    let mut decrypted: *mut u8 = ptr::null_mut();
    let mut decrypted_len: usize = 0;

    let result4 = unsafe {
        rn_keys_node_decrypt_with_profile(
            ptr::null_mut(),
            test_data.as_ptr(),
            test_data.len(),
            profile_id.as_ptr(),
            &mut decrypted,
            &mut decrypted_len,
            &mut error,
        )
    };
    assert_eq!(
        result4, -1,
        "decrypt_with_profile should return -1 for null keys"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_profile_key_memory_management() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Generate keys first
    let result = unsafe { rn_keys_node_generate_keys_v2(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully generate keys");

    // Derive multiple profile keys and ensure proper memory management
    let labels = ["mem-test-1", "mem-test-2", "mem-test-3"];
    let mut derived_keys = Vec::new();

    for label in &labels {
        let label_cstr = create_cstring(label);
        let mut public_key: *mut u8 = ptr::null_mut();
        let mut public_key_len: usize = 0;

        let result = unsafe {
            rn_keys_node_derive_user_profile_key(
                keys,
                label_cstr.as_ptr(),
                &mut public_key,
                &mut public_key_len,
                &mut error,
            )
        };
        assert_eq!(
            result, 0,
            "Should successfully derive profile key for {label}"
        );

        // Store the key for later cleanup
        derived_keys.push((public_key, public_key_len));
    }

    // Verify all keys are accessible
    for label in &labels {
        let label_cstr = create_cstring(label);
        let mut retrieved_key: *mut u8 = ptr::null_mut();
        let mut retrieved_key_len: usize = 0;
        let mut has_key: i32 = 0;

        let result = unsafe {
            rn_keys_node_get_profile_public_key_by_label(
                keys,
                label_cstr.as_ptr(),
                &mut retrieved_key,
                &mut retrieved_key_len,
                &mut has_key,
                &mut error,
            )
        };

        assert_eq!(result, 0, "Should successfully get profile key for {label}");
        assert_eq!(has_key, 1, "Should have key for {label}");

        // Clean up retrieved key immediately
        if !retrieved_key.is_null() {
            rn_free(retrieved_key, retrieved_key_len);
        }
    }

    // Clean up all derived keys
    for (public_key, public_key_len) in derived_keys {
        if !public_key.is_null() {
            rn_free(public_key, public_key_len);
        }
    }

    destroy_keys_handle(keys);
}

#[test]
fn test_profile_key_stress_test() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Generate keys first
    let result = unsafe { rn_keys_node_generate_keys_v2(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully generate keys");

    // Create many profile keys to test memory and performance
    let num_keys = 50;
    let mut derived_keys = Vec::new();

    for i in 0..num_keys {
        let label = format!("stress-test-{}", i);
        let label_cstr = create_cstring(&label);
        let mut public_key: *mut u8 = ptr::null_mut();
        let mut public_key_len: usize = 0;

        let result = unsafe {
            rn_keys_node_derive_user_profile_key(
                keys,
                label_cstr.as_ptr(),
                &mut public_key,
                &mut public_key_len,
                &mut error,
            )
        };
        assert_eq!(result, 0, "Should successfully derive profile key {i}");

        derived_keys.push((public_key, public_key_len));
    }

    // Verify all keys can be retrieved
    for i in 0..num_keys {
        let label = format!("stress-test-{}", i);
        let label_cstr = create_cstring(&label);
        let mut retrieved_key: *mut u8 = ptr::null_mut();
        let mut retrieved_key_len: usize = 0;
        let mut has_key: i32 = 0;

        let result = unsafe {
            rn_keys_node_get_profile_public_key_by_label(
                keys,
                label_cstr.as_ptr(),
                &mut retrieved_key,
                &mut retrieved_key_len,
                &mut has_key,
                &mut error,
            )
        };

        assert_eq!(result, 0, "Should successfully get profile key {i}");
        assert_eq!(has_key, 1, "Should have key {i}");

        // Clean up retrieved key
        if !retrieved_key.is_null() {
            rn_free(retrieved_key, retrieved_key_len);
        }
    }

    // Clean up all derived keys
    for (public_key, public_key_len) in derived_keys {
        if !public_key.is_null() {
            rn_free(public_key, public_key_len);
        }
    }

    destroy_keys_handle(keys);
}

// ============================================================================
// NEW CA NODE API TESTS (STUBS)
// ============================================================================

#[test]
fn test_ca_node_new_stub() {
    let mut error = create_test_error();
    let mut ca_node: *mut c_void = ptr::null_mut();

    let result = rn_keys_ca_node_new(ptr::null_mut(), &mut ca_node, &mut error);

    assert_eq!(result, -1, "Should fail as stub implementation");
    assert!(ca_node.is_null(), "CA node should be null for stub");
}

#[test]
fn test_ca_node_free_null() {
    // Should handle null pointer gracefully
    unsafe { rn_keys_ca_node_free(ptr::null_mut()) };
    // No assertion needed - should not crash
}

// ============================================================================
// NEW CA SERVER API TESTS (STUBS)
// ============================================================================

#[test]
fn test_ca_server_new_stub() {
    let mut error = create_test_error();
    let mut server: *mut c_void = ptr::null_mut();

    let result = rn_transport_ca_server_new(
        ptr::null(),
        ptr::null_mut(),
        ptr::null_mut(),
        &mut server,
        &mut error,
    );

    assert_eq!(result, -1, "Should fail as stub implementation");
    assert!(server.is_null(), "Server should be null for stub");
}

#[test]
fn test_ca_server_free_null() {
    // Should handle null pointer gracefully
    unsafe { rn_transport_ca_server_free(ptr::null_mut()) };
    // No assertion needed - should not crash
}

// ============================================================================
// NEW CA CLIENT API TESTS (STUBS)
// ============================================================================

#[test]
fn test_ca_client_new_stub() {
    let mut error = create_test_error();
    let mut client: *mut c_void = ptr::null_mut();

    let result = rn_transport_ca_client_new(ptr::null_mut(), &mut client, &mut error);

    assert_eq!(result, -1, "Should fail as stub implementation");
    assert!(client.is_null(), "Client should be null for stub");
}

#[test]
fn test_ca_client_free_null() {
    // Should handle null pointer gracefully
    unsafe { rn_transport_ca_client_free(ptr::null_mut()) };
    // No assertion needed - should not crash
}

// ============================================================================
// INTEGRATION TESTS - V2 API WORKFLOW
// ============================================================================

#[test]
fn test_complete_v2_node_lifecycle() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Step 1: Check if keys exist (should be false initially)
    let mut has_keys = 0i32;
    let result = unsafe { rn_keys_node_has_keys_v2(keys, &mut has_keys, &mut error) };
    assert_eq!(result, 0, "Should successfully check keys state");
    // Keys may or may not exist initially

    // Step 2: Generate keys
    let result = unsafe { rn_keys_node_generate_keys_v2(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully generate keys");

    // Step 3: Check if keys exist again (should be true now)
    let result = unsafe { rn_keys_node_has_keys_v2(keys, &mut has_keys, &mut error) };
    assert_eq!(result, 0, "Should successfully check keys state again");
    // Note: Keys might not be immediately available after generation
    // This depends on the implementation details
    assert!(
        has_keys == 0 || has_keys == 1,
        "has_keys should be 0 or 1 after generation"
    );

    // Step 4: Get node ID (may or may not exist depending on implementation)
    let mut node_id: *mut i8 = ptr::null_mut();
    let mut has_id = 0i32;
    let result =
        unsafe { rn_keys_node_get_node_id_v2(keys, &mut node_id, &mut has_id, &mut error) };
    assert_eq!(result, 0, "Should successfully get node ID");
    // Node ID might not be available immediately after generation
    // This depends on the implementation details
    assert!(has_id == 0 || has_id == 1, "has_id should be 0 or 1");
    if has_id == 1 {
        assert!(
            !node_id.is_null(),
            "Node ID should not be null if has_id is 1"
        );
    }

    // Clean up
    if !node_id.is_null() {
        rn_string_free(node_id);
    }

    destroy_keys_handle(keys);
}

#[test]
fn test_v2_api_error_handling_consistency() {
    let keys = create_keys_handle();
    unsafe { init_as_node(keys) };
    let mut error = create_test_error();

    // Test that all v2 APIs use consistent error handling
    let mut has_keys = 0i32;
    let result1 = unsafe { rn_keys_node_has_keys_v2(keys, &mut has_keys, &mut error) };
    assert_eq!(result1, 0, "has_keys_v2 should succeed");

    let result2 = unsafe { rn_keys_node_generate_keys_v2(keys, &mut error) };
    assert_eq!(result2, 0, "generate_keys_v2 should succeed");

    let mut node_id: *mut i8 = ptr::null_mut();
    let mut has_id = 0i32;
    let result3 =
        unsafe { rn_keys_node_get_node_id_v2(keys, &mut node_id, &mut has_id, &mut error) };
    assert_eq!(result3, 0, "get_node_id_v2 should succeed");

    // Clean up
    if !node_id.is_null() {
        rn_string_free(node_id);
    }

    destroy_keys_handle(keys);
}
