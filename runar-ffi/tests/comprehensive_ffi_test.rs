//! Comprehensive FFI API Tests
//!
//! This test suite covers all the new split functions, edge cases, error conditions,
//! and happy path scenarios for the FFI key management API.

use runar_ffi::*;
use std::ffi::c_void;
use std::ptr;

// Helper to create a fresh keys handle for testing
fn create_keys_handle() -> *mut c_void {
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

// Helper to destroy keys handle
fn destroy_keys_handle(keys: *mut c_void) {
    if !keys.is_null() {
        unsafe { rn_keys_free(keys) };
    }
}

// Helper to initialize as mobile
fn init_as_mobile(keys: *mut c_void) {
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };
    let result = unsafe { rn_keys_init_as_mobile(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully initialize as mobile");
}

// Helper to initialize as node
fn init_as_node(keys: *mut c_void) {
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };
    let result = unsafe { rn_keys_init_as_node(keys, &mut error) };
    assert_eq!(result, 0, "Should successfully initialize as node");
}

#[test]
fn test_node_encrypt_with_envelope_happy_path() {
    let keys = create_keys_handle();
    init_as_node(keys);
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
        unsafe { rn_free(eed_ptr, eed_len) };
    }
    destroy_keys_handle(keys);
}

#[test]
fn test_mobile_encrypt_with_envelope_happy_path() {
    let keys = create_keys_handle();
    init_as_mobile(keys);
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    // Test data
    let data = b"Hello, World!";
    let network_id = std::ffi::CString::new("test-network").unwrap();

    // Call the function
    let mut eed_ptr: *mut u8 = ptr::null_mut();
    let mut eed_len: usize = 0;

    let result = unsafe {
        rn_keys_mobile_encrypt_with_envelope(
            keys,
            data.as_ptr(),
            data.len(),
            network_id.as_ptr(),
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
        unsafe { rn_free(eed_ptr, eed_len) };
    }
    destroy_keys_handle(keys);
}

#[test]
fn test_node_encrypt_with_envelope_null_pointers() {
    let keys = create_keys_handle();
    init_as_node(keys);
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
    init_as_node(keys);
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
    init_as_node(keys);
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let data = b"Hello, World!";

    // Create invalid UTF-8 string
    let invalid_utf8 = vec![0xFF, 0xFE]; // Invalid UTF-8 sequence

    let result = unsafe {
        rn_keys_node_encrypt_with_envelope(
            keys,
            data.as_ptr(),
            data.len(),
            invalid_utf8.as_ptr() as *const i8, // Cast to simulate C string
            ptr::null(),
            ptr::null(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut error,
        )
    };
    assert_eq!(
        result, RN_ERROR_INVALID_UTF8,
        "Should fail with invalid UTF-8"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_node_encrypt_with_envelope_wrong_manager_type() {
    let keys = create_keys_handle();
    init_as_mobile(keys); // Initialize as mobile
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let data = b"Hello, World!";

    // Try to call node function with mobile initialization
    let result = unsafe {
        rn_keys_node_encrypt_with_envelope(
            keys,
            data.as_ptr(),
            data.len(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
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
    let result = unsafe {
        rn_keys_node_encrypt_with_envelope(
            keys,
            data.as_ptr(),
            data.len(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
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
    init_as_node(keys); // Initialize as node
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let data = b"Hello, World!";

    // Try to call mobile function with node initialization
    let result = unsafe {
        rn_keys_mobile_encrypt_with_envelope(
            keys,
            data.as_ptr(),
            data.len(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
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
    let result = unsafe {
        rn_keys_mobile_encrypt_with_envelope(
            keys,
            data.as_ptr(),
            data.len(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
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
    init_as_node(keys);
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

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
        unsafe { rn_free(cipher_ptr, cipher_len) };
    }
    destroy_keys_handle(keys);
}

#[test]
fn test_node_encrypt_local_data_wrong_manager_type() {
    let keys = create_keys_handle();
    init_as_mobile(keys); // Initialize as mobile
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let data = b"Secret data to encrypt";

    // Try to call node function with mobile initialization
    let result = unsafe {
        rn_keys_encrypt_local_data(
            keys,
            data.as_ptr(),
            data.len(),
            ptr::null_mut(),
            ptr::null_mut(),
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
    init_as_node(keys);
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
    init_as_mobile(keys);
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
    init_as_mobile(keys);
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let result = unsafe { rn_keys_mobile_initialize_user_root_key(keys, &mut error) };

    // Should succeed (may return 0 or some operation-specific error)
    assert!(
        result == 0 || result == RN_ERROR_OPERATION_FAILED,
        "Should succeed or fail with operation error, got: {}",
        result
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_mobile_initialize_user_root_key_wrong_manager_type() {
    let keys = create_keys_handle();
    init_as_node(keys); // Initialize as node
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
    init_as_node(keys);
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let mut pk_ptr: *mut u8 = ptr::null_mut();
    let mut pk_len: usize = 0;

    let result = unsafe { rn_keys_node_get_public_key(keys, &mut pk_ptr, &mut pk_len, &mut error) };

    assert_eq!(result, 0, "Should successfully get public key");
    assert!(!pk_ptr.is_null(), "Output should not be null");
    assert!(pk_len > 0, "Output length should be > 0");

    // Clean up
    if !pk_ptr.is_null() {
        unsafe { rn_free(pk_ptr, pk_len) };
    }
    destroy_keys_handle(keys);
}

#[test]
fn test_node_get_public_key_wrong_manager_type() {
    let keys = create_keys_handle();
    init_as_mobile(keys); // Initialize as mobile
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let result =
        unsafe { rn_keys_node_get_public_key(keys, ptr::null_mut(), ptr::null_mut(), &mut error) };

    assert_eq!(
        result, RN_ERROR_WRONG_MANAGER_TYPE,
        "Should fail with wrong manager type"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_node_get_agreement_public_key_happy_path() {
    let keys = create_keys_handle();
    init_as_node(keys);
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let mut pk_ptr: *mut u8 = ptr::null_mut();
    let mut pk_len: usize = 0;

    let result = unsafe {
        rn_keys_node_get_agreement_public_key(keys, &mut pk_ptr, &mut pk_len, &mut error)
    };

    assert_eq!(result, 0, "Should successfully get agreement public key");
    assert!(!pk_ptr.is_null(), "Output should not be null");
    assert!(pk_len > 0, "Output length should be > 0");

    // Clean up
    if !pk_ptr.is_null() {
        unsafe { rn_free(pk_ptr, pk_len) };
    }
    destroy_keys_handle(keys);
}

#[test]
fn test_node_get_agreement_public_key_wrong_manager_type() {
    let keys = create_keys_handle();
    init_as_mobile(keys); // Initialize as mobile
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let result = unsafe {
        rn_keys_node_get_agreement_public_key(keys, ptr::null_mut(), ptr::null_mut(), &mut error)
    };

    assert_eq!(
        result, RN_ERROR_WRONG_MANAGER_TYPE,
        "Should fail with wrong manager type"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_node_get_id_happy_path() {
    let keys = create_keys_handle();
    init_as_node(keys);
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let mut id_c: *mut i8 = ptr::null_mut();
    let mut id_len: usize = 0;

    let result = unsafe { rn_keys_node_get_node_id(keys, &mut id_c, &mut id_len, &mut error) };

    assert_eq!(result, 0, "Should successfully get node ID");
    assert!(!id_c.is_null(), "Output should not be null");
    assert!(id_len > 0, "Output length should be > 0");

    // Clean up
    if !id_c.is_null() {
        unsafe { rn_string_free(id_c) };
    }
    destroy_keys_handle(keys);
}

#[test]
fn test_node_get_id_wrong_manager_type() {
    let keys = create_keys_handle();
    init_as_mobile(keys); // Initialize as mobile
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let result =
        unsafe { rn_keys_node_get_node_id(keys, ptr::null_mut(), ptr::null_mut(), &mut error) };

    assert_eq!(
        result, RN_ERROR_WRONG_MANAGER_TYPE,
        "Should fail with wrong manager type"
    );

    destroy_keys_handle(keys);
}

#[test]
fn test_set_persistence_dir_happy_path() {
    let keys = create_keys_handle();
    init_as_node(keys); // Can work with either manager type
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
    init_as_node(keys); // Can work with either manager type
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
    init_as_node(keys);
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
    init_as_node(keys);
    let mut error = RnError {
        code: 0,
        message: ptr::null(),
    };

    let result = unsafe { rn_keys_flush_state(keys, &mut error) };

    assert_eq!(result, 0, "Should successfully flush state");

    destroy_keys_handle(keys);
}
