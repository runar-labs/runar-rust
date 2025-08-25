//! Linux-specific keystore tests
//!
//! These tests only run when the `linux-keystore` feature is enabled and
//! the target OS is Linux. They test Linux-specific keystore functionality.

mod common;

#[cfg(all(feature = "linux-keystore", target_os = "linux"))]
mod linux_tests {
    use crate::common::*;
    use runar_ffi::*;
    use std::ptr;

    #[test]
    fn test_linux_keystore_registration() {
        // Test Linux keystore registration - only available on Linux
        let keys = create_keys_handle();
        unsafe { init_as_mobile(keys) };

        let mut error = create_test_error();
        let service = create_cstring("test-service");
        let account = create_cstring("test-account");

        let result = unsafe {
            rn_keys_register_linux_device_keystore(
                keys,
                service.as_ptr(),
                account.as_ptr(),
                &mut error,
            )
        };

        // This should succeed on Linux with linux-keystore feature
        assert_eq!(result, 0, "Linux keystore registration should succeed");

        destroy_keys_handle(keys);
    }

    #[test]
    fn test_linux_keystore_state_management() {
        // Test Linux keystore state management
        let keys = create_keys_handle();
        unsafe { init_as_mobile(keys) };

        let mut error = create_test_error();
        let mut state = 0;

        let result = unsafe { rn_keys_mobile_get_keystore_state(keys, &mut state, &mut error) };

        assert_eq!(result, 0, "Should get keystore state on Linux");
        assert!(state >= 0, "Keystore state should be valid");

        destroy_keys_handle(keys);
    }

    #[test]
    fn test_linux_keystore_network_key_operations() {
        // Test Linux keystore network key operations
        let keys = create_keys_handle();
        unsafe { init_as_mobile(keys) };

        let mut error = create_test_error();
        let mut key_ptr: *mut i8 = ptr::null_mut();
        let mut key_len: usize = 0;

        // Generate network data key
        let result = unsafe {
            rn_keys_mobile_generate_network_data_key(keys, &mut key_ptr, &mut key_len, &mut error)
        };

        assert_eq!(result, 0, "Should generate network data key on Linux");
        assert!(!key_ptr.is_null(), "Generated key should not be null");
        assert!(key_len > 0, "Generated key should have length > 0");

        // Clean up
        if !key_ptr.is_null() {
            rn_string_free(key_ptr);
        }

        destroy_keys_handle(keys);
    }
}

// When not on Linux or linux-keystore feature not enabled, provide empty module
#[cfg(not(all(feature = "linux-keystore", target_os = "linux")))]
mod linux_tests {
    // This module is intentionally empty when not on Linux
    // or when linux-keystore feature is not enabled
}
