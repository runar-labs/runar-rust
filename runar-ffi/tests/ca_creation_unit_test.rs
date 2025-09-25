use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

#[path = "../src/lib.rs"]
mod ffi;

use ffi::*;

fn create_test_error() -> RnError {
    RnError {
        code: 0,
        message: ptr::null_mut(),
    }
}

fn create_cstring(s: &str) -> CString {
    CString::new(s).expect("Failed to create CString")
}

fn cstring_to_ptr(s: &CString) -> *const c_char {
    s.as_ptr()
}

/// Test successful root CA creation with valid subject
#[test]
fn test_ca_create_root_ca_happy_path() {
    // Set up logging to match Swift test
    unsafe {
        let mut err = RnError {
            code: 0,
            message: std::ptr::null_mut(),
        };
        assert_eq!(rn_set_log_level(5, &mut err as *mut _ as *mut _), 0); // 5 = trace level
        let node_id = std::ffi::CString::new("ca-tests").unwrap();
        assert_eq!(rn_set_logger_node_id(node_id.as_ptr(), &mut err as *mut _ as *mut _), 0);
    }
    
    let subject = create_cstring("CN=Test Root CA,O=Test,C=US");
    let mut ca_handle: *mut std::os::raw::c_void = ptr::null_mut();
    let mut error = create_test_error();

    let result = unsafe {
        rn_keys_ca_create_root_ca(
            cstring_to_ptr(&subject),
            &mut ca_handle,
            &mut error,
        )
    };

    // Verify success
    if result != 0 {
        println!("   ❌ Root CA creation failed with error code: {result}");
        if !error.message.is_null() {
            let error_msg = unsafe { std::ffi::CStr::from_ptr(error.message).to_string_lossy() };
            println!("   ❌ Error message: {error_msg}");
        }
    }
    assert_eq!(result, 0, "Root CA creation should succeed");
    assert!(!ca_handle.is_null(), "CA handle should not be null");
    assert_eq!(error.code, 0, "Error code should be 0");

    // Clean up
    unsafe {
        rn_keys_ca_free(ca_handle);
    }
    
    println!("✅ Root CA created successfully");
}

/// Test root CA creation with null subject pointer
#[test]
fn test_ca_create_root_ca_null_subject() {
    let mut ca_handle: *mut std::os::raw::c_void = ptr::null_mut();
    let mut error = create_test_error();

    let result = unsafe {
        rn_keys_ca_create_root_ca(
            ptr::null(),
            &mut ca_handle,
            &mut error,
        )
    };

    // Verify error
    assert_eq!(result, RN_ERROR_NULL_ARGUMENT, "Should return null argument error");
    assert!(ca_handle.is_null(), "CA handle should remain null");
    
    println!("✅ Null subject properly rejected");
}

/// Test root CA creation with null output pointer
#[test]
fn test_ca_create_root_ca_null_output() {
    let subject = create_cstring("CN=Test Root CA,O=Test,C=US");
    let mut error = create_test_error();

    let result = unsafe {
        rn_keys_ca_create_root_ca(
            cstring_to_ptr(&subject),
            ptr::null_mut(),
            &mut error,
        )
    };

    // Verify error
    assert_eq!(result, RN_ERROR_NULL_ARGUMENT, "Should return null argument error");
    
    println!("✅ Null output pointer properly rejected");
}

/// Test root CA creation with null error pointer
#[test]
fn test_ca_create_root_ca_null_error() {
    let subject = create_cstring("CN=Test Root CA,O=Test,C=US");
    let mut ca_handle: *mut std::os::raw::c_void = ptr::null_mut();

    let result = unsafe {
        rn_keys_ca_create_root_ca(
            cstring_to_ptr(&subject),
            &mut ca_handle,
            ptr::null_mut(),
        )
    };

    // Verify error
    assert_eq!(result, RN_ERROR_NULL_ARGUMENT, "Should return null argument error");
    assert!(ca_handle.is_null(), "CA handle should remain null");
    
    println!("✅ Null error pointer properly rejected");
}

/// Test root CA creation with zero validity days
#[test]
fn test_ca_create_root_ca_zero_validity() {
    let subject = create_cstring("CN=Test Root CA,O=Test,C=US");
    let mut ca_handle: *mut std::os::raw::c_void = ptr::null_mut();
    let mut error = create_test_error();

    let result = unsafe {
        rn_keys_ca_create_root_ca(
            cstring_to_ptr(&subject),
            &mut ca_handle,
            &mut error,
        )
    };

    // Verify success (root CA creation doesn't take validity_days parameter)
    assert_eq!(result, 0, "Root CA creation should succeed");
    assert!(!ca_handle.is_null(), "CA handle should not be null");
    assert_eq!(error.code, 0, "Error code should be 0");
    
    // Clean up
    unsafe {
        rn_keys_ca_free(ca_handle);
    }
    
    println!("✅ Root CA created successfully (no validity_days parameter)");
}

/// Test successful issuing CA creation
#[test]
fn test_ca_create_issuing_ca_happy_path() {
    // First create a root CA
    let root_subject = create_cstring("CN=Test Root CA,O=Test,C=US");
    let mut root_ca_handle: *mut std::os::raw::c_void = ptr::null_mut();
    let mut error = create_test_error();

    let result = unsafe {
        rn_keys_ca_create_root_ca(
            cstring_to_ptr(&root_subject),
            &mut root_ca_handle,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Root CA creation should succeed");
    assert!(!root_ca_handle.is_null(), "Root CA handle should not be null");

    // Now create issuing CA
    let issuing_subject = create_cstring("CN=Test Issuing CA,O=Test,C=US");
    let mut issuing_ca_handle: *mut std::os::raw::c_void = ptr::null_mut();

    let result = unsafe {
        rn_keys_ca_create_issuing_ca(
            root_ca_handle,
            cstring_to_ptr(&issuing_subject),
            365, // validity_days
            1, // Serial number
            &mut issuing_ca_handle,
            &mut error,
        )
    };

    // Verify success
    assert_eq!(result, 0, "Issuing CA creation should succeed");
    assert!(!issuing_ca_handle.is_null(), "Issuing CA handle should not be null");
    assert_eq!(error.code, 0, "Error code should be 0");

    // Clean up
    unsafe {
        rn_keys_ca_free(issuing_ca_handle);
        rn_keys_ca_free(root_ca_handle);
    }
    
    println!("✅ Issuing CA created successfully");
}

/// Test issuing CA creation with null root CA pointer
#[test]
fn test_ca_create_issuing_ca_null_root_ca() {
    let issuing_subject = create_cstring("CN=Test Issuing CA,O=Test,C=US");
    let mut issuing_ca_handle: *mut std::os::raw::c_void = ptr::null_mut();
    let mut error = create_test_error();

    let result = unsafe {
        rn_keys_ca_create_issuing_ca(
            ptr::null_mut(), // Null root CA
            cstring_to_ptr(&issuing_subject),
            365, // validity_days
            1,
            &mut issuing_ca_handle,
            &mut error,
        )
    };

    // Verify error
    assert_eq!(result, RN_ERROR_NULL_ARGUMENT, "Should return null argument error");
    assert!(issuing_ca_handle.is_null(), "Issuing CA handle should remain null");
    
    println!("✅ Null root CA properly rejected");
}

/// Test issuing CA creation with null subject pointer
#[test]
fn test_ca_create_issuing_ca_null_subject() {
    // First create a root CA
    let root_subject = create_cstring("CN=Test Root CA,O=Test,C=US");
    let mut root_ca_handle: *mut std::os::raw::c_void = ptr::null_mut();
    let mut error = create_test_error();

    let result = unsafe {
        rn_keys_ca_create_root_ca(
            cstring_to_ptr(&root_subject),
            &mut root_ca_handle,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Root CA creation should succeed");

    // Try to create issuing CA with null subject
    let mut issuing_ca_handle: *mut std::os::raw::c_void = ptr::null_mut();

    let result = unsafe {
        rn_keys_ca_create_issuing_ca(
            root_ca_handle,
            ptr::null(), // Null subject
            365, // validity_days
            1,
            &mut issuing_ca_handle,
            &mut error,
        )
    };

    // Verify error
    assert_eq!(result, RN_ERROR_NULL_ARGUMENT, "Should return null argument error");
    assert!(issuing_ca_handle.is_null(), "Issuing CA handle should remain null");

    // Clean up
    unsafe {
        rn_keys_ca_free(root_ca_handle);
    }
    
    println!("✅ Null subject properly rejected");
}

/// Test issuing CA creation with null output pointer
#[test]
fn test_ca_create_issuing_ca_null_output() {
    // First create a root CA
    let root_subject = create_cstring("CN=Test Root CA,O=Test,C=US");
    let mut root_ca_handle: *mut std::os::raw::c_void = ptr::null_mut();
    let mut error = create_test_error();

    let result = unsafe {
        rn_keys_ca_create_root_ca(
            cstring_to_ptr(&root_subject),
            &mut root_ca_handle,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Root CA creation should succeed");

    // Try to create issuing CA with null output
    let issuing_subject = create_cstring("CN=Test Issuing CA,O=Test,C=US");

    let result = unsafe {
        rn_keys_ca_create_issuing_ca(
            root_ca_handle,
            cstring_to_ptr(&issuing_subject),
            365, // validity_days
            1,
            ptr::null_mut(), // Null output
            &mut error,
        )
    };

    // Verify error
    assert_eq!(result, RN_ERROR_NULL_ARGUMENT, "Should return null argument error");

    // Clean up
    unsafe {
        rn_keys_ca_free(root_ca_handle);
    }
    
    println!("✅ Null output pointer properly rejected");
}

/// Test issuing CA creation with zero validity days
#[test]
fn test_ca_create_issuing_ca_zero_validity() {
    // First create a root CA
    let root_subject = create_cstring("CN=Test Root CA,O=Test,C=US");
    let mut root_ca_handle: *mut std::os::raw::c_void = ptr::null_mut();
    let mut error = create_test_error();

    let result = unsafe {
        rn_keys_ca_create_root_ca(
            cstring_to_ptr(&root_subject),
            &mut root_ca_handle,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Root CA creation should succeed");

    // Try to create issuing CA with zero validity
    let issuing_subject = create_cstring("CN=Test Issuing CA,O=Test,C=US");
    let mut issuing_ca_handle: *mut std::os::raw::c_void = ptr::null_mut();

    let result = unsafe {
        rn_keys_ca_create_issuing_ca(
            root_ca_handle,
            cstring_to_ptr(&issuing_subject),
            0, // Zero validity days
            1,
            &mut issuing_ca_handle,
            &mut error,
        )
    };

    // Verify error
    assert_eq!(result, RN_ERROR_INVALID_ARGUMENT, "Should return invalid argument error");
    assert!(issuing_ca_handle.is_null(), "Issuing CA handle should remain null");

    // Clean up
    unsafe {
        rn_keys_ca_free(root_ca_handle);
    }
    
    println!("✅ Zero validity days properly rejected");
}

/// Test issuing CA creation with zero serial number
#[test]
fn test_ca_create_issuing_ca_zero_serial() {
    // First create a root CA
    let root_subject = create_cstring("CN=Test Root CA,O=Test,C=US");
    let mut root_ca_handle: *mut std::os::raw::c_void = ptr::null_mut();
    let mut error = create_test_error();

    let result = unsafe {
        rn_keys_ca_create_root_ca(
            cstring_to_ptr(&root_subject),
            &mut root_ca_handle,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Root CA creation should succeed");

    // Try to create issuing CA with zero serial number
    let issuing_subject = create_cstring("CN=Test Issuing CA,O=Test,C=US");
    let mut issuing_ca_handle: *mut std::os::raw::c_void = ptr::null_mut();

    let result = unsafe {
        rn_keys_ca_create_issuing_ca(
            root_ca_handle,
            cstring_to_ptr(&issuing_subject),
            365, // validity_days
            0, // Zero serial number
            &mut issuing_ca_handle,
            &mut error,
        )
    };

    // Verify error
    assert_eq!(result, RN_ERROR_INVALID_ARGUMENT, "Should return invalid argument error");
    assert!(issuing_ca_handle.is_null(), "Issuing CA handle should remain null");

    // Clean up
    unsafe {
        rn_keys_ca_free(root_ca_handle);
    }
    
    println!("✅ Zero serial number properly rejected");
}

/// Test complete CA hierarchy creation workflow
#[test]
fn test_ca_hierarchy_creation_workflow() {
    let mut error = create_test_error();

    // Create root CA
    let root_subject = create_cstring("CN=Workflow Root CA,O=Workflow Test,C=US");
    let mut root_ca_handle: *mut std::os::raw::c_void = ptr::null_mut();

    let result = unsafe {
        rn_keys_ca_create_root_ca(
            cstring_to_ptr(&root_subject),
            &mut root_ca_handle,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Root CA creation should succeed");
    assert!(!root_ca_handle.is_null(), "Root CA handle should not be null");

    // Create issuing CA
    let issuing_subject = create_cstring("CN=Workflow Issuing CA,O=Workflow Test,C=US");
    let mut issuing_ca_handle: *mut std::os::raw::c_void = ptr::null_mut();

    let result = unsafe {
        rn_keys_ca_create_issuing_ca(
            root_ca_handle,
            cstring_to_ptr(&issuing_subject),
            365, // validity_days
            42, // Custom serial number
            &mut issuing_ca_handle,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Issuing CA creation should succeed");
    assert!(!issuing_ca_handle.is_null(), "Issuing CA handle should not be null");

    // Verify both CAs can be used to get certificates
    let mut root_cert_ptr: *mut u8 = ptr::null_mut();
    let mut root_cert_len: usize = 0;
    let result = unsafe {
        rn_keys_ca_get_certificate_der(
            root_ca_handle,
            &mut root_cert_ptr,
            &mut root_cert_len,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Root CA certificate retrieval should succeed");
    assert!(!root_cert_ptr.is_null(), "Root cert DER should not be null");
    assert!(root_cert_len > 0, "Root cert DER length should be positive");

    let mut issuing_cert_ptr: *mut u8 = ptr::null_mut();
    let mut issuing_cert_len: usize = 0;
    let result = unsafe {
        rn_keys_ca_get_certificate_der(
            issuing_ca_handle,
            &mut issuing_cert_ptr,
            &mut issuing_cert_len,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Issuing CA certificate retrieval should succeed");
    assert!(!issuing_cert_ptr.is_null(), "Issuing cert DER should not be null");
    assert!(issuing_cert_len > 0, "Issuing cert DER length should be positive");

    // Clean up
    unsafe {
        if !root_cert_ptr.is_null() {
            rn_free(root_cert_ptr, root_cert_len);
        }
        if !issuing_cert_ptr.is_null() {
            rn_free(issuing_cert_ptr, issuing_cert_len);
        }
        rn_keys_ca_free(issuing_ca_handle);
        rn_keys_ca_free(root_ca_handle);
    }
    
    println!("✅ Complete CA hierarchy workflow completed successfully");
}
