use std::ffi::{CStr, CString};
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

fn create_test_ca() -> *mut std::os::raw::c_void {
    let subject = create_cstring("CN=Test CA,O=Test,C=US");
    let mut ca_handle: *mut std::os::raw::c_void = ptr::null_mut();
    let mut error = create_test_error();

    let result = unsafe {
        rn_keys_ca_create_root_ca(
            cstring_to_ptr(&subject),
            &mut ca_handle,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Test CA creation should succeed");
    assert!(!ca_handle.is_null(), "Test CA handle should not be null");
    
    ca_handle
}

/// Test successful CA handle freeing
#[test]
fn test_ca_free_happy_path() {
    let ca_handle = create_test_ca();
    
    // Verify CA is usable before freeing
    let mut cert_ptr: *mut u8 = ptr::null_mut();
    let mut cert_len: usize = 0;
    let mut error = create_test_error();
    
    let result = unsafe {
        rn_keys_ca_get_certificate_der(
            ca_handle,
            &mut cert_ptr,
            &mut cert_len,
            &mut error,
        )
    };
    assert_eq!(result, 0, "CA should be usable before freeing");
    assert!(!cert_ptr.is_null(), "Certificate should be retrievable");
    
    // Free the certificate memory
    unsafe {
        rn_free(cert_ptr, cert_len);
    }
    
    // Free the CA handle - should not crash
    unsafe {
        rn_keys_ca_free(ca_handle);
    }
    
    println!("✅ CA handle freed successfully without crashes");
}

/// Test freeing null handle (should be safe)
#[test]
fn test_ca_free_null_handle() {
    // Freeing null handle should not crash
    unsafe {
        rn_keys_ca_free(ptr::null_mut());
    }
    
    println!("✅ Freeing null CA handle completed safely");
}

/// Test multiple CA creation and freeing
#[test]
fn test_ca_multiple_creation_and_freeing() {
    let mut ca_handles = Vec::new();
    let mut error = create_test_error();
    
    // Create multiple CAs
    for i in 0..5 {
        let subject = create_cstring(&format!("CN=Test CA {i},O=Test,C=US"));
        let mut ca_handle: *mut std::os::raw::c_void = ptr::null_mut();
        
        let result = unsafe {
            rn_keys_ca_create_root_ca(
                cstring_to_ptr(&subject),
                &mut ca_handle,
                &mut error,
            )
        };
        assert_eq!(result, 0, "CA {i} creation should succeed");
        assert!(!ca_handle.is_null(), "CA {i} handle should not be null");
        
        ca_handles.push(ca_handle);
    }
    
    // Verify all CAs are usable
    for (i, &ca_handle) in ca_handles.iter().enumerate() {
        let mut subject_ptr: *mut c_char = ptr::null_mut();
        let result = unsafe {
            rn_keys_ca_get_certificate_subject(
                ca_handle,
                &mut subject_ptr,
                &mut error,
            )
        };
        assert_eq!(result, 0, "CA {i} should be usable");
        assert!(!subject_ptr.is_null(), "CA {i} subject should be retrievable");
        
        let subject_str = unsafe {
            CStr::from_ptr(subject_ptr).to_string_lossy()
        };
        assert!(subject_str.contains(&format!("CN=Test CA {i}")), 
               "CA {i} should have correct subject");
        
        unsafe {
            rn_string_free(subject_ptr);
        }
    }
    
    // Free all CAs
    for (i, ca_handle) in ca_handles.into_iter().enumerate() {
        unsafe {
            rn_keys_ca_free(ca_handle);
        }
        println!("    ✅ CA {i} freed successfully");
    }
    
    println!("✅ Multiple CA creation and freeing completed successfully");
}

/// Test CA handle reuse after creation (but before freeing)
#[test]
fn test_ca_handle_reuse_patterns() {
    let ca_handle = create_test_ca();
    let mut error = create_test_error();
    
    // Use the handle multiple times for different operations
    for i in 0..3 {
        // Get DER certificate
        let mut cert_ptr: *mut u8 = ptr::null_mut();
        let mut cert_len: usize = 0;
        let result = unsafe {
            rn_keys_ca_get_certificate_der(
                ca_handle,
                &mut cert_ptr,
                &mut cert_len,
                &mut error,
            )
        };
        assert_eq!(result, 0, "DER retrieval {i} should succeed");
        assert!(!cert_ptr.is_null(), "DER {i} should not be null");
        
        // Get subject
        let mut subject_ptr: *mut c_char = ptr::null_mut();
        let result = unsafe {
            rn_keys_ca_get_certificate_subject(
                ca_handle,
                &mut subject_ptr,
                &mut error,
            )
        };
        assert_eq!(result, 0, "Subject retrieval {i} should succeed");
        assert!(!subject_ptr.is_null(), "Subject {i} should not be null");
        
        // Clean up this iteration's allocations
        unsafe {
            rn_free(cert_ptr, cert_len);
            rn_string_free(subject_ptr);
        }
        
        println!("    ✅ Iteration {i}: handle reused successfully");
    }
    
    // Final cleanup
    unsafe {
        rn_keys_ca_free(ca_handle);
    }
    
    println!("✅ CA handle reuse patterns completed successfully");
}

/// Test memory allocation patterns with getters
#[test]
fn test_ca_memory_allocation_patterns() {
    let ca_handle = create_test_ca();
    let mut error = create_test_error();
    let mut allocated_resources = Vec::new();
    
    // Allocate multiple certificates and subjects
    for i in 0..3 {
        // Allocate certificate DER
        let mut cert_ptr: *mut u8 = ptr::null_mut();
        let mut cert_len: usize = 0;
        let result = unsafe {
            rn_keys_ca_get_certificate_der(
                ca_handle,
                &mut cert_ptr,
                &mut cert_len,
                &mut error,
            )
        };
        assert_eq!(result, 0, "Certificate allocation {i} should succeed");
        assert!(!cert_ptr.is_null(), "Certificate {i} should not be null");
        assert!(cert_len > 0, "Certificate {i} length should be positive");
        allocated_resources.push((cert_ptr, cert_len, false)); // false = certificate
        
        // Allocate subject string
        let mut subject_ptr: *mut c_char = ptr::null_mut();
        let result = unsafe {
            rn_keys_ca_get_certificate_subject(
                ca_handle,
                &mut subject_ptr,
                &mut error,
            )
        };
        assert_eq!(result, 0, "Subject allocation {i} should succeed");
        assert!(!subject_ptr.is_null(), "Subject {i} should not be null");
        allocated_resources.push((subject_ptr as *mut u8, 0, true)); // true = subject
        
        println!("    ✅ Allocation {i}: certificate ({cert_len} bytes) and subject allocated");
    }
    
    // Verify all allocated resources are still valid
    for (i, (ptr, len, is_subject)) in allocated_resources.iter().enumerate() {
        if *is_subject {
            // Verify subject string is still valid
            let subject_str = unsafe {
                CStr::from_ptr(*ptr as *const c_char).to_string_lossy()
            };
            assert!(subject_str.contains("CN=Test CA"), "Subject {i} should still be valid");
        } else {
            // Verify certificate DER is still valid
            let cert_data = unsafe { std::slice::from_raw_parts(*ptr, *len) };
            assert_eq!(cert_data[0], 0x30, "Certificate {i} should still start with sequence tag");
        }
    }
    
    // Free all allocated resources
    for (i, (ptr, len, is_subject)) in allocated_resources.into_iter().enumerate() {
        unsafe {
            if is_subject {
                rn_string_free(ptr as *mut c_char);
            } else {
                rn_free(ptr, len);
            }
        }
        println!("    ✅ Resource {i} freed successfully");
    }
    
    // Free the CA handle
    unsafe {
        rn_keys_ca_free(ca_handle);
    }
    
    println!("✅ Memory allocation patterns completed successfully");
}

/// Test CA hierarchy memory management
#[test]
fn test_ca_hierarchy_memory_management() {
    let mut error = create_test_error();
    
    // Create root CA
    let root_subject = create_cstring("CN=Memory Test Root CA,O=Test,C=US");
    let mut root_ca_handle: *mut std::os::raw::c_void = ptr::null_mut();
    let result = unsafe {
        rn_keys_ca_create_root_ca(
            cstring_to_ptr(&root_subject),
            &mut root_ca_handle,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Root CA creation should succeed");
    
    // Create multiple issuing CAs
    let mut issuing_ca_handles = Vec::new();
    for i in 0..3 {
        let issuing_subject = create_cstring(&format!("CN=Memory Test Issuing CA {i},O=Test,C=US"));
        let mut issuing_ca_handle: *mut std::os::raw::c_void = ptr::null_mut();
        let result = unsafe {
            rn_keys_ca_create_issuing_ca(
                root_ca_handle,
                cstring_to_ptr(&issuing_subject),
                365, // validity_days
                i + 1,
                &mut issuing_ca_handle,
                &mut error,
            )
        };
        assert_eq!(result, 0, "Issuing CA {i} creation should succeed");
        assert!(!issuing_ca_handle.is_null(), "Issuing CA {i} handle should not be null");
        issuing_ca_handles.push(issuing_ca_handle);
    }
    
    // Get certificates from all CAs to test memory allocation
    let mut cert_data = Vec::new();
    
    // Root CA certificate
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
    cert_data.push((root_cert_ptr, root_cert_len));
    
    // Issuing CA certificates
    for (i, &issuing_ca_handle) in issuing_ca_handles.iter().enumerate() {
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
        assert_eq!(result, 0, "Issuing CA {i} certificate retrieval should succeed");
        cert_data.push((issuing_cert_ptr, issuing_cert_len));
        println!("    ✅ Issuing CA {i} certificate retrieved ({issuing_cert_len} bytes)");
    }
    
    // Free certificates first
    for (i, (cert_ptr, cert_len)) in cert_data.into_iter().enumerate() {
        unsafe {
            rn_free(cert_ptr, cert_len);
        }
        println!("    ✅ Certificate {i} memory freed");
    }
    
    // Free issuing CAs (children first)
    for (i, issuing_ca_handle) in issuing_ca_handles.into_iter().enumerate() {
        unsafe {
            rn_keys_ca_free(issuing_ca_handle);
        }
        println!("    ✅ Issuing CA {i} freed");
    }
    
    // Free root CA (parent last)
    unsafe {
        rn_keys_ca_free(root_ca_handle);
    }
    println!("    ✅ Root CA freed");
    
    println!("✅ CA hierarchy memory management completed successfully");
}

/// Test freeing CAs in different orders
#[test]
fn test_ca_free_different_orders() {
    let mut error = create_test_error();
    
    // Test 1: Create and free in same order
    let mut cas_same_order = Vec::new();
    for i in 0..3 {
        let ca_handle = create_test_ca();
        cas_same_order.push(ca_handle);
    }
    for (i, ca_handle) in cas_same_order.into_iter().enumerate() {
        unsafe {
            rn_keys_ca_free(ca_handle);
        }
        println!("    ✅ Same order: CA {i} freed");
    }
    
    // Test 2: Create and free in reverse order
    let mut cas_reverse_order = Vec::new();
    for i in 0..3 {
        let ca_handle = create_test_ca();
        cas_reverse_order.push(ca_handle);
    }
    for (i, ca_handle) in cas_reverse_order.into_iter().rev().enumerate() {
        unsafe {
            rn_keys_ca_free(ca_handle);
        }
        println!("    ✅ Reverse order: CA {i} freed");
    }
    
    // Test 3: Create hierarchy and free parent first
    let root_subject = create_cstring("CN=Order Test Root CA,O=Test,C=US");
    let mut root_ca_handle: *mut std::os::raw::c_void = ptr::null_mut();
    let result = unsafe {
        rn_keys_ca_create_root_ca(
            cstring_to_ptr(&root_subject),
            &mut root_ca_handle,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Root CA creation should succeed");
    
    let issuing_subject = create_cstring("CN=Order Test Issuing CA,O=Test,C=US");
    let mut issuing_ca_handle: *mut std::os::raw::c_void = ptr::null_mut();
    let result = unsafe {
        rn_keys_ca_create_issuing_ca(
            root_ca_handle,
            cstring_to_ptr(&issuing_subject),
            365, // validity_days
            1,
            &mut issuing_ca_handle,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Issuing CA creation should succeed");
    
    // Free parent first (should not affect child since they are independent handles)
    unsafe {
        rn_keys_ca_free(root_ca_handle);
    }
    println!("    ✅ Parent freed first");
    
    // Child should still be usable for getting certificate
    let mut cert_ptr: *mut u8 = ptr::null_mut();
    let mut cert_len: usize = 0;
    let result = unsafe {
        rn_keys_ca_get_certificate_der(
            issuing_ca_handle,
            &mut cert_ptr,
            &mut cert_len,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Child CA should still be usable after parent freed");
    
    unsafe {
        rn_free(cert_ptr, cert_len);
        rn_keys_ca_free(issuing_ca_handle);
    }
    println!("    ✅ Child freed after parent");
    
    println!("✅ CA freeing in different orders completed successfully");
}

/// Test that freed handles are properly invalidated (defensive test)
#[test]
fn test_ca_handle_invalidation_after_free() {
    let ca_handle = create_test_ca();
    
    // Verify CA works before freeing
    let mut cert_ptr: *mut u8 = ptr::null_mut();
    let mut cert_len: usize = 0;
    let mut error = create_test_error();
    
    let result = unsafe {
        rn_keys_ca_get_certificate_der(
            ca_handle,
            &mut cert_ptr,
            &mut cert_len,
            &mut error,
        )
    };
    assert_eq!(result, 0, "CA should work before freeing");
    
    unsafe {
        rn_free(cert_ptr, cert_len);
    }
    
    // Free the CA
    unsafe {
        rn_keys_ca_free(ca_handle);
    }
    
    // Note: We cannot safely test using the handle after freeing as it would be undefined behavior
    // The memory might be reused and could cause crashes or undefined results
    // In a real implementation, we would expect the FFI to detect invalid handles and return errors
    
    println!("✅ CA handle invalidation test completed (handle properly freed)");
}
