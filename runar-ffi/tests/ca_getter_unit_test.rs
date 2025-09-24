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

/// Test successful DER certificate retrieval
#[test]
fn test_ca_get_certificate_der_happy_path() {
    let ca_handle = create_test_ca();
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

    // Verify success
    assert_eq!(result, 0, "Certificate DER retrieval should succeed");
    assert!(!cert_ptr.is_null(), "Certificate DER pointer should not be null");
    assert!(cert_len > 0, "Certificate DER length should be positive");
    assert!(cert_len < 10000, "Certificate DER length should be reasonable");
    assert_eq!(error.code, 0, "Error code should be 0");

    // Verify the DER data starts with a sequence tag (0x30)
    let der_data = unsafe { std::slice::from_raw_parts(cert_ptr, cert_len) };
    assert_eq!(der_data[0], 0x30, "Certificate DER should start with sequence tag");

    // Clean up
    unsafe {
        rn_free(cert_ptr, cert_len);
        rn_keys_ca_free(ca_handle);
    }
    
    println!("✅ Certificate DER retrieved successfully: {cert_len} bytes");
}

/// Test DER retrieval with null CA pointer
#[test]
fn test_ca_get_certificate_der_null_ca() {
    let mut cert_ptr: *mut u8 = ptr::null_mut();
    let mut cert_len: usize = 0;
    let mut error = create_test_error();

    let result = unsafe {
        rn_keys_ca_get_certificate_der(
            ptr::null_mut(), // Null CA
            &mut cert_ptr,
            &mut cert_len,
            &mut error,
        )
    };

    // Verify error
    assert_eq!(result, RN_ERROR_NULL_ARGUMENT, "Should return null argument error");
    assert!(cert_ptr.is_null(), "Certificate pointer should remain null");
    assert_eq!(cert_len, 0, "Certificate length should remain 0");
    
    println!("✅ Null CA handle properly rejected");
}

/// Test DER retrieval with null output pointer
#[test]
fn test_ca_get_certificate_der_null_output_ptr() {
    let ca_handle = create_test_ca();
    let mut cert_len: usize = 0;
    let mut error = create_test_error();

    let result = unsafe {
        rn_keys_ca_get_certificate_der(
            ca_handle,
            ptr::null_mut(), // Null output pointer
            &mut cert_len,
            &mut error,
        )
    };

    // Verify error
    assert_eq!(result, RN_ERROR_NULL_ARGUMENT, "Should return null argument error");

    // Clean up
    unsafe {
        rn_keys_ca_free(ca_handle);
    }
    
    println!("✅ Null output pointer properly rejected");
}

/// Test DER retrieval with null length pointer
#[test]
fn test_ca_get_certificate_der_null_length_ptr() {
    let ca_handle = create_test_ca();
    let mut cert_ptr: *mut u8 = ptr::null_mut();
    let mut error = create_test_error();

    let result = unsafe {
        rn_keys_ca_get_certificate_der(
            ca_handle,
            &mut cert_ptr,
            ptr::null_mut(), // Null length pointer
            &mut error,
        )
    };

    // Verify error
    assert_eq!(result, RN_ERROR_NULL_ARGUMENT, "Should return null argument error");
    assert!(cert_ptr.is_null(), "Certificate pointer should remain null");

    // Clean up
    unsafe {
        rn_keys_ca_free(ca_handle);
    }
    
    println!("✅ Null length pointer properly rejected");
}

/// Test DER retrieval with null error pointer
#[test]
fn test_ca_get_certificate_der_null_error() {
    let ca_handle = create_test_ca();
    let mut cert_ptr: *mut u8 = ptr::null_mut();
    let mut cert_len: usize = 0;

    let result = unsafe {
        rn_keys_ca_get_certificate_der(
            ca_handle,
            &mut cert_ptr,
            &mut cert_len,
            ptr::null_mut(), // Null error pointer
        )
    };

    // Verify error
    assert_eq!(result, RN_ERROR_NULL_ARGUMENT, "Should return null argument error");
    assert!(cert_ptr.is_null(), "Certificate pointer should remain null");
    assert_eq!(cert_len, 0, "Certificate length should remain 0");

    // Clean up
    unsafe {
        rn_keys_ca_free(ca_handle);
    }
    
    println!("✅ Null error pointer properly rejected");
}

/// Test successful subject retrieval
#[test]
fn test_ca_get_certificate_subject_happy_path() {
    let ca_handle = create_test_ca();
    let mut subject_ptr: *mut c_char = ptr::null_mut();
    let mut error = create_test_error();

    let result = unsafe {
        rn_keys_ca_get_certificate_subject(
            ca_handle,
            &mut subject_ptr,
            &mut error,
        )
    };

    // Verify success
    assert_eq!(result, 0, "Certificate subject retrieval should succeed");
    assert!(!subject_ptr.is_null(), "Subject pointer should not be null");
    assert_eq!(error.code, 0, "Error code should be 0");

    // Verify the subject string is valid
    let subject_str = unsafe {
        CStr::from_ptr(subject_ptr).to_string_lossy()
    };
    assert!(subject_str.contains("CN=Test CA"), "Subject should contain CN=Test CA");
    assert!(subject_str.contains("O=Test"), "Subject should contain O=Test");
    assert!(subject_str.contains("C=US"), "Subject should contain C=US");

    // Clean up
    unsafe {
        rn_string_free(subject_ptr);
        rn_keys_ca_free(ca_handle);
    }
    
    println!("✅ Certificate subject retrieved successfully: {subject_str}");
}

/// Test subject retrieval with null CA pointer
#[test]
fn test_ca_get_certificate_subject_null_ca() {
    let mut subject_ptr: *mut c_char = ptr::null_mut();
    let mut error = create_test_error();

    let result = unsafe {
        rn_keys_ca_get_certificate_subject(
            ptr::null_mut(), // Null CA
            &mut subject_ptr,
            &mut error,
        )
    };

    // Verify error
    assert_eq!(result, RN_ERROR_NULL_ARGUMENT, "Should return null argument error");
    assert!(subject_ptr.is_null(), "Subject pointer should remain null");
    
    println!("✅ Null CA handle properly rejected");
}

/// Test subject retrieval with null output pointer
#[test]
fn test_ca_get_certificate_subject_null_output() {
    let ca_handle = create_test_ca();
    let mut error = create_test_error();

    let result = unsafe {
        rn_keys_ca_get_certificate_subject(
            ca_handle,
            ptr::null_mut(), // Null output pointer
            &mut error,
        )
    };

    // Verify error
    assert_eq!(result, RN_ERROR_NULL_ARGUMENT, "Should return null argument error");

    // Clean up
    unsafe {
        rn_keys_ca_free(ca_handle);
    }
    
    println!("✅ Null output pointer properly rejected");
}

/// Test subject retrieval with null error pointer
#[test]
fn test_ca_get_certificate_subject_null_error() {
    let ca_handle = create_test_ca();
    let mut subject_ptr: *mut c_char = ptr::null_mut();

    let result = unsafe {
        rn_keys_ca_get_certificate_subject(
            ca_handle,
            &mut subject_ptr,
            ptr::null_mut(), // Null error pointer
        )
    };

    // Verify error
    assert_eq!(result, RN_ERROR_NULL_ARGUMENT, "Should return null argument error");
    assert!(subject_ptr.is_null(), "Subject pointer should remain null");

    // Clean up
    unsafe {
        rn_keys_ca_free(ca_handle);
    }
    
    println!("✅ Null error pointer properly rejected");
}

/// Test both DER and subject retrieval on same CA
#[test]
fn test_ca_get_certificate_both_der_and_subject() {
    let ca_handle = create_test_ca();
    let mut error = create_test_error();

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
    assert_eq!(result, 0, "Certificate DER retrieval should succeed");
    assert!(!cert_ptr.is_null(), "Certificate DER pointer should not be null");
    assert!(cert_len > 0, "Certificate DER length should be positive");

    // Get subject
    let mut subject_ptr: *mut c_char = ptr::null_mut();
    let result = unsafe {
        rn_keys_ca_get_certificate_subject(
            ca_handle,
            &mut subject_ptr,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Certificate subject retrieval should succeed");
    assert!(!subject_ptr.is_null(), "Subject pointer should not be null");

    let subject_str = unsafe {
        CStr::from_ptr(subject_ptr).to_string_lossy()
    };
    assert!(subject_str.contains("CN=Test CA"), "Subject should contain CN=Test CA");

    // Clean up
    unsafe {
        rn_free(cert_ptr, cert_len);
        rn_string_free(subject_ptr);
        rn_keys_ca_free(ca_handle);
    }
    
    println!("✅ Both DER ({cert_len} bytes) and subject ({subject_str}) retrieved successfully");
}

/// Test multiple DER retrievals from same CA (should be consistent)
#[test]
fn test_ca_get_certificate_der_consistency() {
    let ca_handle = create_test_ca();
    let mut error = create_test_error();

    // First retrieval
    let mut cert_ptr1: *mut u8 = ptr::null_mut();
    let mut cert_len1: usize = 0;
    let result = unsafe {
        rn_keys_ca_get_certificate_der(
            ca_handle,
            &mut cert_ptr1,
            &mut cert_len1,
            &mut error,
        )
    };
    assert_eq!(result, 0, "First certificate DER retrieval should succeed");

    // Second retrieval
    let mut cert_ptr2: *mut u8 = ptr::null_mut();
    let mut cert_len2: usize = 0;
    let result = unsafe {
        rn_keys_ca_get_certificate_der(
            ca_handle,
            &mut cert_ptr2,
            &mut cert_len2,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Second certificate DER retrieval should succeed");

    // Verify consistency
    assert_eq!(cert_len1, cert_len2, "Certificate lengths should be identical");

    let cert_data1 = unsafe { std::slice::from_raw_parts(cert_ptr1, cert_len1) };
    let cert_data2 = unsafe { std::slice::from_raw_parts(cert_ptr2, cert_len2) };
    assert_eq!(cert_data1, cert_data2, "Certificate DER data should be identical");

    // Clean up
    unsafe {
        rn_free(cert_ptr1, cert_len1);
        rn_free(cert_ptr2, cert_len2);
        rn_keys_ca_free(ca_handle);
    }
    
    println!("✅ Certificate DER consistency verified across multiple retrievals");
}

/// Test multiple subject retrievals from same CA (should be consistent)
#[test]
fn test_ca_get_certificate_subject_consistency() {
    let ca_handle = create_test_ca();
    let mut error = create_test_error();

    // First retrieval
    let mut subject_ptr1: *mut c_char = ptr::null_mut();
    let result = unsafe {
        rn_keys_ca_get_certificate_subject(
            ca_handle,
            &mut subject_ptr1,
            &mut error,
        )
    };
    assert_eq!(result, 0, "First subject retrieval should succeed");

    let subject_str1 = unsafe {
        CStr::from_ptr(subject_ptr1).to_string_lossy().to_string()
    };

    // Second retrieval
    let mut subject_ptr2: *mut c_char = ptr::null_mut();
    let result = unsafe {
        rn_keys_ca_get_certificate_subject(
            ca_handle,
            &mut subject_ptr2,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Second subject retrieval should succeed");

    let subject_str2 = unsafe {
        CStr::from_ptr(subject_ptr2).to_string_lossy().to_string()
    };

    // Verify consistency
    assert_eq!(subject_str1, subject_str2, "Subject strings should be identical");

    // Clean up
    unsafe {
        rn_string_free(subject_ptr1);
        rn_string_free(subject_ptr2);
        rn_keys_ca_free(ca_handle);
    }
    
    println!("✅ Certificate subject consistency verified: {subject_str1}");
}

/// Test getter functions with issuing CA
#[test]
fn test_ca_getters_with_issuing_ca() {
    let mut error = create_test_error();

    // Create root CA
    let root_subject = create_cstring("CN=Getter Test Root CA,O=Test,C=US");
    let mut root_ca_handle: *mut std::os::raw::c_void = ptr::null_mut();
    let result = unsafe {
        rn_keys_ca_create_root_ca(
            cstring_to_ptr(&root_subject),
            &mut root_ca_handle,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Root CA creation should succeed");

    // Create issuing CA
    let issuing_subject = create_cstring("CN=Getter Test Issuing CA,O=Test,C=US");
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

    // Test issuing CA DER retrieval
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
    assert_eq!(result, 0, "Issuing CA DER retrieval should succeed");
    assert!(!issuing_cert_ptr.is_null(), "Issuing CA DER should not be null");
    assert!(issuing_cert_len > 0, "Issuing CA DER length should be positive");

    // Test issuing CA subject retrieval
    let mut issuing_subject_ptr: *mut c_char = ptr::null_mut();
    let result = unsafe {
        rn_keys_ca_get_certificate_subject(
            issuing_ca_handle,
            &mut issuing_subject_ptr,
            &mut error,
        )
    };
    assert_eq!(result, 0, "Issuing CA subject retrieval should succeed");
    assert!(!issuing_subject_ptr.is_null(), "Issuing CA subject should not be null");

    let issuing_subject_str = unsafe {
        CStr::from_ptr(issuing_subject_ptr).to_string_lossy()
    };
    assert!(issuing_subject_str.contains("CN=Getter Test Issuing CA"), 
           "Subject should contain issuing CA name");

    // Clean up
    unsafe {
        rn_free(issuing_cert_ptr, issuing_cert_len);
        rn_string_free(issuing_subject_ptr);
        rn_keys_ca_free(issuing_ca_handle);
        rn_keys_ca_free(root_ca_handle);
    }
    
    println!("✅ Issuing CA getters working correctly");
    println!("    DER: {issuing_cert_len} bytes");
    println!("    Subject: {issuing_subject_str}");
}
