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
    use runar_logging::{Component, Logger};
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

/// Create Root CA certificate
#[allow(dead_code)]
pub fn create_root_ca_certificate() -> Vec<u8> {
    use runar_keys::certificate::CertificateAuthority;

    let ca =
        CertificateAuthority::new("CN=Test Root CA,O=Test,C=US").expect("Failed to create Root CA");
    ca.ca_certificate().der_bytes().to_vec()
}

/// Create Root CA and Issuing CA certificates with proper chain
/// Returns (root_ca_cert_der, issuing_key_der, issuing_cert_der)
#[allow(dead_code)]
pub fn create_ca_certificate_chain() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use runar_keys::certificate::{CertificateAuthority, CertificateRequest, EcdsaKeyPair};

    // Create Root CA
    let root_ca =
        CertificateAuthority::new("CN=Test Root CA,O=Test,C=US").expect("Failed to create Root CA");

    // Create Issuing CA key
    let issuing_key = EcdsaKeyPair::new().expect("Failed to create issuing CA key");

    // Create Issuing CA CSR
    let issuing_csr = CertificateRequest::create(&issuing_key, "CN=Test Issuing CA,O=Test,C=US")
        .expect("Failed to create issuing CA CSR");

    // Sign Issuing CA certificate with Root CA
    let issuing_cert = root_ca
        .sign_ca_certificate_request_with_serial(&issuing_csr, 365, Some(1))
        .expect("Failed to sign issuing CA certificate");

    // Export certificates and key
    let root_ca_cert_der = root_ca.ca_certificate().der_bytes().to_vec();
    let issuing_key_cbor =
        serde_cbor::to_vec(&issuing_key).expect("Failed to serialize key as CBOR");
    let issuing_cert_der = issuing_cert.der_bytes().to_vec();

    (root_ca_cert_der, issuing_key_cbor, issuing_cert_der)
}

/// Create Issuing CA certificate (key and cert) - DEPRECATED, use create_ca_certificate_chain
#[allow(dead_code)]
pub fn create_issuing_ca_certificate() -> (Vec<u8>, Vec<u8>) {
    let (_, issuing_key_cbor, issuing_cert_der) = create_ca_certificate_chain();
    (issuing_key_cbor, issuing_cert_der)
}

/// Create enrollment token
#[allow(dead_code)]
pub fn create_enrollment_token(network_id: &str, token_id: &str) -> Vec<u8> {
    use runar_keys::certificate::EcdsaKeyPair;
    use runar_keys::{EnrollmentToken, EnrollmentTokenBody};
    use serde_cbor;
    use std::time::SystemTime;

    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let ea_key = EcdsaKeyPair::new().expect("Failed to create EA key");

    let token_body = EnrollmentTokenBody::new(
        token_id.to_string(),
        network_id.to_string(),
        Some("test_subject".to_string()),
        now - 60,                                                // 1 minute ago
        now + 3600,                                              // 1 hour
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], // nonce
        vec!["enroll".to_string()],
    );

    let enrollment_token = EnrollmentToken::generate(&ea_key, token_body)
        .expect("Failed to generate enrollment token");

    serde_cbor::to_vec(&enrollment_token).expect("Failed to serialize enrollment token")
}

/// Create peer info in CBOR format for discovery
#[allow(dead_code)]
pub fn create_peer_info_cbor(public_key: Vec<u8>, addresses: Vec<String>) -> Vec<u8> {
    use runar_transporter::discovery::multicast_discovery::PeerInfo;
    use serde_cbor;

    let peer_info = PeerInfo::new(public_key, addresses);
    serde_cbor::to_vec(&peer_info).expect("Failed to serialize peer info")
}

/// Create discovery options in CBOR format
#[allow(dead_code)]
pub fn create_discovery_options_cbor(
    announce_interval_ms: u64,
    discovery_timeout_ms: u64,
    debounce_window_ms: u64,
    use_multicast: bool,
    local_network_only: bool,
    multicast_group: String,
) -> Vec<u8> {
    use runar_transporter::discovery::DiscoveryOptions;
    use serde_cbor;
    use std::time::Duration;

    let options = DiscoveryOptions {
        announce_interval: Duration::from_millis(announce_interval_ms),
        discovery_timeout: Duration::from_millis(discovery_timeout_ms),
        debounce_window: Duration::from_millis(debounce_window_ms),
        use_multicast,
        local_network_only,
        multicast_group,
    };

    serde_cbor::to_vec(&options).expect("Failed to serialize discovery options")
}

/// Get node public key from keys handle
///
/// # Safety
///
/// The `keys` parameter must be a valid, non-null pointer to a keys handle.
/// The caller is responsible for ensuring the pointer is valid and properly aligned.
#[allow(dead_code)]
pub unsafe fn get_node_public_key(keys: *mut c_void) -> Vec<u8> {
    let mut error = create_test_error();
    let mut public_key: *mut u8 = ptr::null_mut();
    let mut public_key_len: usize = 0;

    let result =
        rn_keys_node_get_public_key(keys, &mut public_key, &mut public_key_len, &mut error);
    assert_eq!(result, 0, "Failed to get node public key");

    let key_slice = std::slice::from_raw_parts(public_key, public_key_len);
    let key_vec = key_slice.to_vec();

    // Free the allocated memory
    if !public_key.is_null() {
        std::alloc::dealloc(
            public_key,
            std::alloc::Layout::from_size_align(public_key_len, 1).unwrap(),
        );
    }

    key_vec
}
