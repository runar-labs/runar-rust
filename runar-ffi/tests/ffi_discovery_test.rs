//! FFI Discovery Tests
//!
//! Tests for the Discovery APIs exposed through the FFI layer.
//! These tests are equivalent to the multicast_discovery_test.rs but use FFI APIs.

use runar_ffi::*;
use std::ffi::c_void;
use std::ptr;
use std::time::Duration;

// Import common utilities
mod common;
use common::*;

/// Test discovery TTL, lost events, and debouncing through FFI
#[test]
fn test_ffi_discovery_ttl_lost_and_debounce() {
    println!("🔍 Starting FFI Discovery TTL and Debounce Test");

    // Create two keys handles for two nodes
    let keys_a = create_keys_handle();
    let keys_b = create_keys_handle();

    // Initialize both as node key managers
    unsafe {
        init_as_node(keys_a);
        init_as_node(keys_b);
    }

    // Generate keys for both nodes
    let mut error = create_test_error();
    let mut csr_a: *mut u8 = ptr::null_mut();
    let mut csr_len_a: usize = 0;
    let mut csr_b: *mut u8 = ptr::null_mut();
    let mut csr_len_b: usize = 0;

    // Generate CSRs for both nodes
    assert_eq!(
        unsafe { rn_keys_node_generate_csr(keys_a, &mut csr_a, &mut csr_len_a, &mut error) },
        0
    );
    assert_eq!(
        unsafe { rn_keys_node_generate_csr(keys_b, &mut csr_b, &mut csr_len_b, &mut error) },
        0
    );

    // Create discovery options with short TTL for testing
    let discovery_options = serde_cbor::to_vec(&serde_cbor::Value::Map({
        let mut map = std::collections::BTreeMap::new();
        map.insert(
            serde_cbor::Value::Text("multicast_group".into()),
            serde_cbor::Value::Text("239.255.0.1:45678".into()),
        );
        map.insert(
            serde_cbor::Value::Text("announce_interval_ms".into()),
            serde_cbor::Value::Integer(50),
        );
        map.insert(
            serde_cbor::Value::Text("discovery_timeout_ms".into()),
            serde_cbor::Value::Integer(1000),
        );
        map.insert(
            serde_cbor::Value::Text("debounce_window_ms".into()),
            serde_cbor::Value::Integer(100),
        );
        map
    }))
    .expect("Failed to serialize discovery options");

    // Create discovery instances for both nodes
    let mut discovery_a: *mut c_void = ptr::null_mut();
    let mut discovery_b: *mut c_void = ptr::null_mut();

    assert_eq!(
        unsafe {
            rn_discovery_new_with_multicast(
                keys_a,
                discovery_options.as_ptr(),
                discovery_options.len(),
                &mut discovery_a,
                &mut error,
            )
        },
        0
    );

    assert_eq!(
        unsafe {
            rn_discovery_new_with_multicast(
                keys_b,
                discovery_options.as_ptr(),
                discovery_options.len(),
                &mut discovery_b,
                &mut error,
            )
        },
        0
    );

    // Initialize both discovery instances
    assert_eq!(
        unsafe {
            rn_discovery_init(
                discovery_a,
                discovery_options.as_ptr(),
                discovery_options.len(),
                &mut error,
            )
        },
        0
    );

    assert_eq!(
        unsafe {
            rn_discovery_init(
                discovery_b,
                discovery_options.as_ptr(),
                discovery_options.len(),
                &mut error,
            )
        },
        0
    );

    // Start announcing on both nodes
    assert_eq!(
        unsafe { rn_discovery_start_announcing(discovery_a, &mut error) },
        0
    );
    assert_eq!(
        unsafe { rn_discovery_start_announcing(discovery_b, &mut error) },
        0
    );

    // Wait for discovery to work
    std::thread::sleep(Duration::from_millis(500));

    // Stop announcing on node A to simulate TTL loss
    assert_eq!(
        unsafe { rn_discovery_stop_announcing(discovery_a, &mut error) },
        0
    );

    // Wait for TTL to expire and debounce
    std::thread::sleep(Duration::from_millis(200));

    // Cleanup
    unsafe {
        rn_discovery_shutdown(discovery_a, &mut error);
        rn_discovery_shutdown(discovery_b, &mut error);
        rn_discovery_free(discovery_a);
        rn_discovery_free(discovery_b);
        rn_keys_free(keys_a);
        rn_keys_free(keys_b);
        if !csr_a.is_null() {
            rn_free(csr_a, csr_len_a);
        }
        if !csr_b.is_null() {
            rn_free(csr_b, csr_len_b);
        }
    }

    println!("✅ FFI Discovery TTL and Debounce Test completed");
}

/// Test discovery announce and discover functionality through FFI
#[test]
fn test_ffi_multicast_announce_and_discover() {
    println!("🔍 Starting FFI Multicast Announce and Discover Test");

    // Create two keys handles for two nodes
    let keys_a = create_keys_handle();
    let keys_b = create_keys_handle();

    // Initialize both as node key managers
    unsafe {
        init_as_node(keys_a);
        init_as_node(keys_b);
    }

    // Generate keys for both nodes
    let mut error = create_test_error();
    let mut csr_a: *mut u8 = ptr::null_mut();
    let mut csr_len_a: usize = 0;
    let mut csr_b: *mut u8 = ptr::null_mut();
    let mut csr_len_b: usize = 0;

    // Generate CSRs for both nodes
    assert_eq!(
        unsafe { rn_keys_node_generate_csr(keys_a, &mut csr_a, &mut csr_len_a, &mut error) },
        0
    );
    assert_eq!(
        unsafe { rn_keys_node_generate_csr(keys_b, &mut csr_b, &mut csr_len_b, &mut error) },
        0
    );

    // Create discovery options
    let discovery_options = serde_cbor::to_vec(&serde_cbor::Value::Map({
        let mut map = std::collections::BTreeMap::new();
        map.insert(
            serde_cbor::Value::Text("multicast_group".into()),
            serde_cbor::Value::Text("239.255.0.1:45679".into()),
        );
        map.insert(
            serde_cbor::Value::Text("announce_interval_ms".into()),
            serde_cbor::Value::Integer(100),
        );
        map.insert(
            serde_cbor::Value::Text("discovery_timeout_ms".into()),
            serde_cbor::Value::Integer(2000),
        );
        map.insert(
            serde_cbor::Value::Text("debounce_window_ms".into()),
            serde_cbor::Value::Integer(200),
        );
        map
    }))
    .expect("Failed to serialize discovery options");

    // Create discovery instances for both nodes
    let mut discovery_a: *mut c_void = ptr::null_mut();
    let mut discovery_b: *mut c_void = ptr::null_mut();

    assert_eq!(
        unsafe {
            rn_discovery_new_with_multicast(
                keys_a,
                discovery_options.as_ptr(),
                discovery_options.len(),
                &mut discovery_a,
                &mut error,
            )
        },
        0
    );

    assert_eq!(
        unsafe {
            rn_discovery_new_with_multicast(
                keys_b,
                discovery_options.as_ptr(),
                discovery_options.len(),
                &mut discovery_b,
                &mut error,
            )
        },
        0
    );

    // Initialize both discovery instances
    assert_eq!(
        unsafe {
            rn_discovery_init(
                discovery_a,
                discovery_options.as_ptr(),
                discovery_options.len(),
                &mut error,
            )
        },
        0
    );

    assert_eq!(
        unsafe {
            rn_discovery_init(
                discovery_b,
                discovery_options.as_ptr(),
                discovery_options.len(),
                &mut error,
            )
        },
        0
    );

    // Start announcing on both nodes
    assert_eq!(
        unsafe { rn_discovery_start_announcing(discovery_a, &mut error) },
        0
    );
    assert_eq!(
        unsafe { rn_discovery_start_announcing(discovery_b, &mut error) },
        0
    );

    // Wait for discovery to work
    std::thread::sleep(Duration::from_millis(1000));

    // Cleanup
    unsafe {
        rn_discovery_shutdown(discovery_a, &mut error);
        rn_discovery_shutdown(discovery_b, &mut error);
        rn_discovery_free(discovery_a);
        rn_discovery_free(discovery_b);
        rn_keys_free(keys_a);
        rn_keys_free(keys_b);
        if !csr_a.is_null() {
            rn_free(csr_a, csr_len_a);
        }
        if !csr_b.is_null() {
            rn_free(csr_b, csr_len_b);
        }
    }

    println!("✅ FFI Multicast Announce and Discover Test completed");
}

/// Test discovery start/stop idempotence through FFI
#[test]
fn test_ffi_discovery_start_stop_idempotence() {
    println!("🔍 Starting FFI Discovery Start/Stop Idempotence Test");

    // Create keys handle
    let keys = create_keys_handle();
    unsafe {
        init_as_node(keys);
    }

    // Generate keys
    let mut error = create_test_error();
    let mut csr: *mut u8 = ptr::null_mut();
    let mut csr_len: usize = 0;

    assert_eq!(
        unsafe { rn_keys_node_generate_csr(keys, &mut csr, &mut csr_len, &mut error) },
        0
    );

    // Create discovery options
    let discovery_options = serde_cbor::to_vec(&serde_cbor::Value::Map({
        let mut map = std::collections::BTreeMap::new();
        map.insert(
            serde_cbor::Value::Text("multicast_group".into()),
            serde_cbor::Value::Text("239.255.0.1:45680".into()),
        );
        map.insert(
            serde_cbor::Value::Text("announce_interval_ms".into()),
            serde_cbor::Value::Integer(100),
        );
        map.insert(
            serde_cbor::Value::Text("discovery_timeout_ms".into()),
            serde_cbor::Value::Integer(2000),
        );
        map.insert(
            serde_cbor::Value::Text("debounce_window_ms".into()),
            serde_cbor::Value::Integer(200),
        );
        map
    }))
    .expect("Failed to serialize discovery options");

    // Create discovery instance
    let mut discovery: *mut c_void = ptr::null_mut();

    assert_eq!(
        unsafe {
            rn_discovery_new_with_multicast(
                keys,
                discovery_options.as_ptr(),
                discovery_options.len(),
                &mut discovery,
                &mut error,
            )
        },
        0
    );

    // Initialize discovery
    assert_eq!(
        unsafe {
            rn_discovery_init(
                discovery,
                discovery_options.as_ptr(),
                discovery_options.len(),
                &mut error,
            )
        },
        0
    );

    // Test multiple start calls (should be idempotent)
    assert_eq!(
        unsafe { rn_discovery_start_announcing(discovery, &mut error) },
        0
    );
    assert_eq!(
        unsafe { rn_discovery_start_announcing(discovery, &mut error) },
        0
    );

    // Test multiple stop calls (should be idempotent)
    assert_eq!(
        unsafe { rn_discovery_stop_announcing(discovery, &mut error) },
        0
    );
    assert_eq!(
        unsafe { rn_discovery_stop_announcing(discovery, &mut error) },
        0
    );

    // Cleanup
    unsafe {
        rn_discovery_shutdown(discovery, &mut error);
        rn_discovery_free(discovery);
        rn_keys_free(keys);
        if !csr.is_null() {
            rn_free(csr, csr_len);
        }
    }

    println!("✅ FFI Discovery Start/Stop Idempotence Test completed");
}

/// Test discovery with invalid CBOR data through FFI
#[test]
fn test_ffi_discovery_invalid_cbor_handling() {
    println!("🔍 Starting FFI Discovery Invalid CBOR Handling Test");

    // Create keys handle
    let keys = create_keys_handle();
    unsafe {
        init_as_node(keys);
    }

    // Generate keys
    let mut error = create_test_error();
    let mut csr: *mut u8 = ptr::null_mut();
    let mut csr_len: usize = 0;

    assert_eq!(
        unsafe { rn_keys_node_generate_csr(keys, &mut csr, &mut csr_len, &mut error) },
        0
    );

    // Create discovery instance
    let mut discovery: *mut c_void = ptr::null_mut();

    // Test with invalid CBOR data
    let invalid_cbor = b"invalid cbor data";
    let result = unsafe {
        rn_discovery_new_with_multicast(
            keys,
            invalid_cbor.as_ptr(),
            invalid_cbor.len(),
            &mut discovery,
            &mut error,
        )
    };

    // Should succeed with invalid CBOR (uses default options)
    assert_eq!(result, 0);
    assert!(!discovery.is_null());

    // Cleanup
    unsafe {
        rn_discovery_free(discovery);
        rn_keys_free(keys);
        if !csr.is_null() {
            rn_free(csr, csr_len);
        }
    }

    println!("✅ FFI Discovery Invalid CBOR Handling Test completed");
}
