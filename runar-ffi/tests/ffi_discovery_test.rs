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
        rn_keys_node_generate_csr(keys_a, &mut csr_a, &mut csr_len_a, &mut error),
        0
    );
    assert_eq!(
        rn_keys_node_generate_csr(keys_b, &mut csr_b, &mut csr_len_b, &mut error),
        0
    );

    // Create discovery options with short TTL for testing
    let discovery_options = create_discovery_options_cbor(
        50,                              // announce_interval_ms
        1000,                            // discovery_timeout_ms
        100,                             // debounce_window_ms
        true,                            // use_multicast
        true,                            // local_network_only
        "239.255.0.1:45678".to_string(), // multicast_group
    );

    // Get public keys for both nodes
    let public_key_a = unsafe { get_node_public_key(keys_a) };
    let public_key_b = unsafe { get_node_public_key(keys_b) };

    // Create peer info for both nodes
    let peer_info_a = create_peer_info_cbor(public_key_a, vec!["127.0.0.1:8080".to_string()]);
    let peer_info_b = create_peer_info_cbor(public_key_b, vec!["127.0.0.1:8081".to_string()]);

    // Create discovery instances for both nodes
    let mut discovery_a: *mut c_void = ptr::null_mut();
    let mut discovery_b: *mut c_void = ptr::null_mut();

    assert_eq!(
        unsafe {
            rn_discovery_new_with_multicast(
                peer_info_a.as_ptr(),
                peer_info_a.len(),
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
                peer_info_b.as_ptr(),
                peer_info_b.len(),
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

/// Test discovery event polling through FFI with new architecture
#[test]
fn test_ffi_discovery_event_polling() {
    println!("🔍 Starting FFI Discovery Event Polling Test");

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
        rn_keys_node_generate_csr(keys_a, &mut csr_a, &mut csr_len_a, &mut error),
        0
    );
    assert_eq!(
        rn_keys_node_generate_csr(keys_b, &mut csr_b, &mut csr_len_b, &mut error),
        0
    );

    // Create discovery options with short intervals for testing
    let discovery_options = create_discovery_options_cbor(
        50,                              // announce_interval_ms
        1000,                            // discovery_timeout_ms
        100,                             // debounce_window_ms
        true,                            // use_multicast
        true,                            // local_network_only
        "239.255.0.2:45679".to_string(), // multicast_group
    );

    // Get public keys for both nodes
    let public_key_a = unsafe { get_node_public_key(keys_a) };
    let public_key_b = unsafe { get_node_public_key(keys_b) };

    // Create peer info for both nodes
    let peer_info_a = create_peer_info_cbor(public_key_a, vec!["127.0.0.1:8080".to_string()]);
    let peer_info_b = create_peer_info_cbor(public_key_b, vec!["127.0.0.1:8081".to_string()]);

    // Create discovery instances
    let mut discovery_a: *mut c_void = ptr::null_mut();
    let mut discovery_b: *mut c_void = ptr::null_mut();

    assert_eq!(
        unsafe {
            rn_discovery_new_with_multicast(
                peer_info_a.as_ptr(),
                peer_info_a.len(),
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
                peer_info_b.as_ptr(),
                peer_info_b.len(),
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

    // Bind discovery events to their own channels
    assert_eq!(
        unsafe { rn_discovery_bind_events(discovery_a, &mut error) },
        0
    );
    assert_eq!(
        unsafe { rn_discovery_bind_events(discovery_b, &mut error) },
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

    // Test discovery event polling on node B (should discover node A)
    let mut discovered_events = 0;
    let mut updated_events = 0;
    let mut lost_events = 0;

    // Poll for discovered events
    for _ in 0..10 {
        let mut ev_ptr: *mut u8 = ptr::null_mut();
        let mut ev_len: usize = 0;
        let rc = unsafe {
            rn_discovery_poll_discovered(discovery_b, &mut ev_ptr, &mut ev_len, &mut error)
        };
        assert_eq!(rc, 0);
        if !ev_ptr.is_null() && ev_len > 0 {
            // Deserialize the PeerInfo
            let peer_data = unsafe { std::slice::from_raw_parts(ev_ptr, ev_len) };
            let peer: runar_transporter::discovery::PeerInfo =
                serde_cbor::from_slice(peer_data).unwrap();
            println!("Discovered peer: {peer:?}");
            discovered_events += 1;
            rn_free(ev_ptr, ev_len);
        }

        // Poll for updated events
        let mut ev_ptr: *mut u8 = ptr::null_mut();
        let mut ev_len: usize = 0;
        let rc =
            unsafe { rn_discovery_poll_updated(discovery_b, &mut ev_ptr, &mut ev_len, &mut error) };
        assert_eq!(rc, 0);
        if !ev_ptr.is_null() && ev_len > 0 {
            let peer_data = unsafe { std::slice::from_raw_parts(ev_ptr, ev_len) };
            let peer: runar_transporter::discovery::PeerInfo =
                serde_cbor::from_slice(peer_data).unwrap();
            println!("Updated peer: {peer:?}");
            updated_events += 1;
            rn_free(ev_ptr, ev_len);
        }

        // Poll for lost events
        let mut ev_ptr: *mut u8 = ptr::null_mut();
        let mut ev_len: usize = 0;
        let rc =
            unsafe { rn_discovery_poll_lost(discovery_b, &mut ev_ptr, &mut ev_len, &mut error) };
        assert_eq!(rc, 0);
        if !ev_ptr.is_null() && ev_len > 0 {
            let node_id_data = unsafe { std::slice::from_raw_parts(ev_ptr, ev_len) };
            let node_id: String = serde_cbor::from_slice(node_id_data).unwrap();
            println!("Lost peer: {node_id}");
            lost_events += 1;
            rn_free(ev_ptr, ev_len);
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    // Stop announcing on node A to simulate TTL loss
    assert_eq!(
        unsafe { rn_discovery_stop_announcing(discovery_a, &mut error) },
        0
    );

    // Wait for TTL to expire
    std::thread::sleep(Duration::from_millis(2000));

    // Poll for lost events after TTL
    for _ in 0..5 {
        let mut ev_ptr: *mut u8 = ptr::null_mut();
        let mut ev_len: usize = 0;
        let rc =
            unsafe { rn_discovery_poll_lost(discovery_b, &mut ev_ptr, &mut ev_len, &mut error) };
        assert_eq!(rc, 0);
        if !ev_ptr.is_null() && ev_len > 0 {
            let node_id_data = unsafe { std::slice::from_raw_parts(ev_ptr, ev_len) };
            let node_id: String = serde_cbor::from_slice(node_id_data).unwrap();
            println!("Lost peer after TTL: {node_id}");
            lost_events += 1;
            rn_free(ev_ptr, ev_len);
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    println!(
        "Discovery events - Discovered: {discovered_events}, Updated: {updated_events}, Lost: {lost_events}"
    );

    // We should have seen at least one discovered event
    assert!(
        discovered_events > 0,
        "Should have discovered at least one peer"
    );

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

    println!("✅ FFI Discovery Event Polling Test completed");
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
        rn_keys_node_generate_csr(keys_a, &mut csr_a, &mut csr_len_a, &mut error),
        0
    );
    assert_eq!(
        rn_keys_node_generate_csr(keys_b, &mut csr_b, &mut csr_len_b, &mut error),
        0
    );

    // Create discovery options
    let discovery_options = create_discovery_options_cbor(
        100,                             // announce_interval_ms
        2000,                            // discovery_timeout_ms
        200,                             // debounce_window_ms
        true,                            // use_multicast
        true,                            // local_network_only
        "239.255.0.1:45679".to_string(), // multicast_group
    );

    // Get public keys for both nodes
    let public_key_a = unsafe { get_node_public_key(keys_a) };
    let public_key_b = unsafe { get_node_public_key(keys_b) };

    // Create peer info for both nodes
    let peer_info_a = create_peer_info_cbor(public_key_a, vec!["127.0.0.1:8080".to_string()]);
    let peer_info_b = create_peer_info_cbor(public_key_b, vec!["127.0.0.1:8081".to_string()]);

    // Create discovery instances for both nodes
    let mut discovery_a: *mut c_void = ptr::null_mut();
    let mut discovery_b: *mut c_void = ptr::null_mut();

    assert_eq!(
        unsafe {
            rn_discovery_new_with_multicast(
                peer_info_a.as_ptr(),
                peer_info_a.len(),
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
                peer_info_b.as_ptr(),
                peer_info_b.len(),
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
        rn_keys_node_generate_csr(keys, &mut csr, &mut csr_len, &mut error),
        0
    );

    // Create discovery options
    let discovery_options = create_discovery_options_cbor(
        100,                             // announce_interval_ms
        2000,                            // discovery_timeout_ms
        200,                             // debounce_window_ms
        true,                            // use_multicast
        true,                            // local_network_only
        "239.255.0.1:45680".to_string(), // multicast_group
    );

    // Get public key for the node
    let public_key = unsafe { get_node_public_key(keys) };

    // Create peer info for the node
    let peer_info = create_peer_info_cbor(public_key, vec!["127.0.0.1:8080".to_string()]);

    // Create discovery instance
    let mut discovery: *mut c_void = ptr::null_mut();

    assert_eq!(
        unsafe {
            rn_discovery_new_with_multicast(
                peer_info.as_ptr(),
                peer_info.len(),
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
        rn_keys_node_generate_csr(keys, &mut csr, &mut csr_len, &mut error),
        0
    );

    // Get public key for the node
    let public_key = unsafe { get_node_public_key(keys) };

    // Create peer info for the node
    let peer_info = create_peer_info_cbor(public_key, vec!["127.0.0.1:8080".to_string()]);

    // Create discovery instance
    let mut discovery: *mut c_void = ptr::null_mut();

    // Test with invalid CBOR data for options
    let invalid_cbor = b"invalid cbor data";
    let result = unsafe {
        rn_discovery_new_with_multicast(
            peer_info.as_ptr(),
            peer_info.len(),
            invalid_cbor.as_ptr(),
            invalid_cbor.len(),
            &mut discovery,
            &mut error,
        )
    };

    // Should fail with invalid CBOR options
    assert_ne!(result, 0);
    assert!(discovery.is_null());

    // Cleanup
    if !discovery.is_null() {
        rn_discovery_free(discovery);
    }
    rn_keys_free(keys);
    if !csr.is_null() {
        rn_free(csr, csr_len);
    }

    println!("✅ FFI Discovery Invalid CBOR Handling Test completed");
}
