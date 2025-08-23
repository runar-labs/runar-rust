#![cfg(test)]

#[cfg(all(feature = "linux-keystore", target_os = "linux"))]
use libc::c_char;
#[cfg(all(feature = "linux-keystore", target_os = "linux"))]
use runar_ffi::*;
#[cfg(all(feature = "linux-keystore", target_os = "linux"))]
use serde::Deserialize;
#[cfg(all(feature = "linux-keystore", target_os = "linux"))]
use std::ffi::CString;

#[cfg(all(feature = "linux-keystore", target_os = "linux"))]
#[test]
fn linux_keystore_end_to_end_mobile_node_flow() {
    unsafe {
        let mut err = runar_ffi::RnError {
            code: 0,
            message: std::ptr::null(),
        };

        // Create keys handle
        let mut keys: *mut core::ffi::c_void = std::ptr::null_mut();
        assert_eq!(
            rn_keys_new(&mut keys, &mut err as *mut _),
            0,
            "rn_keys_new failed: {}",
            last_err()
        );

        // Register linux keystore with unique service/account
        let svc = CString::new("com.runar.keys.test").unwrap();
        let acc = CString::new(format!("state.aead.v1.{}", uuid::Uuid::new_v4())).unwrap();
        assert_eq!(
            rn_keys_register_linux_device_keystore(
                keys,
                svc.as_ptr(),
                acc.as_ptr(),
                &mut err as *mut _
            ),
            0,
            "register linux keystore failed: {}",
            last_err()
        );

        // Set persistence dir to a temp path
        let tmp_dir =
            std::env::temp_dir().join(format!("runar_keys_test_{}", uuid::Uuid::new_v4()));
        let dir = CString::new(tmp_dir.to_string_lossy().to_string()).unwrap();
        assert_eq!(
            rn_keys_set_persistence_dir(keys, dir.as_ptr(), &mut err as *mut _),
            0,
            "set_persistence_dir: {}",
            last_err()
        );

        // Enable auto persist
        assert_eq!(
            rn_keys_enable_auto_persist(keys, true, &mut err as *mut _),
            0,
            "enable_auto_persist: {}",
            last_err()
        );

        // Ensure clean start by wiping and recreating handle; then probe (should be 0)
        assert_eq!(
            rn_keys_wipe_persistence(keys, &mut err as *mut _),
            0,
            "wipe_persistence: {}",
            last_err()
        );
        rn_keys_free(keys);
        let mut keys: *mut core::ffi::c_void = std::ptr::null_mut();
        assert_eq!(rn_keys_new(&mut keys, &mut err as *mut _), 0);
        assert_eq!(
            rn_keys_register_linux_device_keystore(
                keys,
                svc.as_ptr(),
                acc.as_ptr(),
                &mut err as *mut _
            ),
            0
        );
        assert_eq!(
            rn_keys_set_persistence_dir(keys, dir.as_ptr(), &mut err as *mut _),
            0
        );
        assert_eq!(
            rn_keys_enable_auto_persist(keys, true, &mut err as *mut _),
            0
        );
        let mut state = 0i32;
        assert_eq!(
            rn_keys_mobile_get_keystore_state(keys, &mut state as *mut _, &mut err as *mut _),
            0
        );
        assert!(state == 0 || state == 1);

        // Initialize user root key
        assert_eq!(
            rn_keys_mobile_initialize_user_root_key(keys, &mut err as *mut _),
            0,
            "init root: {}",
            last_err()
        );

        // Generate node CSR and decode node_agreement_public_key from CBOR
        let mut st_ptr: *mut u8 = std::ptr::null_mut();
        let mut st_len: usize = 0;
        assert_eq!(
            rn_keys_node_generate_csr(
                keys,
                &mut st_ptr as *mut _,
                &mut st_len as *mut _,
                &mut err as *mut _
            ),
            0,
            "gen csr: {}",
            last_err()
        );
        let st_bytes = std::slice::from_raw_parts(st_ptr, st_len).to_vec();
        #[derive(Deserialize)]
        struct SetupTokenCbor {
            node_agreement_public_key: Vec<u8>,
        }
        let st_val: SetupTokenCbor =
            serde_cbor::from_slice(&st_bytes).expect("decode setup token cbor");
        rn_free(st_ptr, st_len);

        // Create a network and install on node
        let mut nid_c: *mut c_char = std::ptr::null_mut();
        let mut nid_len: usize = 0;
        assert_eq!(
            rn_keys_mobile_generate_network_data_key(
                keys,
                &mut nid_c as *mut _,
                &mut nid_len as *mut _,
                &mut err as *mut _
            ),
            0,
            "gen network key: {}",
            last_err()
        );
        let nid = cstr_to_string(nid_c, nid_len);
        rn_string_free(nid_c);
        let nid_cs = CString::new(nid.clone()).unwrap();

        let mut nkm_ptr: *mut u8 = std::ptr::null_mut();
        let mut nkm_len: usize = 0;
        assert_eq!(
            rn_keys_mobile_create_network_key_message(
                keys,
                nid_cs.as_ptr(),
                st_val.node_agreement_public_key.as_ptr(),
                st_val.node_agreement_public_key.len(),
                &mut nkm_ptr as *mut _,
                &mut nkm_len as *mut _,
                &mut err as *mut _
            ),
            0,
            "create NKM: {}",
            last_err()
        );
        assert_eq!(
            rn_keys_node_install_network_key(keys, nkm_ptr, nkm_len, &mut err as *mut _),
            0,
            "install NKM: {}",
            last_err()
        );
        rn_free(nkm_ptr, nkm_len);

        // Derive a profile key and exercise envelope encryption with network + profile
        let label = CString::new("default").unwrap();
        let mut ppk_ptr: *mut u8 = std::ptr::null_mut();
        let mut ppk_len: usize = 0;
        assert_eq!(
            rn_keys_mobile_derive_user_profile_key(
                keys,
                label.as_ptr(),
                &mut ppk_ptr as *mut _,
                &mut ppk_len as *mut _,
                &mut err as *mut _
            ),
            0,
            "derive profile: {}",
            last_err()
        );
        assert!(ppk_len > 0);

        // Envelope encrypt for network and profile recipient
        let data = b"hello world";
        let mut eed_ptr: *mut u8 = std::ptr::null_mut();
        let mut eed_len: usize = 0;
        let profile_pk_array: [*const u8; 1] = [ppk_ptr as *const u8];
        let profile_len_array: [usize; 1] = [ppk_len];
        assert_eq!(
            rn_keys_encrypt_with_envelope(
                keys,
                data.as_ptr(),
                data.len(),
                nid_cs.as_ptr(),
                profile_pk_array.as_ptr(),
                profile_len_array.as_ptr(),
                1,
                &mut eed_ptr as *mut _,
                &mut eed_len as *mut _,
                &mut err as *mut _
            ),
            0,
            "encrypt_with_envelope: {}",
            last_err()
        );
        rn_free(ppk_ptr, ppk_len);

        // Decrypt with envelope (node path through network key)
        let mut pt_ptr: *mut u8 = std::ptr::null_mut();
        let mut pt_len: usize = 0;
        assert_eq!(
            rn_keys_decrypt_envelope(
                keys,
                eed_ptr,
                eed_len,
                &mut pt_ptr as *mut _,
                &mut pt_len as *mut _,
                &mut err as *mut _
            ),
            0,
            "decrypt_envelope: {}",
            last_err()
        );
        let pt = std::slice::from_raw_parts(pt_ptr, pt_len).to_vec();
        assert_eq!(pt, data);
        rn_free(pt_ptr, pt_len);

        rn_free(eed_ptr, eed_len);

        // Flush and re-probe
        assert_eq!(
            rn_keys_flush_state(keys, &mut err as *mut _),
            0,
            "flush_state: {}",
            last_err()
        );

        // New handle, same dir/keystore
        rn_keys_free(keys);
        let mut keys2: *mut core::ffi::c_void = std::ptr::null_mut();
        assert_eq!(rn_keys_new(&mut keys2, &mut err as *mut _), 0);
        assert_eq!(
            rn_keys_register_linux_device_keystore(
                keys2,
                svc.as_ptr(),
                acc.as_ptr(),
                &mut err as *mut _
            ),
            0
        );
        assert_eq!(
            rn_keys_set_persistence_dir(keys2, dir.as_ptr(), &mut err as *mut _),
            0
        );
        let mut state2 = 0i32;
        assert_eq!(
            rn_keys_mobile_get_keystore_state(keys2, &mut state2 as *mut _, &mut err as *mut _),
            0
        );
        assert_eq!(state2, 1, "state should be restored");

        rn_keys_free(keys2);
    }
}

#[cfg(all(feature = "linux-keystore", target_os = "linux"))]
#[test]
fn test_ensure_symmetric_key() {
    unsafe {
        let mut err = runar_ffi::RnError {
            code: 0,
            message: std::ptr::null(),
        };

        // Create keys handle
        let mut keys: *mut core::ffi::c_void = std::ptr::null_mut();
        assert_eq!(
            rn_keys_new(&mut keys, &mut err as *mut _),
            0,
            "rn_keys_new failed: {}",
            last_err()
        );

        // Test ensure_symmetric_key for different services
        let key_name1 = CString::new("test_service_1").unwrap();
        let key_name2 = CString::new("test_service_2").unwrap();

        let mut key1_ptr: *mut u8 = std::ptr::null_mut();
        let mut key1_len: usize = 0;
        let mut key2_ptr: *mut u8 = std::ptr::null_mut();
        let mut key2_len: usize = 0;
        let mut key1_retrieved_ptr: *mut u8 = std::ptr::null_mut();
        let mut key1_retrieved_len: usize = 0;

        // Get first key
        assert_eq!(
            rn_keys_ensure_symmetric_key(
                keys,
                key_name1.as_ptr(),
                &mut key1_ptr as *mut _,
                &mut key1_len as *mut _,
                &mut err as *mut _
            ),
            0,
            "ensure_symmetric_key failed for service 1: {}",
            last_err()
        );

        // Get second key
        assert_eq!(
            rn_keys_ensure_symmetric_key(
                keys,
                key_name2.as_ptr(),
                &mut key2_ptr as *mut _,
                &mut key2_len as *mut _,
                &mut err as *mut _
            ),
            0,
            "ensure_symmetric_key failed for service 2: {}",
            last_err()
        );

        // Retrieve first key again
        assert_eq!(
            rn_keys_ensure_symmetric_key(
                keys,
                key_name1.as_ptr(),
                &mut key1_retrieved_ptr as *mut _,
                &mut key1_retrieved_len as *mut _,
                &mut err as *mut _
            ),
            0,
            "ensure_symmetric_key failed for service 1 retrieval: {}",
            last_err()
        );

        // Verify keys are valid
        assert!(!key1_ptr.is_null(), "key1_ptr should not be null");
        assert!(!key2_ptr.is_null(), "key2_ptr should not be null");
        assert!(
            !key1_retrieved_ptr.is_null(),
            "key1_retrieved_ptr should not be null"
        );
        assert_eq!(key1_len, 32, "key1 should be 32 bytes");
        assert_eq!(key2_len, 32, "key2 should be 32 bytes");
        assert_eq!(key1_retrieved_len, 32, "key1_retrieved should be 32 bytes");

        // Extract key data
        let key1 = std::slice::from_raw_parts(key1_ptr, key1_len).to_vec();
        let key2 = std::slice::from_raw_parts(key2_ptr, key2_len).to_vec();
        let key1_retrieved =
            std::slice::from_raw_parts(key1_retrieved_ptr, key1_retrieved_len).to_vec();

        // Keys should be different for different services
        assert_ne!(key1, key2, "different services should have different keys");
        // Same service should return the same key
        assert_eq!(
            key1, key1_retrieved,
            "same service should return the same key"
        );

        // Clean up
        rn_free(key1_ptr, key1_len);
        rn_free(key2_ptr, key2_len);
        rn_free(key1_retrieved_ptr, key1_retrieved_len);
        rn_keys_free(keys);
    }
}

#[cfg(all(feature = "linux-keystore", target_os = "linux"))]
fn cstr_to_string(ptr: *const c_char, len: usize) -> String {
    if ptr.is_null() || len == 0 {
        return String::new();
    }
    unsafe {
        let bytes = std::slice::from_raw_parts(ptr as *const u8, len);
        String::from_utf8_lossy(bytes).to_string()
    }
}

#[cfg(all(feature = "linux-keystore", target_os = "linux"))]
fn last_err() -> String {
    unsafe {
        let mut buf = vec![0u8; 256];
        let rc = rn_last_error(buf.as_mut_ptr() as *mut c_char, buf.len());
        if rc == 0 {
            let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            String::from_utf8_lossy(&buf[..nul]).to_string()
        } else {
            String::new()
        }
    }
}
