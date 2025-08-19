use runar_ffi::*;

#[repr(C)]
struct RnError {
    code: i32,
    message: *const std::os::raw::c_char,
}

#[test]
fn ffi_keys_local_crypto_and_state_roundtrip() {
    unsafe {
        let mut err = RnError {
            code: 0,
            message: std::ptr::null(),
        };

        // Create keys handle
        let mut keys: *mut std::ffi::c_void = std::ptr::null_mut();
        assert_eq!(rn_keys_new(&mut keys, &mut err as *mut _ as *mut _), 0);

        // Get node id and public key
        let mut node_id_c: *mut std::os::raw::c_char = std::ptr::null_mut();
        let mut node_id_len: usize = 0;
        assert_eq!(
            rn_keys_node_get_node_id(
                keys,
                &mut node_id_c,
                &mut node_id_len,
                &mut err as *mut _ as *mut _
            ),
            0
        );
        assert!(!node_id_c.is_null());
        rn_string_free(node_id_c);

        let mut pk_ptr: *mut u8 = std::ptr::null_mut();
        let mut pk_len: usize = 0;
        assert_eq!(
            rn_keys_node_get_public_key(
                keys,
                &mut pk_ptr,
                &mut pk_len,
                &mut err as *mut _ as *mut _
            ),
            0
        );
        assert!(!pk_ptr.is_null() && pk_len > 0);
        rn_free(pk_ptr, pk_len);

        // CSR -> Mobile issues certificate -> Node install
        let mut st_ptr: *mut u8 = std::ptr::null_mut();
        let mut st_len: usize = 0;
        assert_eq!(
            rn_keys_node_generate_csr(keys, &mut st_ptr, &mut st_len, &mut err as *mut _ as *mut _),
            0
        );
        let mut ncm_ptr: *mut u8 = std::ptr::null_mut();
        let mut ncm_len: usize = 0;
        assert_eq!(
            rn_keys_mobile_process_setup_token(
                keys,
                st_ptr,
                st_len,
                &mut ncm_ptr,
                &mut ncm_len,
                &mut err as *mut _ as *mut _
            ),
            0
        );
        rn_free(st_ptr, st_len);
        assert_eq!(
            rn_keys_node_install_certificate(keys, ncm_ptr, ncm_len, &mut err as *mut _ as *mut _),
            0
        );
        rn_free(ncm_ptr, ncm_len);

        // Local encryption/decryption
        let data = b"hello ffi";
        let mut enc_ptr: *mut u8 = std::ptr::null_mut();
        let mut enc_len: usize = 0;
        assert_eq!(
            rn_keys_encrypt_local_data(
                keys,
                data.as_ptr(),
                data.len(),
                &mut enc_ptr,
                &mut enc_len,
                &mut err as *mut _ as *mut _
            ),
            0
        );
        assert!(enc_len >= 12); // nonce + ciphertext
        let mut dec_ptr: *mut u8 = std::ptr::null_mut();
        let mut dec_len: usize = 0;
        assert_eq!(
            rn_keys_decrypt_local_data(
                keys,
                enc_ptr,
                enc_len,
                &mut dec_ptr,
                &mut dec_len,
                &mut err as *mut _ as *mut _
            ),
            0
        );
        rn_free(enc_ptr, enc_len);
        let dec = std::slice::from_raw_parts(dec_ptr, dec_len).to_vec();
        rn_free(dec_ptr, dec_len);
        assert_eq!(dec, data);

        // Export state
        let mut st_out_ptr: *mut u8 = std::ptr::null_mut();
        let mut st_out_len: usize = 0;
        assert_eq!(
            rn_keys_node_export_state(
                keys,
                &mut st_out_ptr,
                &mut st_out_len,
                &mut err as *mut _ as *mut _
            ),
            0
        );

        // Create a fresh handle and import state
        let mut keys2: *mut std::ffi::c_void = std::ptr::null_mut();
        assert_eq!(rn_keys_new(&mut keys2, &mut err as *mut _ as *mut _), 0);
        assert_eq!(
            rn_keys_node_import_state(keys2, st_out_ptr, st_out_len, &mut err as *mut _ as *mut _),
            0
        );
        rn_free(st_out_ptr, st_out_len);

        // Verify local encryption/decryption still works with imported state
        let data2 = b"post import";
        let mut enc2_ptr: *mut u8 = std::ptr::null_mut();
        let mut enc2_len: usize = 0;
        assert_eq!(
            rn_keys_encrypt_local_data(
                keys2,
                data2.as_ptr(),
                data2.len(),
                &mut enc2_ptr,
                &mut enc2_len,
                &mut err as *mut _ as *mut _
            ),
            0
        );
        let mut dec2_ptr: *mut u8 = std::ptr::null_mut();
        let mut dec2_len: usize = 0;
        assert_eq!(
            rn_keys_decrypt_local_data(
                keys2,
                enc2_ptr,
                enc2_len,
                &mut dec2_ptr,
                &mut dec2_len,
                &mut err as *mut _ as *mut _
            ),
            0
        );
        rn_free(enc2_ptr, enc2_len);
        let dec2 = std::slice::from_raw_parts(dec2_ptr, dec2_len).to_vec();
        rn_free(dec2_ptr, dec2_len);
        assert_eq!(dec2, data2);

        // Cleanup
        rn_keys_free(keys);
        rn_keys_free(keys2);
    }
}
