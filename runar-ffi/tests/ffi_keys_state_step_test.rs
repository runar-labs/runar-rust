#![cfg(test)]

#[cfg(all(feature = "linux-keystore", target_os = "linux"))]
use libc::c_char;
#[cfg(all(feature = "linux-keystore", target_os = "linux"))]
use runar_ffi::*;
#[cfg(all(feature = "linux-keystore", target_os = "linux"))]
use std::ffi::CString;

#[cfg(all(feature = "linux-keystore", target_os = "linux"))]
#[test]
fn linux_keystore_minimal_network_key_crash_repro() {
    unsafe {
        let mut err = runar_ffi::RnError {
            code: 0,
            message: std::ptr::null(),
        };

        // 1) rn_keys_new_return
        let keys = rn_keys_new_return(&mut err as *mut _);
        assert!(!keys.is_null(), "rn_keys_new_return failed: {}", last_err());

        // 2) rn_keys_register_linux_device_keystore with unique account
        let svc = CString::new("com.runar.keys.test").unwrap();
        let acc = CString::new(format!("state.aead.v1.{}", uuid::Uuid::new_v4())).unwrap();
        assert_eq!(
            rn_keys_register_linux_device_keystore(keys, svc.as_ptr(), acc.as_ptr(), &mut err),
            0,
            "register linux keystore failed: {}",
            last_err()
        );

        // 3) rn_keys_set_persistence_dir to a unique temp directory
        let tmp_dir =
            std::env::temp_dir().join(format!("runar_keys_test_{}", uuid::Uuid::new_v4()));
        let dir = CString::new(tmp_dir.to_string_lossy().to_string()).unwrap();
        assert_eq!(rn_keys_set_persistence_dir(keys, dir.as_ptr(), &mut err), 0);

        // 4) rn_keys_enable_auto_persist(true)
        assert_eq!(rn_keys_enable_auto_persist(keys, true, &mut err), 0);

        // 5) rn_keys_wipe_persistence
        assert_eq!(rn_keys_wipe_persistence(keys, &mut err), 0);

        // 6) rn_keys_mobile_initialize_user_root_key
        assert_eq!(rn_keys_mobile_initialize_user_root_key(keys, &mut err), 0);

        // 7) rn_keys_mobile_generate_network_data_key (crash repro point)
        let mut nid_ptr: *mut c_char = std::ptr::null_mut();
        let mut nid_len: usize = 0;
        let rc =
            rn_keys_mobile_generate_network_data_key(keys, &mut nid_ptr, &mut nid_len, &mut err);
        assert_eq!(rc, 0, "generate_network_data_key failed: {}", last_err());
        if !nid_ptr.is_null() {
            rn_string_free(nid_ptr);
        }

        rn_keys_free(keys);
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
