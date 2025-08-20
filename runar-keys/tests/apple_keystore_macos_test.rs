#![cfg(all(feature = "apple-keystore", target_os = "macos"))]

use runar_keys::keystore::persistence::{load_state, save_state, PersistenceConfig, Role};
use runar_keys::keystore::{self, DeviceKeystore};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn with_timeout<F: FnOnce() + Send + 'static>(dur: Duration, f: F) {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        f();
        let _ = tx.send(());
    });
    match rx.recv_timeout(dur) {
        Ok(()) => (),
        Err(_) => panic!("test timed out after {dur:?}"),
    }
}

#[test]
fn test_encrypt_decrypt_roundtrip_macos() {
    with_timeout(Duration::from_secs(20), || {
        std::env::set_var("RUNAR_APPLE_KEYSTORE_SOFTWARE_ONLY", "1");
        let label = "com.runar.keys.test.apple";
        let ks = keystore::apple::AppleDeviceKeystore::new(label).expect("create ks");
        let plaintext = b"hello apple keystore";
        let aad = b"runar:keys_state:v1|role=mobile";
        let ct = ks.encrypt(plaintext, aad).expect("encrypt");
        let pt = ks.decrypt(&ct, aad).expect("decrypt");
        assert_eq!(pt, plaintext);
        // cleanup
        let _ =
            security_framework::passwords::delete_generic_password(label, "state.aead.v1.software");
        let _ =
            security_framework::passwords::delete_generic_password(label, "state.aead.v1.wrapped");
    });
}

#[test]
fn test_persistence_roundtrip_macos() {
    with_timeout(Duration::from_secs(20), || {
        std::env::set_var("RUNAR_APPLE_KEYSTORE_SOFTWARE_ONLY", "1");
        let label = "com.runar.keys.test.apple.persist";
        let ks = Arc::new(keystore::apple::AppleDeviceKeystore::new(label).expect("create ks"))
            as Arc<dyn DeviceKeystore>;
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let cfg = PersistenceConfig::new(tmpdir.path().to_path_buf());
        let role = Role::Mobile;
        let state = b"some persistent state".to_vec();
        save_state(&ks, &cfg, &role, &state).expect("save");
        let loaded = load_state(&ks, &cfg, &role).expect("load").expect("some");
        assert_eq!(loaded, state);
        // cleanup
        let _ =
            security_framework::passwords::delete_generic_password(label, "state.aead.v1.software");
        let _ =
            security_framework::passwords::delete_generic_password(label, "state.aead.v1.wrapped");
    });
}
