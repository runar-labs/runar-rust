use anyhow::Result;
use runar_common::logging::{Component, Logger};
use runar_keys::compact_ids;
use runar_keys::error::KeyError;
use runar_keys::{keystore::KeyStore, MobileKeyManager, NodeKeyManager};
use std::sync::Arc;

#[test]
fn keystore_profile_encryption_roundtrip_mobile() -> Result<()> {
    let logger = Arc::new(Logger::new_root(Component::System, "keystore-test"));
    let mut mobile = MobileKeyManager::new(logger.clone())?;

    // Prepare keys
    mobile.initialize_user_root_key()?;
    let profile_pk = mobile.derive_user_profile_key("personal")?;
    let network_id = mobile.generate_network_data_key()?;

    // Encrypt using trait object (profile recipient)
    let ks: &dyn KeyStore = &mobile;
    let plaintext = b"secret-profile-data";
    let envelope = ks.encrypt_with_envelope(plaintext, &profile_pk)?;

    // Decrypt using the same keystore
    let decrypted = ks.decrypt_envelope_data(&envelope)?;
    assert_eq!(decrypted.as_slice(), plaintext);

    // Verify can_decrypt_for_key works
    assert!(ks.can_decrypt_for_key(&profile_pk));

    // Ensure network encryption also decrypts
    let network_pub = compact_ids::public_key_from_compact_id(&network_id)?;
    let envelope_net = ks.encrypt_with_envelope(plaintext, &network_pub)?;
    let dec_net = ks.decrypt_envelope_data(&envelope_net)?;
    assert_eq!(dec_net.as_slice(), plaintext);

    Ok(())
}

#[test]
fn keystore_cross_device_network_encryption() -> Result<()> {
    let logger = Arc::new(Logger::new_root(Component::System, "keystore-test"));
    // Mobile side
    let mut mobile = MobileKeyManager::new(logger.clone())?;
    mobile.initialize_user_root_key()?;
    let network_id = mobile.generate_network_data_key()?;

    // Node side
    let mut node = NodeKeyManager::new(logger.clone())?;
    // Provide node public key to mobile and install network key on node
    let nk_msg = mobile.create_network_key_message(&network_id, &node.get_node_public_key())?;
    node.install_network_key(nk_msg)?;

    // Encrypt on mobile for node's network key
    let mobile_ks: &dyn KeyStore = &mobile;
    let node_ks: &dyn KeyStore = &node;

    let plaintext = b"hello-network";
    let network_pub = compact_ids::public_key_from_compact_id(&network_id)?;
    let envelope = mobile_ks.encrypt_with_envelope(plaintext, &network_pub)?;

    // Decrypt on node
    let decrypted = node_ks.decrypt_envelope_data(&envelope)?;
    assert_eq!(decrypted.as_slice(), plaintext);

    Ok(())
}

#[test]
fn node_encrypt_with_profile_ids_should_error() -> Result<()> {
    let logger = Arc::new(Logger::new_root(Component::System, "keystore-test"));
    let node = NodeKeyManager::new(logger)?;
    let data = b"irrelevant";
    let err = node
        .encrypt_with_envelope(data, "some-network", vec!["profile1".to_string()])
        .expect_err("expected error when profile_ids non-empty");
    match err {
        KeyError::InvalidOperation(msg) => {
            assert!(msg.contains("profile"));
        }
        _ => panic!("unexpected error variant"),
    }
    Ok(())
}
