use runar_keys::*;

#[test]
fn test_key_generation_and_derivation() {
    let master = UserMasterKey::generate();
    let profile = derive_profile_key(&master, 0).unwrap();
    assert_eq!(profile.peer_id().0.len(), ed25519_dalek::PUBLIC_KEY_LENGTH);

    let net_key = derive_network_key(&master, 1).unwrap();
    assert_eq!(
        net_key.id().as_bytes().len(),
        ed25519_dalek::PUBLIC_KEY_LENGTH
    );
    //test signature iwth network key also
    let msg = b"hello";
    let sig = net_key.sign(msg);
    net_key.verify(msg, &sig).unwrap();

    let node_key = derive_node_key(&master, 2).unwrap();
    let msg = b"hello";
    let sig = node_key.sign(msg);
    node_key.verify(msg, &sig).unwrap();
}

#[test]
fn test_encryption_roundtrip() {
    let master = UserMasterKey::generate();
    let node_key = derive_node_key(&master, 0).unwrap();
    let sym = derive_symmetric_key_from_node(&node_key, b"ctx").unwrap();
    let data = b"secret data";
    let (cipher, nonce) = encrypt(&sym, data, None).unwrap();
    let plain = decrypt(&sym, &cipher, &nonce, None).unwrap();
    assert_eq!(plain, data);
}

#[test]
fn test_shared_key() {
    let master = UserMasterKey::generate();
    let profile = derive_profile_key(&master, 0).unwrap();
    let node_key = derive_node_key(&master, 1).unwrap();
    let shared = derive_node_shared_key(&profile, &node_key, 60).unwrap();
    assert!(!shared.is_expired());
}

#[test]
fn test_access_token_lifecycle() {
    let master = UserMasterKey::generate();
    let net_key = derive_network_key(&master, 0).unwrap();
    let profile = derive_profile_key(&master, 0).unwrap();

    let token = AccessToken::new(
        profile.peer_id().clone(),
        net_key.id().clone(),
        Some(current_unix_timestamp() + 60),
        Some(vec![Capability::Read]),
        &net_key.keypair,
    );
    assert!(token.verify().unwrap());
}
