use ed25519_dalek::VerifyingKey;
use runar_keys::crypto::PublicKey;
use runar_keys::*;
use std::convert::TryInto;

#[test]
fn test_key_generation_and_derivation() {
    // This goal of this test is to simulate the end to end encryption and keys management flows.
    // in the real implemetnation the mobile process  and the node
    // process will be in different machines and talkig over the network,
    // but here we want to simulate the end to ened and  test the whole flow.
    // so  we willl bypass the network part and deal with the internal compionents

    // mobile side - first time use - generate user keys

    // 1 - (mobile side) - generate user master key
    let mut mobile = MobileKeyManager::new();
    mobile.generate_seed();

    // Generate user root key - now returns only the public key
    let user_root_public_key = mobile
        .generate_user_root_key()
        .expect("Failed to generate user root key");
    assert!(
        user_root_public_key.bytes().len() == 32,
        "User root key should have a valid public key"
    );

    let user_public_key = user_root_public_key.bytes().to_vec();
    println!("User public key: {}", hex::encode(&user_public_key));

    // Create a user owned and managed CA - now returns only the public key
    let user_ca_public_key = mobile
        .generate_user_ca_key()
        .expect("Failed to generate user CA key");
    assert_eq!(user_ca_public_key.bytes().len(), 32);
    println!(
        "User CA public key: {}",
        hex::encode(user_ca_public_key.bytes())
    );

    //Node first time use - enter in setup mode

    // 2 - node side (setup mode) - generate its own TLS and Storage keypairs
    //     and generate a setup handshake token which contains the CSR request and the node public key
    //     which will be presented as QR code.. here in the test we use the token as a string dfirectly.
    let mut node = NodeKeyManager::new();
    let setup_token = node
        .generate_setup_token()
        .expect("Failed to generate setup token");

    // Mobile scans a Node QR code which contains the setup token

    // 3 - (mobile side) - received the token and sign the CSR
    let cert = mobile
        .process_setup_token(&setup_token)
        .expect("Failed to process setup token");
    println!("Certificate: {} -> {}", cert.subject, cert.issuer);
    assert_eq!(
        cert.issuer,
        format!("ca:{}", hex::encode(user_ca_public_key.bytes())),
        "Certificate should be issued by the network CA"
    );

    // Extract the node ID from the setup token
    // In a real-world scenario, the mobile device would have received this in the setup token
    let node_id = hex::encode(&setup_token.node_public_key);
    
    // Mobile encrypts the certificate for secure transmission to the node
    // This ensures only the target node can decrypt the certificate
    let encrypted_cert = mobile
        .encrypt_certificate_for_node(&cert, &node_id)
        .expect("Failed to encrypt certificate");
    println!("Certificate encrypted successfully for secure transmission");
    
    // In a real-world scenario, the encrypted envelope would be transmitted over a network
    // Here we're simulating that by directly passing the envelope to the node
    
    // 4 - (node side) - received the encrypted certificate, decrypts it, validates it, and stores it
    node.process_encrypted_certificate(&encrypted_cert)
        .expect("Failed to process encrypted certificate");

    // 5. Mobile receives the node certificate, validates it, and stores it
    let node_certificate_from_node = node
        .get_node_certificate()
        .expect("Failed to get node certificate");

    // *** ADDED: Validate the certificate against the CA public key ***
    let ca_key = mobile.key_manager().get_signing_key("user_ca_key").unwrap();
    let ca_verifying_key =
        VerifyingKey::from_bytes(ca_key.public_key().try_into().unwrap()).unwrap();
    assert!(node_certificate_from_node
        .validate(&ca_verifying_key)
        .is_ok());

    mobile
        .key_manager_mut()
        .add_certificate(node_certificate_from_node.clone(), "user_ca_key")
        .expect("Failed to add certificate");

    // FROM THIS POINT THE NODE AND MOBILE WILL RE-CONNECT USING THE NEW CERTIFICATES AND
    // ALL FUTURE COMMS ARE SECURED AND ECNRYPTED USING THESE NEW CREDENTIALS.

    // 5 - (mobile side) -  user created a network with a given name - generate a network key
    let network_public_key = mobile
        .generate_network_data_key()
        .expect("Failed to generate network data key");

    // network key is sent to the node. over secure and ecnrypted channel
    let network_private_key = mobile
        .get_network_private_key(&network_public_key)
        .expect("Failed to get network private key");

    // 6 - (node side) - received the network key and store it encrypted and secure.
    node.store_network_key(&network_public_key, network_private_key)
        .expect("Failed to store network key");

    // at this point the node is ready to process requests, events and data of the network_X

    // 7 - (mobile side) - User creates a profile key
    let (profile_public_key, profile_index) = mobile
        .generate_user_profile_key()
        .expect("Failed to generate user profile key");
    assert!(
        profile_public_key.len() > 0,
        "User profile key should have a valid public key"
    );

    // 8 - (mobile side) - Encrypts data using envelop which is encrypted using the
    //     user profile key and network key.
    //     so only the user or apps running in the network can decrypt it.
    let test_data = b"This is a test message that should be encrypted and decrypted";
    let envelope = mobile
        .encrypt_for_network_and_profile(test_data, &network_public_key, profile_index)
        .expect("Failed to encrypt data");

    // 9 - (node side) - received the encrypted data and decrypts it using the
    //     network key. (the node does not have the user profile key - so it needs a shared secreted)
    let decrypted_by_node = node
        .decrypt_with_network_key(&network_public_key, &envelope)
        .expect("Node failed to decrypt data");
    assert_eq!(
        decrypted_by_node, test_data,
        "Node should be able to decrypt the data"
    );

    // Additionally, verify that the mobile can also decrypt the data using the profile key
    let decrypted_by_mobile = mobile
        .decrypt_with_profile_key(&envelope, profile_index)
        .expect("Mobile failed to decrypt data");
    assert_eq!(
        decrypted_by_mobile, test_data,
        "Mobile should be able to decrypt the data"
    );
}
