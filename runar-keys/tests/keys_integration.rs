use runar_keys::*;

#[test]
fn test_e2e_keys_generation_and_exchange() {
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

    // Create a user owned and managed CA
    let user_ca_public_key = mobile
        .generate_user_ca_key()
        .expect("Failed to generate user CA key");
    assert_eq!(user_ca_public_key.bytes().len(), 32);
    println!(
        "User CA public key: {}",
        hex::encode(user_ca_public_key.bytes())
    );

    // Node first time use - enter in setup mode

    // 2 - node side (setup mode) - generate its own TLS and Storage keypairs
    //     and generate a setup handshake token which contains the CSR request and the node public key
    //     which will be presented as QR code.. here in the test we use the token as a string dfirectly.
    let mut node = NodeKeyManager::new();
    let setup_token = node
        .generate_setup_token()
        .expect("Failed to generate setup token");

    //lets serialize the setup token
    let setup_token_bytes =
        bincode::serialize(&setup_token).expect("Failed to serialize setup token");
    let setup_token_str = hex::encode(setup_token_bytes);
    println!("Setup token string: {}", setup_token_str);

    // Mobile scans a Node QR code which contains the setup token
    // setup_token_str represents the QR code

    // lets deserialize the setup token
    let setup_token_bytes_mobile =
        hex::decode(setup_token_str).expect("Failed to decode setup token");
    let setup_token_mobile =
        bincode::deserialize(&setup_token_bytes_mobile).expect("Failed to deserialize setup token");

    // 3 - (mobile side) - received the token and sign the CSR
    let cert = mobile
        .process_setup_token(&setup_token_mobile)
        .expect("Failed to process setup token");
    println!("Certificate: {} -> {}", cert.subject, cert.issuer);
    assert_eq!(
        cert.issuer,
        format!("ca:{}", hex::encode(user_ca_public_key.bytes())),
        "Certificate should be issued by the network CA"
    );

    // Extract the node ID from the setup token
    // In a real-world scenario, the mobile device would have received this in the setup token
    let node_public_key = hex::encode(&setup_token_mobile.node_public_key);

    // Mobile encrypts a message containing both the certificate and CA public key for secure transmission to the node
    // This ensures only the target node can decrypt the message and has the CA key needed for verification
    let encrypted_node_msg = mobile
        .encrypt_message_for_node(&cert, &node_public_key)
        .expect("Failed to encrypt message");
    println!("Certificate and CA key encrypted successfully for secure transmission");

    // The encrypted envelope then is transmitted over a network
    // Here we're simulating that by directly passing the envelope to the node

    //  serialize envelope for transmission
    let serialized_node_msg =
        bincode::serialize(&encrypted_node_msg).expect("Failed to serialize envelope");

    // Node side - received the encrypted message

    //  deserialize envelope
    let deserialized_node_msg =
        bincode::deserialize(&serialized_node_msg).expect("Failed to deserialize envelope");

    // 4 - (node side) - received the encrypted message, decrypts it,
    // validates the certificate using the CA key, and stores it
    node.process_mobile_message(&deserialized_node_msg)
        .expect("Failed to process encrypted certificate");

    // FROM THIS POINT THE NODE AND MOBILE WILL RE-CONNECT USING THE NEW CERTIFICATES AND
    // ALL FUTURE COMMS ARE SECURED AND ECNRYPTED USING THESE NEW CREDENTIALS.

    // 5 - (mobile side) -  user created a network with a given name - generate a network key
    let network_public_key = mobile
        .generate_network_data_key()
        .expect("Failed to generate network data key");

    // Create an encrypted network keys message for the node
    let network_name = "network_X";
    let node_id = hex::encode(&setup_token_mobile.node_public_key);
    let encrypted_network_keys = mobile
        .create_network_keys_message(&network_public_key, network_name, &node_id)
        .expect("Failed to create network keys message");

    // Serialize the encrypted network keys message for transmission
    let serialized_network_keys = bincode::serialize(&encrypted_network_keys)
        .expect("Failed to serialize network keys envelope");

    // Node side - received the encrypted network keys message
    let deserialized_network_keys = bincode::deserialize(&serialized_network_keys)
        .expect("Failed to deserialize network keys envelope");

    // 6 - (node side) - process the network keys message and store the keys securely
    node.process_network_keys_message(&deserialized_network_keys)
        .expect("Failed to process network keys message");

    // at this point the node is ready to process requests, events and data of the network_X

    // 7 - (mobile side) - User creates a profile key
    // Note: The API now returns only the public key, profile index is managed internally
    let profile_public_key = mobile
        .generate_user_profile_key()
        .expect("Failed to generate user profile key");
    assert!(
        profile_public_key.len() > 0,
        "User profile key should have a valid public key"
    );

    // 8 - (mobile side) - Encrypts data using envelope which is encrypted using the
    //     user profile key and network key.
    //     so only the user or apps running in the network can decrypt it.
    let test_data = b"This is a test message that should be encrypted and decrypted";
    let envelope = mobile
        .encrypt_for_network_and_profile(test_data, &network_public_key, &profile_public_key)
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
        .decrypt_with_profile_key(&envelope, &profile_public_key)
        .expect("Mobile failed to decrypt data");
    assert_eq!(
        decrypted_by_mobile, test_data,
        "Mobile should be able to decrypt the data"
    );

    let file_data_1 = b"This is some secret file content that should be encrypted on the node.";

    let encrypted_file_1 = node
        .encrypt_data(file_data_1)
        .expect("Node failed to encrypt data");
    println!("Encrypted data (hex): {}", hex::encode(&encrypted_file_1));
    assert_ne!(file_data_1, &encrypted_file_1[..]); // Ensure it's not plaintext

    let decrypted_file_1 = node
        .decrypt_data(&encrypted_file_1)
        .expect("Node failed to decrypt data");
    println!(
        "Decrypted data: {:?}",
        std::str::from_utf8(&decrypted_file_1).unwrap()
    );

    assert_eq!(
        file_data_1,
        &decrypted_file_1[..],
        "Decrypted data should match original"
    );

    // Now let's simulate when mobile and node already have keys stored in secure storage.
    // Step 1: Export the current state of the key managers
    let mobile_state = mobile.export_state();
    let node_state = node.export_state();

    // In a real implementation, these states would be serialized and stored in secure storage
    // For this test, we'll simulate that by serializing and deserializing them
    let serialized_mobile_state =
        bincode::serialize(&mobile_state).expect("Failed to serialize mobile state");
    let serialized_node_state =
        bincode::serialize(&node_state).expect("Failed to serialize node state");

    // Step 2: Create new key managers and hydrate them with the exported state
    // This simulates restarting the application and loading keys from secure storage
    let deserialized_mobile_state =
        bincode::deserialize(&serialized_mobile_state).expect("Failed to deserialize mobile state");
    let deserialized_node_state =
        bincode::deserialize(&serialized_node_state).expect("Failed to deserialize node state");

    let mut mobile_hydrated = MobileKeyManager::new();
    mobile_hydrated.import_state(deserialized_mobile_state);

    let mut node_hydrated = NodeKeyManager::new();
    node_hydrated.import_state(deserialized_node_state);

    // Verify that the hydrated key managers can still perform operations
    // Try encrypting and decrypting data with the hydrated managers
    let test_data_2 = b"This is a second test message after key restoration";
    let envelope_2 = mobile_hydrated
        .encrypt_for_network_and_profile(test_data_2, &network_public_key, &profile_public_key)
        .expect("Hydrated mobile failed to encrypt data");

    // Node should be able to decrypt with the network key
    let decrypted_by_node_2 = node_hydrated
        .decrypt_with_network_key(&network_public_key, &envelope_2)
        .expect("Hydrated node failed to decrypt data");
    assert_eq!(
        decrypted_by_node_2, test_data_2,
        "Hydrated node should be able to decrypt the data"
    );

    // Mobile should be able to decrypt with the profile key
    let decrypted_by_mobile_2 = mobile_hydrated
        .decrypt_with_profile_key(&envelope_2, &profile_public_key)
        .expect("Hydrated mobile failed to decrypt data");
    assert_eq!(
        decrypted_by_mobile_2, test_data_2,
        "Hydrated mobile should be able to decrypt the data"
    );

    // --- Test Node Symmetric Encryption for File Storage ---
    println!("\n--- Testing Node Symmetric Encryption ---");

    //check encrupted data before hydration
    let decrypted_file_1 = node
        .decrypt_data(&encrypted_file_1)
        .expect("Node failed to decrypt data");
    println!(
        "Decrypted data: {:?}",
        std::str::from_utf8(&decrypted_file_1).unwrap()
    );

    assert_eq!(
        file_data_1,
        &decrypted_file_1[..],
        "Decrypted data should match original"
    );

    // 1. Encrypt and decrypt data with the original node instance
    let file_data_2 = b"This is some secret file content that should be encrypted on the node.";
    println!(
        "Original data: {:?}",
        std::str::from_utf8(file_data_2).unwrap()
    );

    let encrypted_file_2 = node
        .encrypt_data(file_data_2)
        .expect("Node failed to encrypt data");
    println!("Encrypted data (hex): {}", hex::encode(&encrypted_file_2));
    assert_ne!(file_data_2, &encrypted_file_2[..]); // Ensure it's not plaintext

    let decrypted_file_2 = node
        .decrypt_data(&encrypted_file_2)
        .expect("Node failed to decrypt data");
    println!(
        "Decrypted data: {:?}",
        std::str::from_utf8(&decrypted_file_2).unwrap()
    );

    assert_eq!(
        file_data_2,
        &decrypted_file_2[..],
        "Decrypted data should match original"
    );
}
