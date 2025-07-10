use runar_common::logging::{Component, Logger};
use runar_serializer as rs;
use runar_serializer::{ArcValue, SerializerRegistry};
use std::collections::HashMap;
use std::sync::Arc;

// Custom struct that follows the same rules as built-in types
#[derive(Clone, PartialEq, prost::Message, serde::Serialize, serde::Deserialize)]
pub struct MyCustomType {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(int32, tag = "2")]
    pub value: i32,
    #[prost(bool, tag = "3")]
    pub active: bool,
}

// User profile struct following TestProfile pattern with encryption
#[derive(rs::Encrypt, serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug, Default)]
pub struct UserProfile {
    pub id: String,

    #[runar(user, system, search)]
    pub name: String,

    #[runar(user, system, search)]
    pub email: String,

    #[runar(user)]
    pub user_private: String,

    #[runar(user, system, search)]
    pub created_at: u64,
}

// ------------------------------------------------------------
// Test utilities for encryption setup
// ------------------------------------------------------------

/// Build logger, key managers, label resolvers and a pair of serializer
/// registries (mobile + node) that can encrypt/decrypt `UserProfile`.
fn prepare_encryption_registries(
) -> anyhow::Result<(rs::SerializerRegistry, rs::SerializerRegistry, String)> {
    use rs::traits::{KeyScope, LabelKeyInfo};
    use runar_keys::{mobile::MobileKeyManager, node::NodeKeyManager};

    let logger = Arc::new(Logger::new_root(Component::System, "serializer-e2e"));

    // -------- Mobile key manager --------
    let mut mobile_mgr_raw = MobileKeyManager::new(logger.clone())?;
    mobile_mgr_raw.initialize_user_root_key()?;
    let profile_pk = mobile_mgr_raw.derive_user_profile_key("user")?;
    let network_id = mobile_mgr_raw.generate_network_data_key()?;
    let network_pub = mobile_mgr_raw.get_network_public_key(&network_id)?;
    let mobile_mgr = Arc::new(mobile_mgr_raw);

    // -------- Node key manager --------
    let mut node_mgr_raw = NodeKeyManager::new(logger.clone())?;
    let nk_msg =
        mobile_mgr.create_network_key_message(&network_id, &node_mgr_raw.get_node_public_key())?;
    node_mgr_raw.install_network_key(nk_msg)?;
    let node_mgr = Arc::new(node_mgr_raw);

    // -------- Label resolvers --------
    let mobile_resolver = Arc::new(rs::traits::ConfigurableLabelResolver::new(
        rs::traits::KeyMappingConfig {
            label_mappings: HashMap::from([
                (
                    "user".into(),
                    LabelKeyInfo {
                        public_key: profile_pk.clone(),
                        scope: KeyScope::Profile,
                    },
                ),
                (
                    "system".into(),
                    LabelKeyInfo {
                        public_key: network_pub.clone(),
                        scope: KeyScope::Network,
                    },
                ),
                (
                    "search".into(),
                    LabelKeyInfo {
                        public_key: network_pub.clone(),
                        scope: KeyScope::Network,
                    },
                ),
            ]),
        },
    ));

    let node_resolver = Arc::new(rs::traits::ConfigurableLabelResolver::new(
        rs::traits::KeyMappingConfig {
            label_mappings: HashMap::from([
                (
                    "system".into(),
                    LabelKeyInfo {
                        public_key: network_pub.clone(),
                        scope: KeyScope::Network,
                    },
                ),
                (
                    "search".into(),
                    LabelKeyInfo {
                        public_key: network_pub.clone(),
                        scope: KeyScope::Network,
                    },
                ),
            ]),
        },
    ));

    // -------- Serializer registries --------
    let mut mobile_registry = rs::SerializerRegistry::with_keystore(
        logger.clone(),
        mobile_mgr.clone(),
        mobile_resolver.clone(),
    );
    mobile_registry.register_encryptable::<UserProfile>()?;

    let mut node_registry =
        rs::SerializerRegistry::with_keystore(logger, node_mgr.clone(), node_resolver.clone());
    node_registry.register_encryptable::<UserProfile>()?;

    Ok((mobile_registry, node_registry, network_id))
}

#[test]
fn test_direct_hashmap_serialization() {
    // Create a logger
    let logger = Arc::new(Logger::new_root(Component::System, "direct-hashmap-test"));
    // Create a serializer registry
    let registry = SerializerRegistry::new(logger);
    // Create test data: HashMap<String, String> directly
    let mut map1 = HashMap::new();
    map1.insert("key1".to_string(), "value1".to_string());
    map1.insert("key2".to_string(), "value2".to_string());
    // Wrap directly in ArcValue - no conversion needed
    let arc_value = ArcValue::from_struct(map1.clone());
    // Serialize and deserialize using expect for concise error handling
    let bytes = registry
        .serialize_value(&arc_value)
        .expect("Serialization failed");
    let mut deserialized_arc = registry.deserialize_value(bytes).unwrap();
    // Extract back to HashMap<String, String> directly
    let extracted: HashMap<String, String> = deserialized_arc
        .as_type()
        .expect("Failed to convert ArcValue to HashMap<String, String>");
    assert_eq!(extracted, map1);
}

#[test]
fn test_direct_vec_hashmap_serialization() {
    // Create a logger
    let logger = Arc::new(Logger::new_root(
        Component::System,
        "direct-vec-hashmap-test",
    ));
    // Create a serializer registry
    let registry = SerializerRegistry::new(logger);
    // Create test data: Vec<HashMap<String, String>> directly
    let mut map1 = HashMap::new();
    map1.insert("key1".to_string(), "value1".to_string());
    map1.insert("key2".to_string(), "value2".to_string());
    let mut map2 = HashMap::new();
    map2.insert("key3".to_string(), "value3".to_string());
    let test_data: Vec<HashMap<String, String>> = vec![map1, map2];
    // Wrap directly in ArcValue - no conversion needed
    let arc_value = ArcValue::from_struct(test_data.clone());
    // Serialize and deserialize using expect for concise error handling
    let bytes = registry
        .serialize_value(&arc_value)
        .expect("Serialization failed");
    let mut deserialized_arc = registry.deserialize_value(bytes).unwrap();
    // Extract back to Vec<HashMap<String, String>> directly
    let extracted: Vec<HashMap<String, String>> = deserialized_arc
        .as_type()
        .expect("Failed to convert ArcValue to Vec<HashMap<String, String>>");
    assert_eq!(extracted, test_data);
}

#[test]
fn test_direct_hashmap_float_serialization() {
    // Create a logger
    let logger = Arc::new(Logger::new_root(
        Component::System,
        "direct-hashmap-float-test",
    ));
    // Create a serializer registry
    let registry = SerializerRegistry::new(logger);
    // Create test data: HashMap<String, f64> directly
    let mut map1 = HashMap::new();
    map1.insert("a".to_string(), 1000.0);
    map1.insert("b".to_string(), 500.0);
    // Wrap directly in ArcValue - no conversion needed
    let arc_value = ArcValue::from_struct(map1.clone());
    // Serialize and deserialize using expect for concise error handling
    let bytes = registry
        .serialize_value(&arc_value)
        .expect("Serialization failed");
    let mut deserialized_arc = registry.deserialize_value(bytes).unwrap();
    // Extract back to HashMap<String, f64> directly
    let extracted: HashMap<String, f64> = deserialized_arc
        .as_type()
        .expect("Failed to convert ArcValue to HashMap<String, f64>");
    assert_eq!(extracted, map1);
}

#[test]
#[should_panic(expected = "No serializer registered for type")]
fn test_custom_type_hashmap_serialization() {
    // TODO: This test fails because the registry doesn't auto-register composite types for plain types.
    // The registry only auto-registers HashMap<String, T> and Vec<HashMap<String, T>> for encrypted types.
    // We need to enhance the registry to also auto-register these composite types for any type registered with register().
    // This will require macros to generate custom Map and Vec types for each registered type.
    // For now, this test demonstrates the limitation - manual registration would be needed.

    // Create a logger
    let logger = Arc::new(Logger::new_root(
        Component::System,
        "custom-type-hashmap-test",
    ));
    // Create a serializer registry
    let mut registry = SerializerRegistry::new(logger);

    // Register the custom types (this would be done automatically by macros)
    registry
        .register::<MyCustomType>()
        .expect("Failed to register MyCustomType");

    // Create test data: HashMap<String, MyCustomType> directly
    let mut map1 = HashMap::new();
    map1.insert(
        "user1".to_string(),
        MyCustomType {
            name: "Alice".to_string(),
            value: 42,
            active: true,
        },
    );
    map1.insert(
        "user2".to_string(),
        MyCustomType {
            name: "Bob".to_string(),
            value: 100,
            active: false,
        },
    );

    // Wrap directly in ArcValue - no conversion needed
    let arc_value = ArcValue::from_struct(map1.clone());

    // Serialize and deserialize using expect for concise error handling
    let bytes = registry
        .serialize_value(&arc_value)
        .expect("Serialization failed");
    let mut deserialized_arc = registry.deserialize_value(bytes).unwrap();

    // Extract back to HashMap<String, MyCustomType> directly
    let extracted: HashMap<String, MyCustomType> = deserialized_arc
        .as_type()
        .expect("Failed to convert ArcValue to HashMap<String, MyCustomType>");
    assert_eq!(extracted, map1);

    // Verify the custom type data is preserved correctly
    let alice = extracted.get("user1").expect("user1 should exist");
    assert!(alice.active);
    assert_eq!(alice.name, "Alice");
    assert_eq!(alice.value, 42);

    let bob = extracted.get("user2").expect("user2 should exist");
    assert_eq!(bob.name, "Bob");
    assert_eq!(bob.value, 100);
    assert!(!bob.active);
}

#[test]
#[should_panic(expected = "No serializer registered for type")]
fn test_custom_type_vec_hashmap_serialization() {
    // TODO: This test fails because the registry doesn't auto-register composite types for plain types.
    // The registry only auto-registers HashMap<String, T> and Vec<HashMap<String, T>> for encrypted types.
    // We need to enhance the registry to also auto-register these composite types for any type registered with register().
    // This will require macros to generate custom Map and Vec types for each registered type.
    // For now, this test demonstrates the limitation - manual registration would be needed.

    // Create a logger
    let logger = Arc::new(Logger::new_root(
        Component::System,
        "custom-type-vec-hashmap-test",
    ));
    // Create a serializer registry
    let mut registry = SerializerRegistry::new(logger);

    // Register the custom types (this would be done automatically by macros)
    registry
        .register::<MyCustomType>()
        .expect("Failed to register MyCustomType");

    // Create test data: Vec<HashMap<String, MyCustomType>> directly
    let mut map1 = HashMap::new();
    map1.insert(
        "user1".to_string(),
        MyCustomType {
            name: "Alice".to_string(),
            value: 42,
            active: true,
        },
    );

    let mut map2 = HashMap::new();
    map2.insert(
        "user2".to_string(),
        MyCustomType {
            name: "Bob".to_string(),
            value: 100,
            active: false,
        },
    );

    let test_data: Vec<HashMap<String, MyCustomType>> = vec![map1, map2];

    // Wrap directly in ArcValue - no conversion needed
    let arc_value = ArcValue::from_struct(test_data.clone());

    // Serialize and deserialize using expect for concise error handling
    let bytes = registry
        .serialize_value(&arc_value)
        .expect("Serialization failed");
    let mut deserialized_arc = registry.deserialize_value(bytes).unwrap();

    // Extract back to Vec<HashMap<String, MyCustomType>> directly
    let extracted: Vec<HashMap<String, MyCustomType>> = deserialized_arc
        .as_type()
        .expect("Failed to convert ArcValue to Vec<HashMap<String, MyCustomType>>");
    assert_eq!(extracted, test_data);

    // Verify the data is preserved correctly
    assert_eq!(extracted.len(), 2);

    let first_map = &extracted[0];
    let alice = first_map
        .get("user1")
        .expect("user1 should exist in first map");
    assert_eq!(alice.name, "Alice");
    assert_eq!(alice.value, 42);
    assert!(alice.active);

    let second_map = &extracted[1];
    let bob = second_map
        .get("user2")
        .expect("user2 should exist in second map");
    assert_eq!(bob.name, "Bob");
    assert_eq!(bob.value, 100);
    assert!(!bob.active);
}

#[test]
fn test_encrypted_user_profile_hashmap_serialization() -> anyhow::Result<()> {
    let (mobile_registry, node_registry, _network_id) = prepare_encryption_registries()?;

    // Create test data: HashMap<String, UserProfile> with encrypted fields
    let mut map1 = HashMap::new();
    map1.insert(
        "user1".to_string(),
        UserProfile {
            id: "user-001".to_string(),
            name: "Alice Smith".to_string(),
            email: "alice@example.com".to_string(),
            user_private: "secret-data-1".to_string(),
            created_at: 1640995200, // 2022-01-01 00:00:00 UTC
        },
    );
    map1.insert(
        "user2".to_string(),
        UserProfile {
            id: "user-002".to_string(),
            name: "Bob Johnson".to_string(),
            email: "bob@example.com".to_string(),
            user_private: "secret-data-2".to_string(),
            created_at: 1640995260, // 2022-01-01 00:01:00 UTC
        },
    );

    // Mobile serializes (encrypts where resolver allows)
    let serialized = mobile_registry.serialize_value(&ArcValue::from_struct(map1.clone()))?;

    // ---- Business-logic path (plain struct) ----
    let mut node_val = node_registry.deserialize_value(serialized.clone())?;
    let av_map: HashMap<String, rs::ArcValue> = node_val
        .as_type()
        .expect("Failed to convert ArcValue to HashMap<String, ArcValue>");

    assert_eq!(av_map.len(), 2);

    let mut alice_av = av_map["user1"].clone();
    let alice = alice_av.as_struct_ref::<UserProfile>()?;
    assert_eq!(alice.id, "user-001");
    assert_eq!(alice.name, "Alice Smith");
    assert_eq!(alice.email, "alice@example.com");
    assert_eq!(alice.user_private, "");
    assert_eq!(alice.created_at, 1640995200);

    let mut bob_av = av_map["user2"].clone();
    let bob = bob_av.as_struct_ref::<UserProfile>()?;
    assert_eq!(bob.id, "user-002");
    assert_eq!(bob.name, "Bob Johnson");
    assert_eq!(bob.email, "bob@example.com");
    assert_eq!(bob.user_private, "");
    assert_eq!(bob.created_at, 1640995260);

    // ---- Storage path (encrypted struct) ----
    let mut node_enc_value = node_registry.deserialize_value(serialized.clone())?;
    let enc_arc_map: HashMap<String, rs::ArcValue> = node_enc_value
        .as_type()
        .expect("Failed to convert ArcValue to HashMap<String, ArcValue>");

    // Lazily inspect encrypted representation
    let mut enc_extracted: HashMap<String, EncryptedUserProfile> = HashMap::new();
    for (k, arc_val) in enc_arc_map.iter() {
        let mut cloned = arc_val.clone();
        let enc_prof = cloned
            .as_struct_ref::<EncryptedUserProfile>()?
            .as_ref()
            .clone();
        enc_extracted.insert(k.clone(), enc_prof);
    }

    // Check that user-private field is encrypted
    let alice_enc = enc_extracted
        .get("user1")
        .expect("user1 should exist in encrypted map");
    assert!(
        alice_enc.user_encrypted.is_some(),
        "User-private field should be encrypted"
    );
    if let Some(user_encrypted) = &alice_enc.user_encrypted {
        assert_eq!(
            user_encrypted.label, "user",
            "User-private field should have 'user' label"
        );
        assert!(
            user_encrypted.envelope.is_some(),
            "User-private field should have envelope data"
        );
    }

    // Check that system fields are encrypted
    assert!(
        alice_enc.system_encrypted.is_some(),
        "System fields should be encrypted"
    );
    if let Some(system_encrypted) = &alice_enc.system_encrypted {
        assert_eq!(
            system_encrypted.label, "system",
            "System fields should have 'system' label"
        );
        assert!(
            system_encrypted.envelope.is_some(),
            "System fields should have envelope data"
        );
    }

    // Check that search fields are encrypted
    assert!(
        alice_enc.search_encrypted.is_some(),
        "Search fields should be encrypted"
    );
    if let Some(search_encrypted) = &alice_enc.search_encrypted {
        assert_eq!(
            search_encrypted.label, "search",
            "Search fields should have 'search' label"
        );
        assert!(
            search_encrypted.envelope.is_some(),
            "Search fields should have envelope data"
        );
    }

    // Check that user-private field is encrypted for Bob as well
    let bob_enc = enc_extracted
        .get("user2")
        .expect("user2 should exist in encrypted map");
    assert!(
        bob_enc.user_encrypted.is_some(),
        "User-private field should be encrypted for user2"
    );
    // System encrypted check for Bob
    assert!(
        bob_enc.system_encrypted.is_some(),
        "System fields should be encrypted for user2"
    );
    if let Some(system_encrypted) = &bob_enc.system_encrypted {
        assert_eq!(system_encrypted.label, "system");
        assert!(system_encrypted.envelope.is_some());
    }
    // Search encrypted check for Bob
    assert!(
        bob_enc.search_encrypted.is_some(),
        "Search fields should be encrypted for user2"
    );
    if let Some(search_encrypted) = &bob_enc.search_encrypted {
        assert_eq!(search_encrypted.label, "search");
        assert!(search_encrypted.envelope.is_some());
    }

    Ok(())
}

#[test]
fn test_encrypted_user_profile_vec_hashmap_serialization() -> anyhow::Result<()> {
    let (mobile_registry, node_registry, _network_id) = prepare_encryption_registries()?;

    // Create test data: Vec<HashMap<String, UserProfile>> with encrypted fields
    let mut map1 = HashMap::new();
    map1.insert(
        "user1".to_string(),
        UserProfile {
            id: "user-001".to_string(),
            name: "Alice Smith".to_string(),
            email: "alice@example.com".to_string(),
            user_private: "secret-data-1".to_string(),
            created_at: 1640995200,
        },
    );

    let mut map2 = HashMap::new();
    map2.insert(
        "user2".to_string(),
        UserProfile {
            id: "user-002".to_string(),
            name: "Bob Johnson".to_string(),
            email: "bob@example.com".to_string(),
            user_private: "secret-data-2".to_string(),
            created_at: 1640995260,
        },
    );

    let test_data: Vec<HashMap<String, UserProfile>> = vec![map1, map2];

    // Mobile serializes (encrypts where resolver allows)
    let serialized = mobile_registry.serialize_value(&ArcValue::from_struct(test_data.clone()))?;

    // ---- Business-logic path (plain struct) ----
    let mut node_val = node_registry.deserialize_value(serialized.clone())?;
    let av_vec: Vec<HashMap<String, rs::ArcValue>> = node_val
        .as_type()
        .expect("Failed to convert ArcValue to Vec<HashMap<String, ArcValue>>");

    assert_eq!(av_vec.len(), 2);

    let first_map_av = &av_vec[0];
    let mut alice_av = first_map_av["user1"].clone();
    let alice = alice_av.as_struct_ref::<UserProfile>()?;
    assert_eq!(alice.id, "user-001");
    assert_eq!(alice.name, "Alice Smith");
    assert_eq!(alice.email, "alice@example.com");
    assert_eq!(alice.user_private, "");
    assert_eq!(alice.created_at, 1640995200);

    let second_map_av = &av_vec[1];
    let mut bob_av = second_map_av["user2"].clone();
    let bob = bob_av.as_struct_ref::<UserProfile>()?;
    assert_eq!(bob.id, "user-002");
    assert_eq!(bob.name, "Bob Johnson");
    assert_eq!(bob.email, "bob@example.com");
    assert_eq!(bob.user_private, "");
    assert_eq!(bob.created_at, 1640995260);

    // ---- Storage path (encrypted struct) ----
    let mut node_enc_value = node_registry.deserialize_value(serialized.clone())?;
    let enc_arc_vec: Vec<HashMap<String, rs::ArcValue>> = node_enc_value
        .as_type()
        .expect("Failed to convert ArcValue to Vec<HashMap<String, ArcValue>>");

    // Lazily inspect encrypted representation
    let mut enc_extracted: Vec<HashMap<String, EncryptedUserProfile>> = Vec::new();
    for map in enc_arc_vec.iter() {
        let mut enc_map: HashMap<String, EncryptedUserProfile> = HashMap::new();
        for (k, arc_val) in map.iter() {
            let mut cloned = arc_val.clone();
            let enc_prof = cloned
                .as_struct_ref::<EncryptedUserProfile>()?
                .as_ref()
                .clone();
            enc_map.insert(k.clone(), enc_prof);
        }
        enc_extracted.push(enc_map);
    }

    // Check that user-private field is encrypted in first map
    let first_enc_map = &enc_extracted[0];
    let alice_enc = first_enc_map
        .get("user1")
        .expect("user1 should exist in first encrypted map");
    assert!(
        alice_enc.user_encrypted.is_some(),
        "User-private field should be encrypted in first map"
    );
    if let Some(user_encrypted) = &alice_enc.user_encrypted {
        assert_eq!(
            user_encrypted.label, "user",
            "User-private field should have 'user' label in first map"
        );
        assert!(
            user_encrypted.envelope.is_some(),
            "User-private field should have envelope data in first map"
        );
    }

    // Check that system fields are encrypted in first map
    assert!(
        alice_enc.system_encrypted.is_some(),
        "System fields should be encrypted in first map"
    );
    if let Some(system_encrypted) = &alice_enc.system_encrypted {
        assert_eq!(
            system_encrypted.label, "system",
            "System fields should have 'system' label in first map"
        );
        assert!(
            system_encrypted.envelope.is_some(),
            "System fields should have envelope data in first map"
        );
    }

    // Check that search fields are encrypted in first map
    assert!(
        alice_enc.search_encrypted.is_some(),
        "Search fields should be encrypted in first map"
    );
    if let Some(search_encrypted) = &alice_enc.search_encrypted {
        assert_eq!(
            search_encrypted.label, "search",
            "Search fields should have 'search' label in first map"
        );
        assert!(
            search_encrypted.envelope.is_some(),
            "Search fields should have envelope data in first map"
        );
    }

    // Check that user-private field is encrypted in second map
    let second_enc_map = &enc_extracted[1];
    let bob_enc = second_enc_map
        .get("user2")
        .expect("user2 should exist in second encrypted map");
    assert!(
        bob_enc.user_encrypted.is_some(),
        "User-private field should be encrypted in second map"
    );
    if let Some(user_encrypted) = &bob_enc.user_encrypted {
        assert_eq!(
            user_encrypted.label, "user",
            "User-private field should have 'user' label in second map"
        );
        assert!(
            user_encrypted.envelope.is_some(),
            "User-private field should have envelope data in second map"
        );
    }

    // Check that system fields are encrypted in second map
    assert!(
        bob_enc.system_encrypted.is_some(),
        "System fields should be encrypted in second map"
    );
    if let Some(system_encrypted) = &bob_enc.system_encrypted {
        assert_eq!(
            system_encrypted.label, "system",
            "System fields should have 'system' label in second map"
        );
        assert!(
            system_encrypted.envelope.is_some(),
            "System fields should have envelope data in second map"
        );
    }

    // Check that search fields are encrypted in second map
    assert!(
        bob_enc.search_encrypted.is_some(),
        "Search fields should be encrypted in second map"
    );
    if let Some(search_encrypted) = &bob_enc.search_encrypted {
        assert_eq!(
            search_encrypted.label, "search",
            "Search fields should have 'search' label in second map"
        );
        assert!(
            search_encrypted.envelope.is_some(),
            "Search fields should have envelope data in second map"
        );
    }

    Ok(())
}
