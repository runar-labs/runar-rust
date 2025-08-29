use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use runar_common::logging::{Component, Logger};
use runar_keys::{MobileKeyManager, NodeKeyManager};
use runar_serializer::{
    traits::{
        ConfigurableLabelResolver, EnvelopeCrypto, KeyMappingConfig, LabelKeyInfo,
        SerializationContext,
    },
    ArcValue, Plain, ValueCategory,
};
use runar_serializer_macros::Encrypt;

// Test struct with encryption
#[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize, Encrypt)]
#[runar(name = "encryption_test.TestProfile")]
pub struct TestProfile {
    pub id: String,
    #[runar(system)]
    pub name: String,
    #[runar(user)]
    pub private: String,
    #[runar(search)]
    pub email: String,
    #[runar(system_only)]
    pub system_metadata: String,
}

// Simple struct for basic serialization test
#[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize, Plain)]
pub struct SimpleStruct {
    pub a: i64,
    pub b: String,
}

// Build keystores + resolver for testing

type TestContext = (
    Arc<dyn EnvelopeCrypto>,
    Arc<dyn EnvelopeCrypto>,
    Arc<runar_serializer::traits::ConfigurableLabelResolver>,
    String,
    Vec<u8>,
);

fn build_test_context() -> Result<TestContext> {
    let logger = Arc::new(Logger::new_root(Component::System));

    // This mimics a proper setup, where one mobile key store is used to setup the network and nodes
    // and the user has its own mobile key store with its keys, but does not have access to the network private keys

    let mut mobile_network_master = MobileKeyManager::new(logger.clone())?;
    let network_id = mobile_network_master.generate_network_data_key()?;
    let network_pub = mobile_network_master.get_network_public_key(&network_id)?;

    let mut user_mobile = MobileKeyManager::new(logger.clone())?;
    user_mobile.initialize_user_root_key()?;
    let profile_pk = user_mobile.derive_user_profile_key("user")?;
    // Install only the network public key, not the network private key
    // so this user mobile can encrypt for the network, but not decrypt
    user_mobile.install_network_public_key(&network_pub)?;

    let mut node_keys = NodeKeyManager::new(logger.clone())?;
    let token = node_keys.generate_csr()?;
    let nk_msg = mobile_network_master
        .create_network_key_message(&network_id, &token.node_agreement_public_key)?;
    node_keys.install_network_key(nk_msg)?;

    let user_mobile_ks = Arc::new(user_mobile) as Arc<dyn EnvelopeCrypto>;
    let node_ks = Arc::new(node_keys) as Arc<dyn EnvelopeCrypto>;

    let resolver = Arc::new(ConfigurableLabelResolver::new(KeyMappingConfig {
        label_mappings: HashMap::from([
            (
                "user".into(),
                LabelKeyInfo {
                    profile_public_keys: vec![profile_pk.clone()],
                    network_public_key: None,
                },
            ),
            (
                "system".to_string(),
                LabelKeyInfo {
                    profile_public_keys: vec![profile_pk.clone()],
                    network_public_key: Some(network_pub.clone()),
                },
            ),
            (
                "system_only".to_string(),
                LabelKeyInfo {
                    profile_public_keys: vec![], // system only has no profile ids
                    network_public_key: Some(network_pub.clone()),
                },
            ),
            (
                "search".to_string(),
                LabelKeyInfo {
                    profile_public_keys: vec![profile_pk.clone()],
                    network_public_key: Some(network_pub.clone()),
                },
            ),
        ]),
    }));

    Ok((user_mobile_ks, node_ks, resolver, network_id, profile_pk))
}

#[test]
fn test_encryption_basic() -> Result<()> {
    let (mobile_ks, node_ks, resolver, _network_id, _profile_pk) = build_test_context()?;

    let original = TestProfile {
        id: "123".to_string(),
        name: "Test User".to_string(),
        private: "secret123".to_string(),
        email: "test@example.com".to_string(),
        system_metadata: "system_data".to_string(),
    };

    // Test encryption
    let encrypted: EncryptedTestProfile =
        original.encrypt_with_keystore(&mobile_ks, resolver.as_ref())?;

    // Verify encrypted struct has the expected fields
    assert_eq!(encrypted.id, "123");
    assert!(encrypted.user_encrypted.is_some());
    assert!(encrypted.system_encrypted.is_some());
    assert!(encrypted.search_encrypted.is_some());
    assert!(encrypted.system_only_encrypted.is_some());

    // Test decryption with mobile (should have access to user fields but not system_only)
    let decrypted_mobile = encrypted.decrypt_with_keystore(&mobile_ks)?;
    assert_eq!(decrypted_mobile.id, original.id);
    assert_eq!(decrypted_mobile.name, original.name);
    assert_eq!(decrypted_mobile.private, original.private);
    assert_eq!(decrypted_mobile.email, original.email);
    assert!(decrypted_mobile.system_metadata.is_empty()); // Mobile should NOT have access to system_metadata

    // Test decryption with node (should have access to system fields but not user fields)
    let decrypted_node = encrypted.decrypt_with_keystore(&node_ks)?;
    assert_eq!(decrypted_node.id, original.id);
    assert_eq!(decrypted_node.name, original.name);
    assert!(decrypted_node.private.is_empty()); // Should be empty for node
    assert_eq!(decrypted_node.email, original.email);
    assert_eq!(decrypted_node.system_metadata, original.system_metadata); // Node should have access to system_metadata

    Ok(())
}

#[test]
fn test_encryption_in_arcvalue() -> Result<()> {
    let (mobile_ks, node_ks, resolver, network_id, profile_pk) = build_test_context()?; // keep network_id & profile_id used below

    let profile = TestProfile {
        id: "789".to_string(),
        name: "ArcValue Test".to_string(),
        private: "arc_secret".to_string(),
        email: "arc@example.com".to_string(),
        system_metadata: "arc_system_data".to_string(),
    };

    // Create ArcValue with struct
    let val = ArcValue::new_struct(profile.clone());
    assert_eq!(val.category(), ValueCategory::Struct);

    // Create serialization context - resolve network_public_key from resolver
    let system_info = resolver.resolve_label_info("system")?.unwrap();
    let context = SerializationContext {
        keystore: mobile_ks.clone(),
        resolver: resolver.clone(),
        network_public_key: system_info.network_public_key.unwrap(),
        profile_public_keys: vec![profile_pk.clone()],
    };

    // Serialize with encryption
    let ser = val.serialize(Some(&context))?;

    // Deserialize with node (limited access)
    let de_node = ArcValue::deserialize(&ser, Some(node_ks.clone()))?;
    let node_profile: Arc<TestProfile> = de_node.as_struct_ref()?;
    assert_eq!(node_profile.id, profile.id);
    assert_eq!(node_profile.name, profile.name);
    assert!(node_profile.private.is_empty());
    assert_eq!(node_profile.email, profile.email);
    assert_eq!(node_profile.system_metadata, profile.system_metadata); // Node should have access to system_metadata

    // Deserialize with mobile (access to user fields but not system_only)
    let de_mobile = ArcValue::deserialize(&ser, Some(mobile_ks.clone()))?;
    let mobile_profile: Arc<TestProfile> = de_mobile.as_struct_ref()?;
    assert_eq!(mobile_profile.id, profile.id);
    assert_eq!(mobile_profile.name, profile.name);
    assert_eq!(mobile_profile.private, profile.private);
    assert_eq!(mobile_profile.email, profile.email);
    assert!(mobile_profile.system_metadata.is_empty()); // Mobile should NOT have access to system_metadata

    let node_profile_encrypted: Arc<EncryptedTestProfile> = de_node.as_struct_ref()?;
    assert_eq!(node_profile_encrypted.id, profile.id);
    assert!(node_profile_encrypted.search_encrypted.is_some());
    assert!(node_profile_encrypted.system_encrypted.is_some());
    assert!(node_profile_encrypted.system_only_encrypted.is_some());
    assert!(node_profile_encrypted.user_encrypted.is_some());

    let node_profile = node_profile_encrypted.decrypt_with_keystore(&node_ks)?;
    assert_eq!(node_profile.id, profile.id);
    assert_eq!(node_profile.name, profile.name);
    assert!(node_profile.private.is_empty());
    assert_eq!(node_profile.email, profile.email);
    assert_eq!(node_profile.system_metadata, profile.system_metadata);
    Ok(())
}
