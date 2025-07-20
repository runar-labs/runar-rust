use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use runar_common::{
    compact_ids::compact_id,
    logging::{Component, Logger},
};
use runar_keys::{MobileKeyManager, NodeKeyManager};
use runar_serializer::{
    traits::{ConfigurableLabelResolver, EnvelopeCrypto, KeyMappingConfig, LabelKeyInfo, SerializationContext},
    ArcValue, ValueCategory, RunarSerializer,
};
use runar_serializer_macros::{Encrypt, Serializable};

// Test struct with encryption
#[derive(Clone, PartialEq, Debug, Encrypt)]
struct TestProfile {
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
#[derive(Clone, PartialEq, Debug, Serializable, serde::Serialize, serde::Deserialize)]
struct SimpleStruct {
    pub a: i64,
    pub b: String,
}

// Build keystores + resolver for testing
fn build_test_context() -> Result<(
    Arc<dyn EnvelopeCrypto>,
    Arc<dyn EnvelopeCrypto>,
    Arc<dyn runar_serializer::traits::LabelResolver>,
    String,
    String,
)> {
    let logger = Arc::new(Logger::new_root(Component::System, "encryption-test"));

    // This mimics a proper setup, where one mobile key store is used to setup the network and nodes
    // and the user has its own mobile key store with its keys, but does not have access to the network private keys

    let mut mobile_network_master = MobileKeyManager::new(logger.clone())?;
    let network_id = mobile_network_master.generate_network_data_key()?;
    let network_pub = mobile_network_master.get_network_public_key(&network_id)?;

    let mut user_mobile = MobileKeyManager::new(logger.clone())?;
    user_mobile.initialize_user_root_key()?;
    let profile_pk = user_mobile.derive_user_profile_key("user")?;
    let profile_id = compact_id(&profile_pk);
    // Install only the network public key, not the network private key
    // so this user mobile can encrypt for the network, but not decrypt
    user_mobile.install_network_public_key(&network_pub)?;

    let mut node = NodeKeyManager::new(logger.clone())?;
    let nk_msg = mobile_network_master
        .create_network_key_message(&network_id, &node.get_node_public_key())?;
    node.install_network_key(nk_msg)?;

    let user_mobile_ks = Arc::new(user_mobile) as Arc<dyn EnvelopeCrypto>;
    let node_ks = Arc::new(node) as Arc<dyn EnvelopeCrypto>;

    let resolver = Arc::new(ConfigurableLabelResolver::new(KeyMappingConfig {
        label_mappings: HashMap::from([
            (
                "user".into(),
                LabelKeyInfo {
                    profile_ids: vec![compact_id(&profile_pk)],
                    network_id: None,
                },
            ),
            (
                "system".to_string(),
                LabelKeyInfo {
                    profile_ids: vec![compact_id(&profile_pk)],
                    network_id: Some(network_id.clone()),
                },
            ),
            (
                "system_only".to_string(),
                LabelKeyInfo {
                    profile_ids: vec![], // system only has no profile ids
                    network_id: Some(network_id.clone()),
                },
            ),
            (
                "search".to_string(),
                LabelKeyInfo {
                    profile_ids: vec![compact_id(&profile_pk)],
                    network_id: Some(network_id.clone()),
                },
            ),
        ]),
    }));

    Ok((user_mobile_ks, node_ks, resolver, network_id, profile_id))
}

#[test]
fn test_simple_serialization() -> Result<()> {
    let original = SimpleStruct {
        a: 123,
        b: "test".to_string(),
    };

    // Test serialization
    let bytes = original.to_binary(None)?;
    let decoded: SimpleStruct = SimpleStruct::from_plain_bytes(&bytes, None)?;
    assert_eq!(original, decoded);

    Ok(())
}

#[test]
fn test_encryption_basic() -> Result<()> {
    let (mobile_ks, node_ks, resolver, network_id, profile_id) = build_test_context()?;

    let original = TestProfile {
        id: "123".to_string(),
        name: "Test User".to_string(),
        private: "secret123".to_string(),
        email: "test@example.com".to_string(),
        system_metadata: "system_data".to_string(),
    };

    // Create serialization context
    let context = SerializationContext::new(
        mobile_ks.clone(),
        resolver.clone(),
        network_id.clone(),
        profile_id.clone(),
    );

    // Test encryption
    let encrypted = original.encrypt_with_keystore(&mobile_ks, resolver.as_ref())?;
    
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
fn test_encryption_serialization_roundtrip() -> Result<()> {
    let (mobile_ks, node_ks, resolver, network_id, profile_id) = build_test_context()?;

    let original = TestProfile {
        id: "456".to_string(),
        name: "Another User".to_string(),
        private: "another_secret".to_string(),
        email: "another@example.com".to_string(),
        system_metadata: "more_system_data".to_string(),
    };

    // Create serialization context
    let context = SerializationContext::new(
        mobile_ks.clone(),
        resolver.clone(),
        network_id.clone(),
        profile_id.clone(),
    );

    // Create ArcValue with struct and serialize with encryption
    let val = ArcValue::new_struct(original.clone());
    let bytes = val.serialize(Some(&context))?;

    // Deserialize without keystore (should fail to access encrypted data)
    let av_no_key = ArcValue::deserialize(&bytes, None)?;
    assert!(av_no_key.as_struct_ref::<TestProfile>().is_err());

    // Deserialize with node keystore (should work but with limited access)
    let av_node = ArcValue::deserialize(&bytes, Some(node_ks.clone()))?;
    let node_profile: Arc<TestProfile> = av_node.as_struct_ref()?;
    assert_eq!(node_profile.id, original.id);
    assert_eq!(node_profile.name, original.name);
    assert!(node_profile.private.is_empty()); // Should be empty for node
    assert_eq!(node_profile.email, original.email);
    assert_eq!(node_profile.system_metadata, original.system_metadata); // Node should have access to system_metadata

    // Deserialize with mobile keystore (should have access to user fields but not system_only)
    let av_mobile = ArcValue::deserialize(&bytes, Some(mobile_ks.clone()))?;
    let mobile_profile: Arc<TestProfile> = av_mobile.as_struct_ref()?;
    assert_eq!(mobile_profile.id, original.id);
    assert_eq!(mobile_profile.name, original.name);
    assert_eq!(mobile_profile.private, original.private);
    assert_eq!(mobile_profile.email, original.email);
    // Mobile doesn't have access to system_only fields
    assert!(mobile_profile.system_metadata.is_empty());

    Ok(())
}

#[test]
fn test_encryption_in_arcvalue() -> Result<()> {
    let (mobile_ks, node_ks, resolver, network_id, profile_id) = build_test_context()?;

    let profile = TestProfile {
        id: "789".to_string(),
        name: "ArcValue Test".to_string(),
        private: "arc_secret".to_string(),
        email: "arc@example.com".to_string(),
        system_metadata: "arc_system_data".to_string(),
    };

    // Create ArcValue with struct
    let val = ArcValue::new_struct(profile.clone());
    assert_eq!(val.category, ValueCategory::Struct);

    // Create serialization context
    let context = SerializationContext::new(
        mobile_ks.clone(),
        resolver.clone(),
        network_id.clone(),
        profile_id.clone(),
    );

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

    Ok(())
} 