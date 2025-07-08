use crate as runar_serializer;
use crate::*;
use anyhow::Result;
use runar_common::logging::{Component, Logger};
use runar_common::types::ArcValue;
use std::collections::HashMap;
use std::sync::Arc;

// Real key managers from runar-keys
use runar_keys::{
    mobile::{EnvelopeEncryptedData, MobileKeyManager},
    node::NodeKeyManager,
};

// Test structs
#[derive(Encrypt, serde::Serialize, serde::Deserialize, Debug, PartialEq, Clone)]
pub struct TestProfile {
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

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Clone)]
struct PlainData {
    pub value: String,
    pub count: u32,
}

#[test]
fn test_end_to_end_encryption_real_keystores() -> Result<()> {
    // Logger
    let logger = Arc::new(Logger::new_root(Component::System, "serializer-e2e"));

    // Build & initialise mobile key manager before wrapping in Arc
    let mut mobile_mgr_raw = MobileKeyManager::new(logger.clone())?;
    mobile_mgr_raw.initialize_user_root_key()?;

    // Derive keys required for tests before Arc wrapping
    let profile_pk = mobile_mgr_raw.derive_user_profile_key("user")?;
    let network_id = mobile_mgr_raw.generate_network_data_key()?;
    let network_pub = mobile_mgr_raw.get_network_public_key(&network_id)?;

    // Wrap in Arc after setup
    let mobile_mgr = Arc::new(mobile_mgr_raw);

    // ---------------- Node Setup ----------------
    let mut node_mgr_raw = NodeKeyManager::new(logger.clone())?;

    // Provide network key to node
    let nk_msg =
        mobile_mgr.create_network_key_message(&network_id, &node_mgr_raw.get_node_public_key())?;
    node_mgr_raw.install_network_key(nk_msg)?;

    let node_mgr = Arc::new(node_mgr_raw);

    // ---------------- Label Resolvers ----------------
    use runar_serializer::traits::{KeyScope, LabelKeyInfo};

    let mobile_label_config = KeyMappingConfig {
        label_mappings: HashMap::from([
            (
                "user".to_string(),
                LabelKeyInfo {
                    public_key: profile_pk.clone(),
                    scope: KeyScope::Profile,
                },
            ),
            (
                "system".to_string(),
                LabelKeyInfo {
                    public_key: network_pub.clone(),
                    scope: KeyScope::Network,
                },
            ),
            (
                "search".to_string(),
                LabelKeyInfo {
                    public_key: network_pub.clone(),
                    scope: KeyScope::Network,
                },
            ),
        ]),
    };
    let node_label_config = KeyMappingConfig {
        label_mappings: HashMap::from([
            (
                "system".to_string(),
                LabelKeyInfo {
                    public_key: network_pub.clone(),
                    scope: KeyScope::Network,
                },
            ),
            (
                "search".to_string(),
                LabelKeyInfo {
                    public_key: network_pub.clone(),
                    scope: KeyScope::Network,
                },
            ),
        ]),
    };

    let mobile_resolver = ConfigurableLabelResolver::new(mobile_label_config);
    let node_resolver = ConfigurableLabelResolver::new(node_label_config);

    // ---------------- Serializer Registries ----------------
    let mut mobile_registry = SerializerRegistry::with_keystore(
        logger.clone(),
        mobile_mgr.clone(),
        Arc::new(mobile_resolver),
    );
    mobile_registry.register_encryptable::<TestProfile>()?;
    mobile_registry.register::<PlainData>()?;

    let mut node_registry = SerializerRegistry::with_keystore(
        logger.clone(),
        node_mgr.clone(),
        Arc::new(node_resolver),
    );
    node_registry.register_encryptable::<TestProfile>()?;
    node_registry.register::<PlainData>()?;

    // ---------------- Test Data ----------------
    let profile = TestProfile {
        id: "user123".to_string(),
        name: "Alice".to_string(),
        email: "alice@example.com".to_string(),
        user_private: "VIP user".to_string(),
        created_at: 1234567890,
    };

    let plain_data = PlainData {
        value: "test".to_string(),
        count: 42,
    };

    // Serialize on mobile (encryption occurs)
    let mobile_arc = ArcValue::from_struct(profile.clone());
    let serialized_bytes = mobile_registry.serialize_value(&mobile_arc)?;

    // ---------------- Lazy ArcValue deserialization ----------------
    let mut mobile_val = mobile_registry.deserialize_value(serialized_bytes.clone())?;
    let roundtrip_profile = mobile_val.as_struct_ref::<TestProfile>()?;
    assert_eq!(&*roundtrip_profile, &profile);

    let mut node_val = node_registry.deserialize_value(serialized_bytes.clone())?;
    let node_profile = node_val.as_struct_ref::<TestProfile>()?;
    assert_eq!(node_profile.id, "user123");
    // Node should NOT be able to decrypt user-only fields
    assert_eq!(node_profile.name, "Alice");
    assert_eq!(node_profile.email, "alice@example.com");
    assert_eq!(node_profile.user_private, "");
    assert_eq!(node_profile.created_at, 1234567890);

    // Plain data path (still using lazy)
    let plain_arc = ArcValue::from_struct(plain_data.clone());
    let plain_bytes = mobile_registry.serialize_value(&plain_arc)?;
    let mut plain_val = node_registry.deserialize_value(plain_bytes)?;
    let plain_roundtrip = plain_val.as_struct_ref::<PlainData>()?;
    assert_eq!(&*plain_roundtrip, &plain_data);

    // -----------------------------------------------------------
    //  Validate that we can also obtain the *encrypted* variant
    //  lazily from the same ArcValue bytes.
    // -----------------------------------------------------------

    // Mobile side: the encrypted struct must be available and must contain
    // both label groups.
    let mut mobile_val_enc = mobile_registry.deserialize_value(serialized_bytes.clone())?;
    let enc_profile = mobile_val_enc.as_struct_ref::<EncryptedTestProfile>()?;
    assert!(enc_profile.user_encrypted.is_some());
    assert!(enc_profile.system_encrypted.is_some());

    // Node side: the encrypted struct must be available and must contain
    // both label groups.
    let mut node_val_enc = node_registry.deserialize_value(serialized_bytes.clone())?;
    let enc_profile = node_val_enc.as_struct_ref::<EncryptedTestProfile>()?;
    assert!(enc_profile.user_encrypted.is_some());
    assert!(enc_profile.system_encrypted.is_some());

    // the data storage layer will store the EncryptedTestProfile
    //but it also needs to know which fields can be used for search (in additio to the ID which is always searchable)
    //in this example abote. the label search is mapped for data store searched fields.. so the data storage layer
    // will use this struct to nkow which fields to use as searcheable fields.
    assert!(enc_profile.search_encrypted.is_some());
    //so we also need to be able to decrypt a
    let search_group = enc_profile.search_encrypted.as_ref().unwrap();
    let search_decrypted: TestProfileSearchFields =
        node_registry.decrypt_label_group(search_group)?;
    assert_eq!(search_decrypted.name, "Alice");
    assert_eq!(search_decrypted.email, "alice@example.com");
    assert_eq!(search_decrypted.created_at, 1234567890);

    Ok(())
}

#[test]
fn test_label_resolver() {
    use runar_serializer::traits::{KeyScope, LabelKeyInfo};

    let config = KeyMappingConfig {
        label_mappings: HashMap::from([
            (
                "user".to_string(),
                LabelKeyInfo {
                    public_key: vec![0x01, 0x02, 0x03],
                    scope: KeyScope::Profile,
                },
            ),
            (
                "system".to_string(),
                LabelKeyInfo {
                    public_key: vec![0x04, 0x05, 0x06],
                    scope: KeyScope::Network,
                },
            ),
        ]),
    };

    let resolver = ConfigurableLabelResolver::new(config);

    assert!(resolver.can_resolve("user"));
    assert!(resolver.can_resolve("system"));
    assert!(!resolver.can_resolve("unknown"));

    assert_eq!(
        resolver.resolve_label("user").unwrap(),
        Some(vec![0x01, 0x02, 0x03])
    );
    assert_eq!(
        resolver.resolve_label("system").unwrap(),
        Some(vec![0x04, 0x05, 0x06])
    );
    assert_eq!(resolver.resolve_label("unknown").unwrap(), None);

    let available = resolver.available_labels();
    assert!(available.contains(&"user".to_string()));
    assert!(available.contains(&"system".to_string()));
    assert_eq!(available.len(), 2);
}

#[test]
fn test_encrypted_label_group() {
    let group = EncryptedLabelGroup {
        label: "test".to_string(),
        envelope: Some(EnvelopeEncryptedData {
            encrypted_data: vec![1, 2, 3],
            network_id: String::new(),
            network_encrypted_key: Vec::new(),
            profile_encrypted_keys: std::collections::HashMap::new(),
        }),
    };

    assert!(!group.is_empty());

    let empty_group = EncryptedLabelGroup {
        label: "test".to_string(),
        envelope: Some(EnvelopeEncryptedData {
            encrypted_data: vec![],
            network_id: String::new(),
            network_encrypted_key: Vec::new(),
            profile_encrypted_keys: std::collections::HashMap::new(),
        }),
    };

    assert!(empty_group.is_empty());
}
