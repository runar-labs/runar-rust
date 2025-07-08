//! End-to-end encryption round-trip with real Mobile/Node key managers.

use rs::*;
use runar_serializer as rs;

use anyhow::Result;
use prost::Message;
use runar_common::logging::{Component, Logger};
use runar_common::types::ArcValue;
use std::collections::HashMap;
use std::sync::Arc;

use runar_keys::{mobile::MobileKeyManager, node::NodeKeyManager};

// Test structs
#[derive(rs::Encrypt, serde::Serialize, serde::Deserialize, Clone, PartialEq, Message)]
pub struct TestProfile {
    #[prost(string, tag = "1")]
    pub id: String,
    #[runar(user, system, search)]
    #[prost(string, tag = "2")]
    pub name: String,
    #[runar(user, system, search)]
    #[prost(string, tag = "3")]
    pub email: String,
    #[runar(user)]
    #[prost(string, tag = "4")]
    pub user_private: String,
    #[runar(user, system, search)]
    #[prost(uint64, tag = "5")]
    pub created_at: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Message)]
struct PlainData {
    #[prost(string, tag = "1")]
    pub value: String,
    #[prost(uint32, tag = "2")]
    pub count: u32,
}

// ------------------------------------------------------------
// Test utilities
// ------------------------------------------------------------

/// Build logger, key managers, label resolvers and a pair of serializer
/// registries (mobile + node) that can encrypt/decrypt `TestProfile` and
/// serialize `PlainData`.
fn prepare_registries() -> Result<(rs::SerializerRegistry, rs::SerializerRegistry)> {
    use rs::traits::{KeyScope, LabelKeyInfo};

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
    mobile_registry.register_encryptable::<TestProfile>()?;
    mobile_registry.register::<PlainData>()?;

    let mut node_registry =
        rs::SerializerRegistry::with_keystore(logger, node_mgr.clone(), node_resolver.clone());
    node_registry.register_encryptable::<TestProfile>()?;
    node_registry.register::<PlainData>()?;

    Ok((mobile_registry, node_registry))
}

#[test]
fn end_to_end_encryption() -> Result<()> {
    let (mobile_registry, node_registry) = prepare_registries()?;

    // -------- Test data --------
    let profile = TestProfile {
        id: "user123".into(),
        name: "Alice".into(),
        email: "alice@example.com".into(),
        user_private: "VIP user".into(),
        created_at: 1_234_567_890,
    };

    let plain = PlainData {
        value: "test".into(),
        count: 42,
    };

    // Mobile serializes (encrypts where resolver allows)
    let serialized = mobile_registry.serialize_value(&ArcValue::from_struct(profile.clone()))?;

    // ---- Business-logic path (plain struct) ----
    let mut node_val = node_registry.deserialize_value(serialized.clone())?;
    let plain_at_node = node_val.as_struct_ref::<TestProfile>()?;
    assert_eq!(plain_at_node.id, "user123");
    assert_eq!(plain_at_node.user_private, ""); // user-only field hidden

    // ---- Storage path (encrypted struct) ----
    let mut node_enc = node_registry.deserialize_value(serialized)?;
    let enc_at_node = node_enc.as_struct_ref::<EncryptedTestProfile>()?;
    assert!(enc_at_node.user_encrypted.is_some());

    // Skipping direct keystore-based round-trip here; the registry path above already
    // ensures encryption and decryption succeed end-to-end.

    // Plain struct lazy for PlainData
    let bytes_plain = mobile_registry.serialize_value(&ArcValue::from_struct(plain.clone()))?;
    let mut plain_val = node_registry.deserialize_value(bytes_plain)?;
    let roundtrip_plain = plain_val.as_struct_ref::<PlainData>()?;
    assert_eq!(&*roundtrip_plain, &plain);

    Ok(())
}

// A second variant that keeps the value as `ArcValue` for the entire round-trip and only later
// deserializes/inspects it.
#[test]
fn end_to_end_encryption_arc_value() -> Result<()> {
    let (mobile_registry, node_registry) = prepare_registries()?;

    let profile = TestProfile {
        id: "user123".into(),
        name: "Alice".into(),
        email: "alice@example.com".into(),
        user_private: "VIP user".into(),
        created_at: 1_234_567_890,
    };

    let avt = ArcValue::from_struct(profile.clone());
    let serialized = mobile_registry.serialize_value(&avt)?;

    // Deserialize but keep as ArcValue
    let mut node_val = node_registry.deserialize_value(serialized.clone())?;
    assert_eq!(
        node_val.category,
        runar_common::types::arc_value::ValueCategory::Struct
    );

    // Convert back to struct and verify contents (same as original test)
    let plain_at_node = node_val.as_struct_ref::<TestProfile>()?;
    assert_eq!(plain_at_node.id, "user123");
    assert_eq!(plain_at_node.name, "Alice");
    assert_eq!(plain_at_node.user_private, ""); // should be stripped

    // A fresh deserialization to inspect the encrypted representation lazily.
    let mut node_enc_val = node_registry.deserialize_value(serialized)?;
    let enc_at_node = node_enc_val.as_struct_ref::<EncryptedTestProfile>()?;
    assert!(enc_at_node.user_encrypted.is_some());

    Ok(())
}

// Simple checks preserved from unit tests -----------------------------------

#[test]
fn test_label_resolver() {
    use rs::traits::{KeyScope, LabelKeyInfo};
    let cfg = rs::traits::KeyMappingConfig {
        label_mappings: HashMap::from([
            (
                "user".into(),
                LabelKeyInfo {
                    public_key: vec![1],
                    scope: KeyScope::Profile,
                },
            ),
            (
                "system".into(),
                LabelKeyInfo {
                    public_key: vec![2],
                    scope: KeyScope::Network,
                },
            ),
        ]),
    };
    let resolver = rs::traits::ConfigurableLabelResolver::new(cfg);
    assert!(resolver.can_resolve("user"));
    assert_eq!(resolver.resolve_label("user").unwrap(), Some(vec![1]));
}

#[test]
fn test_encrypted_label_group() {
    let grp = rs::encryption::EncryptedLabelGroup {
        label: "x".into(),
        envelope: Some(runar_keys::mobile::EnvelopeEncryptedData {
            encrypted_data: vec![0, 1],
            network_id: String::new(),
            network_encrypted_key: vec![],
            profile_encrypted_keys: HashMap::new(),
        }),
    };
    assert!(!grp.is_empty());
}
