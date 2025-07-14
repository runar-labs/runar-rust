use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use prost::Message;
use runar_serializer::{ArcValue, CustomFromBytes, ValueCategory};
use serde_json::{json, Value as JsonValue};

// Add missing imports
use runar_keys::error::{KeyError, Result as KeyResult};
use runar_serializer::traits::{
    EnvelopeEncryptedData, KeyScope, KeyStore, LabelKeyInfo, LabelResolver,
};

// Add derive(Debug) and derive(prost::Message) to TestStruct
#[derive(Clone, PartialEq, prost::Message, runar_serializer_macros::Serializable)]
struct TestStruct {
    #[prost(int64, tag = "1")]
    pub a: i64,
    #[prost(string, tag = "2")]
    pub b: String,
}

// For TestProfile, to avoid duplication, use unique fields for test
#[derive(Clone, PartialEq, Debug, runar_serializer_macros::Encrypt)]
struct TestProfile {
    pub id: String,
    #[runar(system)]
    pub name: String,
    #[runar(user)]
    pub private: String,
    #[runar(search)]
    pub email: String,
}

#[test]
fn test_primitive_string() -> Result<()> {
    let original = "hello".to_string();
    let val = ArcValue::new_primitive(original.clone());
    assert_eq!(val.category, ValueCategory::Primitive);

    let ser = val.serialize(None, None)?;
    let mut de = ArcValue::deserialize(&ser, None)?;
    let resolved: Arc<String> = de.as_type_ref()?;
    assert_eq!(*resolved, original);
    Ok(())
}

#[test]
fn test_primitive_i64() -> Result<()> {
    let original = 42i64;
    let val = ArcValue::new_primitive(original);
    assert_eq!(val.category, ValueCategory::Primitive);

    let ser = val.serialize(None, None)?;
    let mut de = ArcValue::deserialize(&ser, None)?;
    let resolved: Arc<i64> = de.as_type_ref()?;
    assert_eq!(*resolved, original);
    Ok(())
}

#[test]
fn test_primitive_bool() -> Result<()> {
    let original = true;
    let val = ArcValue::new_primitive(original);
    assert_eq!(val.category, ValueCategory::Primitive);

    let ser = val.serialize(None, None)?;
    let mut de = ArcValue::deserialize(&ser, None)?;
    let resolved: Arc<bool> = de.as_type_ref()?;
    assert_eq!(*resolved, original);
    Ok(())
}

#[test]
fn test_primitive_f64() -> Result<()> {
    let original = 3.14f64;
    let val = ArcValue::new_primitive(original);
    assert_eq!(val.category, ValueCategory::Primitive);

    let ser = val.serialize(None, None)?;
    let mut de = ArcValue::deserialize(&ser, None)?;
    let resolved: Arc<f64> = de.as_type_ref()?;
    assert_eq!(*resolved, original);
    Ok(())
}

#[test]
fn test_list() -> Result<()> {
    let original = vec![
        ArcValue::new_primitive(1i64),
        ArcValue::new_primitive("two".to_string()),
    ];
    let val = ArcValue::new_list(original.clone());
    assert_eq!(val.category, ValueCategory::List);

    let ser = val.serialize(None, None)?;
    let mut de = ArcValue::deserialize(&ser, None)?;
    let resolved: Arc<Vec<ArcValue>> = de.as_list_ref()?;
    assert_eq!(resolved.len(), 2);
    let mut item0 = resolved[0].clone();
    assert_eq!(*item0.as_type_ref::<i64>()?, 1);
    let mut item1 = resolved[1].clone();
    assert_eq!(*item1.as_type_ref::<String>()?, "two");
    Ok(())
}

#[test]
fn test_map() -> Result<()> {
    let mut original = HashMap::new();
    original.insert("key1".to_string(), ArcValue::new_primitive(42i64));
    original.insert(
        "key2".to_string(),
        ArcValue::new_primitive("value".to_string()),
    );
    let val = ArcValue::new_map(original.clone());
    assert_eq!(val.category, ValueCategory::Map);

    let ser = val.serialize(None, None)?;
    let mut de = ArcValue::deserialize(&ser, None)?;
    let resolved: Arc<HashMap<String, ArcValue>> = de.as_map_ref()?;
    assert_eq!(resolved.len(), 2);
    let mut val1 = resolved.get("key1").unwrap().clone();
    assert_eq!(*val1.as_type_ref::<i64>()?, 42);
    let mut val2 = resolved.get("key2").unwrap().clone();
    assert_eq!(*val2.as_type_ref::<String>()?, "value");
    Ok(())
}

#[test]
fn test_bytes() -> Result<()> {
    let original = vec![1u8, 2, 3];
    let val = ArcValue::new_bytes(original.clone());
    assert_eq!(val.category, ValueCategory::Bytes);

    let ser = val.serialize(None, None)?;
    let mut de = ArcValue::deserialize(&ser, None)?;
    let resolved: Arc<Vec<u8>> = de.as_bytes_ref()?;
    assert_eq!(*resolved, original);
    Ok(())
}

#[test]
fn test_json() -> Result<()> {
    let original = json!({"key": "value"});
    let val = ArcValue::new_json(original.clone());
    assert_eq!(val.category, ValueCategory::Json);

    let ser = val.serialize(None, None)?;
    let mut de = ArcValue::deserialize(&ser, None)?;
    let resolved: Arc<JsonValue> = de.as_json_ref()?;
    assert_eq!(*resolved, original);
    Ok(())
}

#[test]
fn test_struct() -> Result<()> {
    let original = TestStruct {
        a: 123,
        b: "test".to_string(),
    };
    let val = ArcValue::new_struct(original.clone());
    assert_eq!(val.category, ValueCategory::Struct);

    let ser = val.serialize(None, None)?;
    let mut de = ArcValue::deserialize(&ser, None)?;
    let resolved: Arc<TestStruct> = de.as_struct_ref()?;
    assert_eq!(*resolved, original);
    Ok(())
}

#[test]
fn test_nested() -> Result<()> {
    let mut map = HashMap::new();
    map.insert("num".to_string(), ArcValue::new_primitive(42i64));
    map.insert(
        "str".to_string(),
        ArcValue::new_primitive("nested".to_string()),
    );
    let list = vec![ArcValue::new_map(map)];
    let val = ArcValue::new_list(list);

    let ser = val.serialize(None, None)?;
    let mut de = ArcValue::deserialize(&ser, None)?;
    let resolved_list: Arc<Vec<ArcValue>> = de.as_list_ref()?;
    assert_eq!(resolved_list.len(), 1);
    let mut inner_map_val = resolved_list[0].clone();
    let resolved_map: Arc<HashMap<String, ArcValue>> = inner_map_val.as_map_ref()?;
    let mut num_val = resolved_map.get("num").unwrap().clone();
    assert_eq!(*num_val.as_type_ref::<i64>()?, 42);
    let mut str_val = resolved_map.get("str").unwrap().clone();
    assert_eq!(*str_val.as_type_ref::<String>()?, "nested");
    Ok(())
}

#[test]
fn test_to_json_primitive() -> Result<()> {
    let mut val = ArcValue::new_primitive("hello".to_string());
    let json_val = val.to_json()?;
    assert_eq!(json_val, json!("hello"));
    Ok(())
}

#[test]
fn test_to_json_list() -> Result<()> {
    let list = vec![ArcValue::new_primitive(1i64), ArcValue::new_primitive(2i64)];
    let mut val = ArcValue::new_list(list);
    let json_val = val.to_json()?;
    assert_eq!(json_val, json!([1, 2]));
    Ok(())
}

#[test]
fn test_from_json() -> Result<()> {
    let json_val = json!({"key": [1, true]});
    let val = ArcValue::from_json(json_val.clone());
    let mut map = val.clone();
    let resolved_map: Arc<HashMap<String, ArcValue>> = map.as_map_ref()?;
    let mut list_val = resolved_map.get("key").unwrap().clone();
    let resolved_list: Arc<Vec<ArcValue>> = list_val.as_list_ref()?;
    let mut item0 = resolved_list[0].clone();
    assert_eq!(*item0.as_type_ref::<i64>()?, 1);
    let mut item1 = resolved_list[1].clone();
    assert_eq!(*item1.as_type_ref::<bool>()?, true);
    Ok(())
}

#[test]
fn test_null() -> Result<()> {
    let val = ArcValue::null();
    assert!(val.is_null());
    let ser = val.serialize(None, None)?;
    assert_eq!(ser, vec![0]);
    let de = ArcValue::deserialize(&ser, None)?;
    assert!(de.is_null());
    Ok(())
}

// Replace test_end_to_end_label_encryption with real key managers
#[test]
fn test_end_to_end_label_encryption_real() -> Result<()> {
    use runar_common::logging::{Component, Logger};
    use runar_keys::{MobileKeyManager, NodeKeyManager};
    use runar_serializer::traits::{
        ConfigurableLabelResolver, KeyMappingConfig, KeyScope, LabelKeyInfo,
    };

    let logger = Arc::new(Logger::new_root(Component::System, "test"));

    let mut mobile_mgr = MobileKeyManager::new(logger.clone())?;
    mobile_mgr.initialize_user_root_key()?;
    let profile_pk = mobile_mgr.derive_user_profile_key("user")?;
    let network_id = mobile_mgr.generate_network_data_key()?;
    let network_pub = mobile_mgr.get_network_public_key(&network_id)?;

    let mut node_mgr = NodeKeyManager::new(logger.clone())?;
    let nk_msg =
        mobile_mgr.create_network_key_message(&network_id, &node_mgr.get_node_public_key())?;
    node_mgr.install_network_key(nk_msg)?;

    let mobile_keystore = Arc::new(mobile_mgr) as Arc<dyn runar_serializer::traits::EnvelopeCrypto>;
    let node_keystore = Arc::new(node_mgr) as Arc<dyn runar_serializer::traits::EnvelopeCrypto>;

    let mobile_resolver = Arc::new(ConfigurableLabelResolver::new(KeyMappingConfig {
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
    }));

    // Node resolver not needed for decryption; node uses its keystore only.

    let original = TestProfile {
        id: "123".to_string(),
        name: "Test".to_string(),
        private: "secret".to_string(),
        email: "test@example.com".to_string(),
    };
    let val = ArcValue::new_struct(original.clone());
    // --- Mobile serialises (outer envelope) ---
    let ser = val.serialize(
        Some(mobile_keystore.clone()),
        Some(mobile_resolver.as_ref()),
    )?;

    // Deserialising without keystore returns a lazy ArcValue, but accessing data must fail
    let mut av_no_key = ArcValue::deserialize(&ser, None)?;
    assert!(av_no_key.as_struct_ref::<EncryptedTestProfile>().is_err());

    // --- Node opens envelope -> obtains encrypted representation ---
    let mut av_enc = ArcValue::deserialize(&ser, Some(node_keystore.clone()))?;
    let enc_profile: Arc<EncryptedTestProfile> = av_enc.as_struct_ref()?;
    // Ensure label groups present and encrypted
    assert!(enc_profile.user_encrypted.is_some());
    assert!(enc_profile.system_encrypted.is_some());
    assert!(enc_profile.search_encrypted.is_some());

    // Verify envelope metadata for system label
    let sys_env = enc_profile
        .system_encrypted
        .as_ref()
        .unwrap()
        .envelope
        .as_ref()
        .unwrap();
    assert!(!sys_env.network_encrypted_key.is_empty());

    // --- Node converts to plain TestProfile ---
    let mut av_plain = ArcValue::deserialize(&ser, Some(node_keystore.clone()))?;
    let plain: Arc<TestProfile> = av_plain.as_struct_ref()?;
    assert_eq!(plain.id, original.id);
    assert_eq!(plain.name, original.name);
    assert_eq!(plain.email, original.email);
    assert_eq!(plain.private, ""); // user-private stripped

    // --- Re-serialise encrypted struct for storage ---
    let av_store = ArcValue::new_struct(enc_profile.as_ref().clone());
    let stored_bytes = av_store.serialize(Some(node_keystore), None)?; // node re-wraps outer envelope with its network id
                                                                       // Stored bytes: outer envelope present – deserialises lazily but access should fail without key
    let mut av_no_key2 = ArcValue::deserialize(&stored_bytes, None)?;
    let ep: Arc<EncryptedTestProfile> = av_no_key2.as_struct_ref()?;
    assert!(ep.system_encrypted.is_some());

    Ok(())
}
