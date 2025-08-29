use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use runar_common::logging::{Component, Logger};
use runar_keys::{MobileKeyManager, NodeKeyManager};
use runar_serializer::traits::{
    ConfigurableLabelResolver, EnvelopeCrypto, KeyMappingConfig, LabelKeyInfo, SerializationContext,
};
use runar_serializer::ArcValue;
use runar_serializer_macros::Encrypt;

#[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize, Encrypt)]
pub struct TestProfile {
    pub id: String,
    #[runar(system)]
    pub name: String,
}

#[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct WrongPlain {
    pub x: i32,
}

type TestContext = (
    Arc<dyn EnvelopeCrypto>,
    Arc<dyn EnvelopeCrypto>,
    Arc<runar_serializer::traits::ConfigurableLabelResolver>,
    String,
    Vec<u8>,
);

fn build_test_context() -> Result<TestContext> {
    let logger = Arc::new(Logger::new_root(Component::System));
    let mut mobile_network_master = MobileKeyManager::new(logger.clone())?;
    let network_id = mobile_network_master.generate_network_data_key()?;
    let network_pub = mobile_network_master.get_network_public_key(&network_id)?;

    let mut user_mobile = MobileKeyManager::new(logger.clone())?;
    user_mobile.initialize_user_root_key()?;
    let profile_pk = user_mobile.derive_user_profile_key("user")?;
    user_mobile.install_network_public_key(&network_pub)?;

    let mut node_keys = NodeKeyManager::new(logger.clone())?;
    let token = node_keys.generate_csr()?;
    let nk_msg = mobile_network_master
        .create_network_key_message(&network_id, &token.node_agreement_public_key)?;
    node_keys.install_network_key(nk_msg)?;

    let user_mobile_ks = Arc::new(user_mobile) as Arc<dyn EnvelopeCrypto>;
    let node_ks = Arc::new(node_keys) as Arc<dyn EnvelopeCrypto>;

    let resolver = Arc::new(ConfigurableLabelResolver::new(KeyMappingConfig {
        label_mappings: HashMap::from([(
            "system".to_string(),
            LabelKeyInfo {
                profile_public_keys: vec![profile_pk.clone()],
                network_public_key: Some(network_pub.clone()),
            },
        )]),
    }));

    Ok((user_mobile_ks, node_ks, resolver, network_id, profile_pk))
}

#[test]
fn negative_typed_list_missing_keystore() -> Result<()> {
    let (mobile_ks, _node_ks, resolver, network_id, profile_pk) = build_test_context()?;

    let items = vec![TestProfile {
        id: "1".into(),
        name: "A".into(),
    }];
    let val = ArcValue::new_list(items);

    // Resolve network_public_key from resolver
    let system_info = resolver.resolve_label_info("system")?.unwrap();
    let ctx = SerializationContext {
        keystore: mobile_ks.clone(),
        resolver: resolver.clone(),
        network_public_key: system_info.network_public_key.unwrap(),
        profile_public_keys: vec![profile_pk.clone()],
    };

    // Serialize with context so element-level encryption is applied (bytes container)
    let ser = val.serialize(Some(&ctx))?;

    // Deserialize WITHOUT keystore in the lazy data to trigger error on decrypt
    let de = ArcValue::deserialize(&ser, None)?;
    assert!(de.as_typed_list_ref::<TestProfile>().is_err());
    Ok(())
}

#[test]
fn negative_unknown_primitive_wire_type() {
    // Build bytes: [category=1][encrypted=0][type_len]["unknown"][cbor bytes]
    let category = 1u8; // Primitive
    let is_encrypted = 0u8;
    let type_name = b"unknown";
    let value_cbor = serde_cbor::to_vec(&"x").unwrap();

    let mut buf = Vec::with_capacity(1 + 1 + 1 + type_name.len() + value_cbor.len());
    buf.push(category);
    buf.push(is_encrypted);
    buf.push(type_name.len() as u8);
    buf.extend_from_slice(type_name);
    buf.extend_from_slice(&value_cbor);

    let err = ArcValue::deserialize(&buf, None).unwrap_err();
    assert!(format!("{err}").contains("Unknown primitive wire type"));
}

#[test]
fn negative_typed_list_payload_mismatch() -> Result<()> {
    // Header declares typed list of TestProfile, but payload is Vec<i64>
    let type_name = "list<TestProfile>".as_bytes();
    let payload = serde_cbor::to_vec(&vec![1_i64, 2_i64, 3_i64])?;
    let mut buf = Vec::new();
    buf.push(2u8); // category: List
    buf.push(0u8); // not encrypted
    buf.push(type_name.len() as u8);
    buf.extend_from_slice(type_name);
    buf.extend_from_slice(&payload);

    let av = ArcValue::deserialize(&buf, None)?;
    let err = av.as_typed_list_ref::<TestProfile>().unwrap_err();
    assert!(format!("{err}").contains("Unsupported list payload"));
    Ok(())
}

#[test]
fn negative_typed_map_non_string_keys() -> Result<()> {
    // Header declares map<string,TestProfile> but payload has i64 keys
    let type_name = "map<string,TestProfile>".as_bytes();
    let mut bad_map: HashMap<i64, TestProfile> = HashMap::new();
    bad_map.insert(
        1,
        TestProfile {
            id: "1".into(),
            name: "A".into(),
        },
    );
    let payload = serde_cbor::to_vec(&bad_map)?;
    let mut buf = Vec::new();
    buf.push(3u8); // category: Map
    buf.push(0u8); // not encrypted
    buf.push(type_name.len() as u8);
    buf.extend_from_slice(type_name);
    buf.extend_from_slice(&payload);

    let av = ArcValue::deserialize(&buf, None)?;
    assert!(av.as_typed_map_ref::<TestProfile>().is_err());
    Ok(())
}

#[test]
fn negative_typed_map_wrong_value_payload() -> Result<()> {
    // Header declares map<string,TestProfile> but payload has map<string,i64>
    let type_name = "map<string,TestProfile>".as_bytes();
    let mut wrong_map: HashMap<String, i64> = HashMap::new();
    wrong_map.insert("k".into(), 42);
    let payload = serde_cbor::to_vec(&wrong_map)?;
    let mut buf = Vec::new();
    buf.push(3u8); // category: Map
    buf.push(0u8); // not encrypted
    buf.push(type_name.len() as u8);
    buf.extend_from_slice(type_name);
    buf.extend_from_slice(&payload);

    let av = ArcValue::deserialize(&buf, None)?;
    assert!(av.as_typed_map_ref::<TestProfile>().is_err());
    Ok(())
}

#[test]
fn negative_malformed_typename_list() -> Result<()> {
    let type_name = b"list<>";
    let payload = serde_cbor::to_vec(&vec![1_i64, 2_i64])?;
    let mut buf = Vec::new();
    buf.push(2u8); // List
    buf.push(0u8);
    buf.push(type_name.len() as u8);
    buf.extend_from_slice(type_name);
    buf.extend_from_slice(&payload);

    let av = ArcValue::deserialize(&buf, None)?;
    let err = av.as_typed_list_ref::<TestProfile>().unwrap_err();
    assert!(format!("{err}").contains("Unsupported list payload"));
    Ok(())
}

#[test]
fn negative_malformed_typename_map() -> Result<()> {
    let type_name = b"map<string,>";
    let payload = serde_cbor::to_vec(&HashMap::<String, i64>::new())?;
    let mut buf = Vec::new();
    buf.push(3u8); // Map
    buf.push(0u8);
    buf.push(type_name.len() as u8);
    buf.extend_from_slice(type_name);
    buf.extend_from_slice(&payload);

    let av = ArcValue::deserialize(&buf, None)?;
    assert!(av.as_typed_map_ref::<TestProfile>().is_err());
    Ok(())
}

#[test]
fn negative_unknown_category_byte() {
    let buf = vec![9u8, 0u8, 0u8];
    let err = ArcValue::deserialize(&buf, None).unwrap_err();
    assert!(format!("{err}").contains("Invalid category byte"));
}

#[test]
fn negative_missing_decryptor_for_t() -> Result<()> {
    let (mobile_ks, node_ks, resolver, network_id, profile_pk) = build_test_context()?;

    let items = vec![TestProfile {
        id: "1".into(),
        name: "A".into(),
    }];
    let val = ArcValue::new_list(items);

    // Resolve network_public_key from resolver
    let system_info = resolver.resolve_label_info("system")?.unwrap();
    let ctx = SerializationContext {
        keystore: mobile_ks.clone(),
        resolver: resolver.clone(),
        network_public_key: system_info.network_public_key.unwrap(),
        profile_public_keys: vec![profile_pk.clone()],
    };

    // Serialize with element encryption
    let ser = val.serialize(Some(&ctx))?;
    // Deserialize with keystore so decrypt path can run
    let de = ArcValue::deserialize(&ser, Some(node_ks.clone()))?;
    // Ask for WrongPlain (no decryptor registered) -> should error
    let err = de.as_typed_list_ref::<WrongPlain>().unwrap_err();
    assert!(format!("{err}").contains("No decryptor registered"));
    Ok(())
}

#[test]
fn negative_list_any_with_plain_vec_payload() -> Result<()> {
    // Header declares list<any>, but payload is Vec<i64>
    let type_name = b"list<any>";
    let payload = serde_cbor::to_vec(&vec![1_i64, 2_i64])?;
    let mut buf = Vec::new();
    buf.push(2u8); // List
    buf.push(0u8); // not encrypted
    buf.push(type_name.len() as u8);
    buf.extend_from_slice(type_name);
    buf.extend_from_slice(&payload);

    let av = ArcValue::deserialize(&buf, None)?;
    let err = av.as_list_ref().unwrap_err();
    // Expect an error since list<any> requires ArcValue-shaped elements
    assert!(
        format!("{err}").contains("Keystore required for decryptor")
            || format!("{err}").contains("No decryptor registered")
            || format!("{err}").contains("Unsupported")
    );
    Ok(())
}

#[test]
fn negative_map_any_with_plain_values() -> Result<()> {
    // Header declares map<string,any>, but payload is HashMap<String, i64>
    let type_name = b"map<string,any>";
    let mut plain: HashMap<String, i64> = HashMap::new();
    plain.insert("k".into(), 7);
    let payload = serde_cbor::to_vec(&plain)?;
    let mut buf = Vec::new();
    buf.push(3u8); // Map
    buf.push(0u8);
    buf.push(type_name.len() as u8);
    buf.extend_from_slice(type_name);
    buf.extend_from_slice(&payload);

    let av = ArcValue::deserialize(&buf, None)?;
    let err = av.as_map_ref().unwrap_err();
    assert!(
        format!("{err}").contains("Keystore required for decryptor")
            || format!("{err}").contains("No decryptor registered")
            || format!("{err}").contains("Unsupported")
    );
    Ok(())
}

#[test]
fn negative_invalid_utf8_typename() {
    // Embed invalid UTF-8 in type name
    let category = 1u8; // Primitive
    let is_encrypted = 0u8;
    let type_name = [0xff, 0xfe, 0xfd];
    let value_cbor = serde_cbor::to_vec(&"x").unwrap();

    let mut buf = Vec::new();
    buf.push(category);
    buf.push(is_encrypted);
    buf.push(type_name.len() as u8);
    buf.extend_from_slice(&type_name);
    buf.extend_from_slice(&value_cbor);

    let err = ArcValue::deserialize(&buf, None).unwrap_err();
    assert!(format!("{err}").contains("Invalid UTF-8 in type name"));
}

#[test]
fn negative_invalid_type_len_overflow() {
    // Type length indicates more than available bytes
    let buf = vec![1u8, 0u8, 200u8];
    // No further bytes
    let err = ArcValue::deserialize(&buf, None).unwrap_err();
    assert!(format!("{err}").contains("Invalid type name length"));
}

#[test]
fn negative_declared_list_but_payload_is_map() -> Result<()> {
    let type_name = b"list<i64>";
    let payload = serde_cbor::to_vec(&HashMap::<String, i64>::new())?; // map instead of list
    let mut buf = Vec::new();
    buf.push(2u8); // List
    buf.push(0u8);
    buf.push(type_name.len() as u8);
    buf.extend_from_slice(type_name);
    buf.extend_from_slice(&payload);

    let av = ArcValue::deserialize(&buf, None)?;
    let err = av.as_typed_list_ref::<i64>().unwrap_err();
    assert!(format!("{err}").contains("Unsupported list payload"));
    Ok(())
}

#[test]
fn negative_declared_map_but_payload_is_list() -> Result<()> {
    let type_name = b"map<string,i64>";
    let payload = serde_cbor::to_vec(&vec![1_i64, 2_i64])?; // list instead of map
    let mut buf = Vec::new();
    buf.push(3u8); // Map
    buf.push(0u8);
    buf.push(type_name.len() as u8);
    buf.extend_from_slice(type_name);
    buf.extend_from_slice(&payload);

    let av = ArcValue::deserialize(&buf, None)?;
    let err = av.as_typed_map_ref::<i64>().unwrap_err();
    assert!(format!("{err}").contains("Unsupported map payload"));
    Ok(())
}
