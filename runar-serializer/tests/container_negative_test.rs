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

type TestContext = (
    Arc<dyn EnvelopeCrypto>,
    Arc<dyn EnvelopeCrypto>,
    Arc<dyn runar_serializer::traits::LabelResolver>,
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
                network_id: Some(network_id.clone()),
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

    let ctx = SerializationContext {
        keystore: mobile_ks.clone(),
        resolver: resolver.clone(),
        network_id: network_id.clone(),
        profile_public_key: Some(profile_pk.clone()),
    };

    // Serialize with context so element-level encryption is applied (bytes container)
    let ser = val.serialize(Some(&ctx))?;

    // Deserialize WITHOUT keystore in the lazy data to trigger error on decrypt
    let de = ArcValue::deserialize(&ser, None)?;
    let err = de.as_typed_list_ref::<TestProfile>().unwrap_err();
    assert!(format!("{err}").contains("Keystore required for decryptor"));
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
