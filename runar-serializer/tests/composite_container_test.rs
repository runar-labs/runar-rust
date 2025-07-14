// Composite container tests using new API without orphan impls

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use prost::Message;
use runar_serializer::{ArcValue, ValueCategory};

// Encryptable profile
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

use runar_common::logging::{Component, Logger};
use runar_keys::{MobileKeyManager, NodeKeyManager};
use runar_serializer::traits::{
    ConfigurableLabelResolver, EnvelopeCrypto, KeyMappingConfig, KeyScope, LabelKeyInfo,
};

// Build keystores + resolver
fn ctx() -> Result<(
    Arc<dyn EnvelopeCrypto>,
    Arc<dyn EnvelopeCrypto>,
    Arc<dyn runar_serializer::traits::LabelResolver>,
)> {
    let logger = Arc::new(Logger::new_root(Component::System, "comp-test"));
    let mut mobile = MobileKeyManager::new(logger.clone())?;
    mobile.initialize_user_root_key()?;
    let profile_pk = mobile.derive_user_profile_key("user")?;
    let network_id = mobile.generate_network_data_key()?;
    let network_pub = mobile.get_network_public_key(&network_id)?;

    let mut node = NodeKeyManager::new(logger.clone())?;
    let nk_msg = mobile.create_network_key_message(&network_id, &node.get_node_public_key())?;
    node.install_network_key(nk_msg)?;

    let mobile_ks = Arc::new(mobile) as Arc<dyn EnvelopeCrypto>;
    let node_ks = Arc::new(node) as Arc<dyn EnvelopeCrypto>;

    let resolver = Arc::new(ConfigurableLabelResolver::new(KeyMappingConfig {
        label_mappings: HashMap::from([
            (
                "user".into(),
                LabelKeyInfo {
                    public_key: profile_pk,
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
                    public_key: network_pub,
                    scope: KeyScope::Network,
                },
            ),
        ]),
    }));

    Ok((mobile_ks, node_ks, resolver))
}

#[test]
fn hashmap_of_profiles_roundtrip() -> Result<()> {
    let (mobile_ks, node_ks, resolver) = ctx()?;
    let mut map: HashMap<String, ArcValue> = HashMap::new();
    map.insert(
        "u1".into(),
        ArcValue::new_struct(TestProfile {
            id: "u1".into(),
            name: "Alice".into(),
            private: "secret1".into(),
            email: "a@x.com".into(),
        }),
    );
    map.insert(
        "u2".into(),
        ArcValue::new_struct(TestProfile {
            id: "u2".into(),
            name: "Bob".into(),
            private: "secret2".into(),
            email: "b@x.com".into(),
        }),
    );

    let av = ArcValue::new_map(map);
    let bytes = av.serialize(Some(mobile_ks.clone()), Some(resolver.as_ref()))?;
    let mut de = ArcValue::deserialize(&bytes, Some(node_ks.clone()))?;
    assert_eq!(de.category, ValueCategory::Map);
    let result_map = de.as_map_ref()?;
    for (k, v) in result_map.iter() {
        let mut inner = v.clone();
        let prof = inner.as_struct_ref::<TestProfile>()?;
        assert_eq!(prof.id, *k);
        assert!(prof.private.is_empty());
    }
    Ok(())
}

#[test]
fn vec_of_hashmap_profiles_roundtrip() -> Result<()> {
    let (mobile_ks, node_ks, resolver) = ctx()?;

    let build_map = |id: &str| {
        let mut m = HashMap::new();
        m.insert(
            id.to_string(),
            ArcValue::new_struct(TestProfile {
                id: id.into(),
                name: id.into(),
                private: "secret".into(),
                email: "e@x.com".into(),
            }),
        );
        m
    };

    let list = vec![
        ArcValue::new_map(build_map("u1")),
        ArcValue::new_map(build_map("u2")),
    ];
    let av = ArcValue::new_list(list);

    let bytes = av.serialize(Some(mobile_ks.clone()), Some(resolver.as_ref()))?;
    let mut de = ArcValue::deserialize(&bytes, Some(node_ks.clone()))?;
    let res_list = de.as_list_ref()?;
    assert_eq!(res_list.len(), 2);
    for item in res_list.iter() {
        let mut m_val = item.clone();
        let m = m_val.as_map_ref()?;
        for (_k, v) in m.iter() {
            let mut v_clone = v.clone();
            let p = v_clone.as_struct_ref::<TestProfile>()?;
            assert!(p.private.is_empty());
        }
    }
    Ok(())
}
