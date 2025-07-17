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
    #[runar(system_only)]
    pub system_metadata: String,
}

use runar_common::{
    compact_ids::compact_id,
    logging::{Component, Logger},
};
use runar_keys::{MobileKeyManager, NodeKeyManager};
use runar_serializer::traits::{
    ConfigurableLabelResolver, EnvelopeCrypto, KeyMappingConfig, LabelKeyInfo,
};

// Build keystores + resolver
fn ctx() -> Result<(
    Arc<dyn EnvelopeCrypto>,
    Arc<dyn EnvelopeCrypto>,
    Arc<dyn runar_serializer::traits::LabelResolver>,
    String,
)> {
    let logger = Arc::new(Logger::new_root(Component::System, "comp-test"));

    //this mimics a proper setup, where one mobile key store is use to setup the network and nodes
    //and the user has its own mobile key store with its keys, but does not have access to the network private keys

    let mut mobile_network_master = MobileKeyManager::new(logger.clone())?;
    let network_id = mobile_network_master.generate_network_data_key()?;
    let network_pub = mobile_network_master.get_network_public_key(&network_id)?;

    let mut user_mobile = MobileKeyManager::new(logger.clone())?;
    user_mobile.initialize_user_root_key()?;
    let profile_pk = user_mobile.derive_user_profile_key("user")?;
    //install only the network public key, not the network private key
    //so this user mobile can encrypt for the network, but not decrypt
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
                    profile_ids: vec![], //system only has no profile ids
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

    Ok((user_mobile_ks, node_ks, resolver, network_id))
}

#[test]
fn hashmap_of_profiles_roundtrip() -> Result<()> {
    let (mobile_ks, node_ks, resolver, network_id) = ctx()?;
    let mut map: HashMap<String, ArcValue> = HashMap::new();
    map.insert(
        "u1".into(),
        ArcValue::new_struct(TestProfile {
            id: "u1".into(),
            name: "Alice".into(),
            private: "secret1".into(),
            email: "a@x.com".into(),
            system_metadata: "system_metadata1".into(),
        }),
    );
    map.insert(
        "u2".into(),
        ArcValue::new_struct(TestProfile {
            id: "u2".into(),
            name: "Bob".into(),
            private: "secret2".into(),
            email: "b@x.com".into(),
            system_metadata: "system_metadata2".into(),
        }),
    );

    let av = ArcValue::new_map(map);
    let bytes = av.serialize(
        Some(mobile_ks.clone()),
        Some(resolver.as_ref()),
        &network_id,
    )?;
    //node side
    let de_node = ArcValue::deserialize(&bytes, Some(node_ks.clone()))?;
    assert_eq!(de_node.category, ValueCategory::Map);
    let result_map = de_node.as_typed_map_ref::<TestProfile>()?;
    assert_eq!(result_map.len(), 2);

    // Check u1 profile on node side (private should be empty, others visible)
    let u1_profile = result_map.get("u1").expect("u1 profile not found");
    assert_eq!(u1_profile.id, "u1");
    assert_eq!(u1_profile.name, "Alice");
    assert!(
        u1_profile.private.is_empty(),
        "private should be empty on node side for u1"
    );
    assert_eq!(u1_profile.email, "a@x.com");
    assert_eq!(u1_profile.system_metadata, "system_metadata1");

    // Check u2 profile on node side (private should be empty, others visible)
    let u2_profile = result_map.get("u2").expect("u2 profile not found");
    assert_eq!(u2_profile.id, "u2");
    assert_eq!(u2_profile.name, "Bob");
    assert!(
        u2_profile.private.is_empty(),
        "private should be empty on node side for u2"
    );
    assert_eq!(u2_profile.email, "b@x.com");

    //mobile side
    let de_mobile = ArcValue::deserialize(&bytes, Some(mobile_ks.clone()))?;
    assert_eq!(de_mobile.category, ValueCategory::Map);
    let result_map = de_mobile.as_typed_map_ref::<TestProfile>()?;
    assert_eq!(result_map.len(), 2);

    // Check u1 profile on mobile side (all fields should be visible)
    let u1_profile = result_map.get("u1").expect("u1 profile not found");
    assert_eq!(u1_profile.id, "u1");
    assert_eq!(u1_profile.name, "Alice");
    assert_eq!(u1_profile.private, "secret1");
    assert_eq!(u1_profile.email, "a@x.com");
    assert_eq!(u1_profile.system_metadata, "");

    // Check u2 profile on mobile side (all fields should be visible)
    let u2_profile = result_map.get("u2").expect("u2 profile not found");
    assert_eq!(u2_profile.id, "u2");
    assert_eq!(u2_profile.name, "Bob");
    assert_eq!(u2_profile.private, "secret2");
    assert_eq!(u2_profile.email, "b@x.com");
    assert_eq!(u2_profile.system_metadata, "");
    Ok(())
}

#[test]
fn vec_of_hashmap_profiles_roundtrip() -> Result<()> {
    let (mobile_ks, node_ks, resolver, network_id) = ctx()?;

    let build_map = |id: &str| {
        let mut m = HashMap::new();
        m.insert(
            id.to_string(),
            ArcValue::new_struct(TestProfile {
                id: id.into(),
                name: id.into(),
                private: "secret".into(),
                email: "e@x.com".into(),
                system_metadata: "system_metadata".into(),
            }),
        );
        m
    };

    let list = vec![
        ArcValue::new_map(build_map("u1")),
        ArcValue::new_map(build_map("u2")),
    ];
    let av = ArcValue::new_list(list);

    let bytes = av.serialize(
        Some(mobile_ks.clone()),
        Some(resolver.as_ref()),
        &network_id,
    )?;
    let de = ArcValue::deserialize(&bytes, Some(node_ks.clone()))?;
    let res_list = de.as_list_ref()?;
    assert_eq!(res_list.len(), 2);
    for item in res_list.iter() {
        let m_val = item.clone();
        let m = m_val.as_map_ref()?;
        for (_k, v) in m.iter() {
            let v_clone = v.clone();
            let p = v_clone.as_struct_ref::<TestProfile>()?;
            assert!(p.private.is_empty());
        }
    }
    Ok(())
}
