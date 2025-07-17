use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use prost::Message;
use runar_serializer::ArcValue;

#[derive(Clone, PartialEq, Debug, runar_serializer_macros::Encrypt)]
struct MessageForUser {
    pub id: String,
    #[runar(system)]
    pub status: String,
    #[runar(user)]
    pub secret: String,
}

#[test]
fn node_to_mobile_roundtrip() -> Result<()> {
    use runar_common::logging::{Component, Logger};
    use runar_keys::{MobileKeyManager, NodeKeyManager};
    use runar_serializer::traits::{
        ConfigurableLabelResolver, KeyMappingConfig, KeyScope, LabelKeyInfo,
    };

    let logger = Arc::new(Logger::new_root(Component::System, "node-mobile"));

    // mobile prepares profile + network keys
    let mut mobile = MobileKeyManager::new(logger.clone())?;
    mobile.initialize_user_root_key()?;
    let profile_pk = mobile.derive_user_profile_key("user")?;
    let network_id = mobile.generate_network_data_key()?;
    let network_pub = mobile.get_network_public_key(&network_id)?;

    // node installs network key and profile key
    let mut node = NodeKeyManager::new(logger.clone())?;
    let nk_msg = mobile.create_network_key_message(&network_id, &node.get_node_public_key())?;
    node.install_network_key(nk_msg)?;
    node.install_profile_public_key(profile_pk.clone());

    let node_keystore = Arc::new(node) as Arc<dyn runar_serializer::traits::EnvelopeCrypto>;
    let mobile_keystore = Arc::new(mobile) as Arc<dyn runar_serializer::traits::EnvelopeCrypto>;

    // node resolver: only system label (network) + user label mapping
    let node_resolver = Arc::new(ConfigurableLabelResolver::new(KeyMappingConfig {
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
        ]),
    }));

    // mobile resolver (needed for decryption path)
    let mobile_resolver = Arc::new(ConfigurableLabelResolver::new(KeyMappingConfig {
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
                    public_key: network_pub,
                    scope: KeyScope::Network,
                },
            ),
        ]),
    }));

    // node creates message
    let original = MessageForUser {
        id: "42".into(),
        status: "OK".into(),
        secret: "very-private".into(),
    };
    let av = ArcValue::new_struct(original.clone());
    let bytes = av.serialize(Some(node_keystore.clone()), Some(node_resolver.as_ref()))?;

    // mobile deserialises
    let av_mobile = ArcValue::deserialize(&bytes, Some(mobile_keystore.clone()))?;
    let msg: Arc<MessageForUser> = av_mobile.as_struct_ref()?;
    assert_eq!(msg.id, original.id);
    assert_eq!(msg.status, original.status);
    assert_eq!(msg.secret, original.secret);

    Ok(())
}
