runar-serializer
================

Typed values with optional, selective field encryption for Runar apps and
services. Provides a compact, clone-efficient `ArcValue` container and
pluggable encryption via a `SerializationContext` (network/profile keys).

Install
-------

```toml
[dependencies]
runar-serializer = "0.1"
```

Highlights
----------

- **ArcValue**: typed, clone-efficient container with JSON/CBOR/Proto support
- **Pluggable crypto**: transparent encryption/decryption when a
  `SerializationContext` is provided
- **Derives**: works with `runar-serializer-macros` (`Encrypt`, `Plain`)

Quick start
-----------

```rust
use runar_serializer::{ArcValue, ValueCategory};

#[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
struct User { id: String, name: String }

let av = ArcValue::new_struct(User { id: "1".into(), name: "alice".into() });
assert_eq!(av.category(), ValueCategory::Struct);

// No encryption
let bytes = av.serialize(None)?;
let roundtrip = ArcValue::deserialize(&bytes, None)?;
let user: std::sync::Arc<User> = roundtrip.as_struct_ref()?;
```

Field‑level encryption (abridged)
---------------------------------

Combine this crate with `runar-serializer-macros` and `runar-keys` to encrypt
specific fields for user/profile or system/network contexts.

```rust
use std::collections::HashMap;
use std::sync::Arc;
use runar_common::logging::{Component, Logger};
use runar_keys::{MobileKeyManager, NodeKeyManager};
use runar_serializer::{
    traits::{
        ConfigurableLabelResolver, EnvelopeCrypto, KeyMappingConfig, LabelKeyInfo,
        SerializationContext,
    },
    ArcValue,
};
use runar_serializer_macros::Encrypt;

#[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize, Encrypt)]
struct Profile {
    id: String,
    #[runar(system)] name: String,
    #[runar(user)] private: String,
    #[runar(search)] email: String,
    #[runar(system_only)] system_metadata: String,
}

// Prepare keystores and resolver
let logger = Arc::new(Logger::new_root(Component::System, "readme-example"));
let mut network_master = MobileKeyManager::new(logger.clone())?;
let network_id = network_master.generate_network_data_key()?;
let network_pub = network_master.get_network_public_key(&network_id)?;

let mut user_mobile = MobileKeyManager::new(logger.clone())?;
user_mobile.initialize_user_root_key()?;
let profile_pk = user_mobile.derive_user_profile_key("default")?;
user_mobile.install_network_public_key(&network_pub)?;

let mut node = NodeKeyManager::new(logger.clone())?;
let token = node.generate_csr()?;
let nk_msg = network_master.create_network_key_message(&network_id, &token.node_agreement_public_key)?;
node.install_network_key(nk_msg)?;

let resolver = Arc::new(ConfigurableLabelResolver::new(KeyMappingConfig {
    label_mappings: HashMap::from([
        ("user".into(),        LabelKeyInfo { profile_public_keys: vec![profile_pk.clone()], network_id: None }),
        ("system".into(),      LabelKeyInfo { profile_public_keys: vec![profile_pk.clone()], network_id: Some(network_id.clone()) }),
        ("system_only".into(), LabelKeyInfo { profile_public_keys: vec![],                    network_id: Some(network_id.clone()) }),
        ("search".into(),      LabelKeyInfo { profile_public_keys: vec![profile_pk.clone()], network_id: Some(network_id.clone()) }),
    ]),
}));

let mobile_ks = Arc::new(user_mobile) as Arc<dyn EnvelopeCrypto>;
let node_ks = Arc::new(node) as Arc<dyn EnvelopeCrypto>;

let profile = Profile { id: "123".into(), name: "User".into(), private: "secret".into(), email: "u@example.com".into(), system_metadata: "sys".into() };

// Encrypt to generated EncryptedProfile
let enc: EncryptedProfile = profile.encrypt_with_keystore(&mobile_ks, resolver.as_ref())?;
// Decrypt in different contexts
let _mobile_view = enc.decrypt_with_keystore(&mobile_ks)?; // user fields available
let _node_view = enc.decrypt_with_keystore(&node_ks)?;     // system fields available

// ArcValue integration with transparent encryption on serialize
let ctx = SerializationContext { keystore: mobile_ks, resolver, network_id, profile_public_key: Some(profile_pk) };
let av = ArcValue::new_struct(Profile { id: "1".into(), name: "Alice".into(), private: "s".into(), email: "a@ex".into(), system_metadata: "m".into() });
let ser = av.serialize(Some(&ctx))?;              // encrypted
let de = ArcValue::deserialize(&ser, Some(node_ks))?; // decrypted for node
```

Plain derive (zero glue)
------------------------

Use `#[derive(Plain)]` from `runar-serializer-macros` to implement efficient
conversions to/from `ArcValue`.

```rust
use runar_serializer::ArcValue;
use runar_serializer_macros::Plain;

#[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize, Plain)]
struct Simple { a: i64, b: String }

let av = ArcValue::new_struct(Simple { a: 7, b: "x".into() });
let extracted: std::sync::Arc<Simple> = av.as_struct_ref()?;
```

License
-------

MIT. See `LICENSE`.


