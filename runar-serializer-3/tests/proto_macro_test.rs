use runar_serializer::RunarSerializer;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SampleStruct {
    pub id: i64,
    pub name: String,
    pub created: u64,
}

impl RunarSerializer for SampleStruct {
    fn from_plain_bytes(bytes: &[u8], _keystore: Option<&std::sync::Arc<runar_serializer::KeyStore>>) -> anyhow::Result<Self> {
        serde_cbor::from_slice(bytes).map_err(anyhow::Error::from)
    }

    fn from_encrypted_bytes(bytes: &[u8], keystore: Option<&std::sync::Arc<runar_serializer::KeyStore>>) -> anyhow::Result<Self> {
        let decrypted = runar_serializer::encryption::decrypt_bytes(bytes, keystore.ok_or(anyhow::anyhow!("Keystore required"))?)?;
        Self::from_plain_bytes(&decrypted, keystore)
    }

    fn to_binary(&self, _context: Option<&runar_serializer::SerializationContext>) -> anyhow::Result<Vec<u8>> {
        serde_cbor::to_vec(self).map_err(anyhow::Error::from)
    }
}

#[test]
fn test_serde_cbor_struct_serialization() {
    let original = SampleStruct {
        id: 42,
        name: "test".to_string(),
        created: 1700000000,
    };

    // Test plain serialization
    let bytes = original.to_binary(None).expect("serialize");
    let deserialized = SampleStruct::from_plain_bytes(&bytes, None).expect("deserialize");

    assert_eq!(original, deserialized);
    assert_eq!(deserialized.id, 42);
    assert_eq!(deserialized.name, "test");
}
