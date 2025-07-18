use prost::Message;
use runar_serializer::encryption::EncryptedLabelGroup;
use runar_serializer::RunarSerializer;
use runar_serializer_macros::Encrypt;

#[derive(Encrypt, serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct SampleStruct {
    pub id: i64,
    #[runar(user)]
    pub name: String,
    pub created: u64,
}

#[test]
fn generated_proto_structs_compile() {
    // Build encrypted struct directly
    let encrypted = EncryptedSampleStruct {
        id: 42,
        user_encrypted: None,
        created: 1700000000,
    };

    // Round-trip to binary (prost) and back using the generated CustomFromBytes impl
    let bytes = encrypted
        .to_binary(None, None, &"".to_string(), &"".to_string())
        .expect("serialise");
    let decrypted = EncryptedSampleStruct::from_plain_bytes(&bytes, None).expect("decode");

    assert_eq!(decrypted.id, 42);
    assert!(decrypted.user_encrypted.is_none());

    // Type assertion helper
    let _phantom: Option<EncryptedLabelGroup> = decrypted.user_encrypted.clone();
}
