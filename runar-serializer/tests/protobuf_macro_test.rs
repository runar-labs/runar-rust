use runar_serializer::encryption::EncryptedLabelGroup;
use runar_serializer_macros::Encrypt;

#[derive(Encrypt, serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SampleStruct {
    pub id: u32,
    #[runar(user)]
    pub name: String,
    pub created: u64,
}

#[test]
fn generated_proto_structs_compile() {
    // Ensure proto struct exists and can be instantiated
    let proto = EncryptedSampleStructProto {
        id: 42,
        created: 1700000000,
        user_encrypted: None,
    };

    // Convert to encrypted struct and back
    let encrypted: EncryptedSampleStruct = proto.clone().into();
    let _roundtrip: EncryptedSampleStructProto = encrypted.clone().into();

    // Type assertions to silence unused variable warnings
    let _phantom: Option<EncryptedLabelGroup> = encrypted.user_encrypted.clone();
}
