use runar_serializer_macros::Encrypt;

#[derive(Encrypt, serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SchemaTestStruct {
    pub id: String,
    #[runar(user, system)]
    pub name: String,
    pub created_at: u64,
}

#[test]
fn proto_structs_compile() {
    // Just verify the proto structs are generated and compile
    let _proto = EncryptedSchemaTestStructProto {
        id: "test".to_string(),
        created_at: 1700000000,
        user_encrypted: None,
        system_encrypted: None,
    };
}
