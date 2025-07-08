use prost::Message;
use runar_serializer::encryption::EncryptedLabelGroup;
use runar_serializer_macros::Encrypt;

#[derive(Encrypt, serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ProtoRoundTripStruct {
    pub id: u32,
    #[runar(user)]
    pub name: String,
    pub created_at: u64,
}

#[test]
fn proto_serialization_roundtrip() {
    // Create some dummy encrypted data for testing
    let dummy_encrypted = EncryptedLabelGroup {
        label: "user".to_string(),
        envelope: Some(runar_keys::mobile::EnvelopeEncryptedData {
            encrypted_data: vec![1, 2, 3, 4, 5],
            network_id: "test_network".to_string(),
            network_encrypted_key: vec![6, 7, 8],
            profile_encrypted_keys: std::collections::HashMap::new(),
        }),
    };

    // Build proto representation with encrypted data
    let proto_original = EncryptedProtoRoundTripStructProto {
        id: 1,
        created_at: 1700000000,
        user_encrypted: Some({
            let mut buf = Vec::new();
            prost::Message::encode(&dummy_encrypted, &mut buf).expect("encode label group");
            buf
        }),
    };

    // Serialize proto struct with protobuf (prost)
    let mut buf = Vec::new();
    proto_original.encode(&mut buf).expect("prost encode");

    // Deserialize back to proto struct
    let proto_deser = EncryptedProtoRoundTripStructProto::decode(&*buf).expect("prost decode");

    // Verify equality
    assert_eq!(proto_original.id, proto_deser.id);
    assert_eq!(proto_original.created_at, proto_deser.created_at);
    assert_eq!(proto_original.user_encrypted, proto_deser.user_encrypted);

    // Convert to encrypted struct and back again
    let encrypted: EncryptedProtoRoundTripStruct = proto_deser.clone().into();
    let proto_again: EncryptedProtoRoundTripStructProto = encrypted.clone().into();

    assert_eq!(proto_again.id, proto_deser.id);
    assert_eq!(proto_again.created_at, proto_deser.created_at);
    assert_eq!(proto_again.user_encrypted, proto_deser.user_encrypted);

    // Verify the encrypted data round-trips correctly
    assert!(encrypted.user_encrypted.is_some());
    let roundtrip_encrypted = encrypted.user_encrypted.unwrap();
    assert_eq!(roundtrip_encrypted.label, "user");
    assert_eq!(
        roundtrip_encrypted.envelope.unwrap().encrypted_data,
        vec![1, 2, 3, 4, 5]
    );
}
