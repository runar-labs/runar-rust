// Simple composite container tests using new serde_cbor approach

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use runar_serializer::{ArcValue, Plain};
use serde::{Deserialize, Serialize};

// Simple test struct without encryption
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, Plain)]
struct TestProfile {
    pub id: String,
    pub name: String,
    pub email: String,
}

#[test]
fn test_hashmap_of_profiles_roundtrip() -> Result<()> {
    let mut map: HashMap<String, ArcValue> = HashMap::new();
    map.insert(
        "u1".into(),
        ArcValue::new_struct(TestProfile {
            id: "u1".into(),
            name: "Alice".into(),
            email: "a@x.com".into(),
        }),
    );
    map.insert(
        "u2".into(),
        ArcValue::new_struct(TestProfile {
            id: "u2".into(),
            name: "Bob".into(),
            email: "b@x.com".into(),
        }),
    );

    let av = ArcValue::new_map(map);

    // Test serialization without encryption context
    let bytes = av.serialize(None)?;

    // Test deserialization
    let de = ArcValue::deserialize(&bytes, None)?;
    assert_eq!(de.category, runar_serializer::ValueCategory::Map);

    // Extract typed HashMap using as_typed_map_ref
    let typed_profiles: HashMap<String, Arc<TestProfile>> = de.as_typed_map_ref()?;

    // Verify the map has the correct number of entries
    assert_eq!(typed_profiles.len(), 2);

    // Verify user1
    let user1 = typed_profiles.get("u1").expect("user1 not found");
    assert_eq!(user1.id, "u1");
    assert_eq!(user1.name, "Alice");
    assert_eq!(user1.email, "a@x.com");

    // Verify user2
    let user2 = typed_profiles.get("u2").expect("user2 not found");
    assert_eq!(user2.id, "u2");
    assert_eq!(user2.name, "Bob");
    assert_eq!(user2.email, "b@x.com");

    Ok(())
}

#[test]
fn test_nested_composite_structures() -> Result<()> {
    // Create a more complex nested structure: HashMap<String, Vec<TestProfile>>
    let mut nested_map: HashMap<String, ArcValue> = HashMap::new();

    // First group of profiles
    let group1_profiles = vec![
        ArcValue::new_struct(TestProfile {
            id: "g1_u1".into(),
            name: "Group1 Alice".into(),
            email: "g1_a@x.com".into(),
        }),
        ArcValue::new_struct(TestProfile {
            id: "g1_u2".into(),
            name: "Group1 Bob".into(),
            email: "g1_b@x.com".into(),
        }),
    ];
    nested_map.insert("group1".into(), ArcValue::new_list(group1_profiles));

    // Second group of profiles
    let group2_profiles = vec![ArcValue::new_struct(TestProfile {
        id: "g2_u1".into(),
        name: "Group2 Charlie".into(),
        email: "g2_c@x.com".into(),
    })];
    nested_map.insert("group2".into(), ArcValue::new_list(group2_profiles));

    let av = ArcValue::new_map(nested_map);

    // Test serialization and deserialization
    let bytes = av.serialize(None)?;
    let de = ArcValue::deserialize(&bytes, None)?;
    assert_eq!(de.category, runar_serializer::ValueCategory::Map);

    // Extract the nested structure
    let typed_nested: HashMap<String, Arc<Vec<ArcValue>>> = de.as_typed_map_ref()?;

    // Verify structure
    assert_eq!(typed_nested.len(), 2);

    // Verify group1
    let group1 = typed_nested.get("group1").expect("group1 not found");
    assert_eq!(group1.len(), 2);

    let g1_user1 = group1[0].as_struct_ref::<TestProfile>()?;
    assert_eq!(g1_user1.id, "g1_u1");
    assert_eq!(g1_user1.name, "Group1 Alice");
    assert_eq!(g1_user1.email, "g1_a@x.com");

    let g1_user2 = group1[1].as_struct_ref::<TestProfile>()?;
    assert_eq!(g1_user2.id, "g1_u2");
    assert_eq!(g1_user2.name, "Group1 Bob");
    assert_eq!(g1_user2.email, "g1_b@x.com");

    // Verify group2
    let group2 = typed_nested.get("group2").expect("group2 not found");
    assert_eq!(group2.len(), 1);

    let g2_user1 = group2[0].as_struct_ref::<TestProfile>()?;
    assert_eq!(g2_user1.id, "g2_u1");
    assert_eq!(g2_user1.name, "Group2 Charlie");
    assert_eq!(g2_user1.email, "g2_c@x.com");

    Ok(())
}

#[test]
fn test_mixed_content_containers() -> Result<()> {
    // Test containers with mixed content types
    let mut mixed_map: HashMap<String, ArcValue> = HashMap::new();

    // Add a struct
    mixed_map.insert(
        "profile".into(),
        ArcValue::new_struct(TestProfile {
            id: "mixed_user".into(),
            name: "Mixed User".into(),
            email: "mixed@x.com".into(),
        }),
    );

    // Add a primitive
    mixed_map.insert("count".into(), ArcValue::new_primitive(42i64));

    // Add a string
    mixed_map.insert(
        "description".into(),
        ArcValue::new_primitive("Mixed content test".to_string()),
    );

    // Add a list of primitives
    mixed_map.insert(
        "scores".into(),
        ArcValue::new_list(vec![
            ArcValue::new_primitive(85i64),
            ArcValue::new_primitive(92i64),
            ArcValue::new_primitive(78i64),
        ]),
    );

    let av = ArcValue::new_map(mixed_map);

    // Test serialization and deserialization
    let bytes = av.serialize(None)?;
    let de = ArcValue::deserialize(&bytes, None)?;
    assert_eq!(de.category, runar_serializer::ValueCategory::Map);

    // Extract the map
    let typed_map: Arc<HashMap<String, ArcValue>> = de.as_map_ref()?;

    // Verify profile
    let profile_arc = typed_map.get("profile").expect("profile not found");
    let profile = profile_arc.as_struct_ref::<TestProfile>()?;
    assert_eq!(profile.id, "mixed_user");
    assert_eq!(profile.name, "Mixed User");
    assert_eq!(profile.email, "mixed@x.com");

    // Verify count
    let count = typed_map.get("count").expect("count not found");
    let count_value: Arc<i64> = count.as_type_ref()?;
    assert_eq!(*count_value, 42);

    // Verify description
    let description = typed_map.get("description").expect("description not found");
    let desc_value: Arc<String> = description.as_type_ref()?;
    assert_eq!(*desc_value, "Mixed content test");

    // Verify scores
    let scores = typed_map.get("scores").expect("scores not found");
    let scores_list: Arc<Vec<ArcValue>> = scores.as_list_ref()?;
    assert_eq!(scores_list.len(), 3);

    let score1: Arc<i64> = scores_list[0].as_type_ref()?;
    let score2: Arc<i64> = scores_list[1].as_type_ref()?;
    let score3: Arc<i64> = scores_list[2].as_type_ref()?;

    assert_eq!(*score1, 85);
    assert_eq!(*score2, 92);
    assert_eq!(*score3, 78);

    Ok(())
}

#[test]
fn test_vec_of_profiles_roundtrip() -> Result<()> {
    let profiles = vec![
        ArcValue::new_struct(TestProfile {
            id: "u1".into(),
            name: "Alice".into(),
            email: "a@x.com".into(),
        }),
        ArcValue::new_struct(TestProfile {
            id: "u2".into(),
            name: "Bob".into(),
            email: "b@x.com".into(),
        }),
    ];

    let av = ArcValue::new_list(profiles);

    // Test serialization without encryption context
    let bytes = av.serialize(None)?;

    // Test deserialization
    let de = ArcValue::deserialize(&bytes, None)?;
    assert_eq!(de.category, runar_serializer::ValueCategory::List);

    // Extract typed Vec using as_typed_list_ref
    let typed_profiles: Vec<Arc<TestProfile>> = de.as_typed_list_ref()?;

    // Verify the list has the correct number of entries
    assert_eq!(typed_profiles.len(), 2);

    // Verify first profile (user1)
    let user1 = &typed_profiles[0];
    assert_eq!(user1.id, "u1");
    assert_eq!(user1.name, "Alice");
    assert_eq!(user1.email, "a@x.com");

    // Verify second profile (user2)
    let user2 = &typed_profiles[1];
    assert_eq!(user2.id, "u2");
    assert_eq!(user2.name, "Bob");
    assert_eq!(user2.email, "b@x.com");

    Ok(())
}
