use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use runar_serializer::{ArcValue, Plain, ValueCategory};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};

// Simple test struct without protobuf
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, Plain)]
struct TestStruct {
    pub a: i64,
    pub b: String,
}

// Simple test profile without encryption
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, Plain)]
struct TestProfile {
    pub id: String,
    pub name: String,
    pub email: String,
}

#[test]
fn test_primitive_string() -> Result<()> {
    let original = "hello".to_string();
    let val = ArcValue::new_primitive(original.clone());
    assert_eq!(val.category, ValueCategory::Primitive);

    let ser = val.serialize(None)?;
    let de = ArcValue::deserialize(&ser, None)?;
    let resolved: Arc<String> = de.as_type_ref()?;
    assert_eq!(*resolved, original);

    let resolved_2 = de.as_type::<String>()?;
    assert_eq!(resolved_2, original);

    Ok(())
}

#[test]
fn test_primitive_i64() -> Result<()> {
    let original = 42i64;
    let val = ArcValue::new_primitive(original);
    assert_eq!(val.category, ValueCategory::Primitive);

    let ser = val.serialize(None)?;
    let de = ArcValue::deserialize(&ser, None)?;
    let resolved: Arc<i64> = de.as_type_ref()?;
    assert_eq!(*resolved, original);

    let resolved_2 = de.as_type::<i64>()?;
    assert_eq!(resolved_2, original);

    Ok(())
}

#[test]
fn test_primitive_bool() -> Result<()> {
    let original = true;
    let val = ArcValue::new_primitive(original);
    assert_eq!(val.category, ValueCategory::Primitive);

    let ser = val.serialize(None)?;
    let de = ArcValue::deserialize(&ser, None)?;
    let resolved: Arc<bool> = de.as_type_ref()?;
    assert_eq!(*resolved, original);
    Ok(())
}

#[test]
fn test_primitive_f64() -> Result<()> {
    let original = std::f64::consts::PI;
    let val = ArcValue::new_primitive(original);
    assert_eq!(val.category, ValueCategory::Primitive);

    let ser = val.serialize(None)?;
    let de = ArcValue::deserialize(&ser, None)?;
    let resolved: Arc<f64> = de.as_type_ref()?;
    assert_eq!(*resolved, original);
    Ok(())
}

#[test]
fn test_list() -> Result<()> {
    let original = vec![
        ArcValue::new_primitive(1i64),
        ArcValue::new_primitive("two".to_string()),
    ];
    let val = ArcValue::new_list(original.clone());
    assert_eq!(val.category, ValueCategory::List);

    let ser = val.serialize(None)?;
    let de = ArcValue::deserialize(&ser, None)?;
    let resolved: Arc<Vec<ArcValue>> = de.as_list_ref()?;
    assert_eq!(resolved.len(), 2);
    let item0 = resolved[0].clone();
    assert_eq!(*item0.as_type_ref::<i64>()?, 1);
    let item1 = resolved[1].clone();
    assert_eq!(*item1.as_type_ref::<String>()?, "two");
    Ok(())
}

#[test]
fn test_map() -> Result<()> {
    let mut original = HashMap::new();
    original.insert("key1".to_string(), ArcValue::new_primitive(42i64));
    original.insert(
        "key2".to_string(),
        ArcValue::new_primitive("value".to_string()),
    );
    let val = ArcValue::new_map(original.clone());
    assert_eq!(val.category, ValueCategory::Map);

    let ser = val.serialize(None)?;
    let de = ArcValue::deserialize(&ser, None)?;
    let resolved: Arc<HashMap<String, ArcValue>> = de.as_map_ref()?;
    assert_eq!(resolved.len(), 2);
    let val1 = resolved.get("key1").unwrap().clone();
    assert_eq!(*val1.as_type_ref::<i64>()?, 42);
    let val2 = resolved.get("key2").unwrap().clone();
    assert_eq!(*val2.as_type_ref::<String>()?, "value");
    Ok(())
}

#[test]
fn test_bytes() -> Result<()> {
    let original = vec![1u8, 2, 3];
    let val = ArcValue::new_bytes(original.clone());
    assert_eq!(val.category, ValueCategory::Bytes);

    let ser = val.serialize(None)?;
    let de = ArcValue::deserialize(&ser, None)?;
    let resolved: Arc<Vec<u8>> = de.as_bytes_ref()?;
    assert_eq!(*resolved, original);
    Ok(())
}

#[test]
fn test_json() -> Result<()> {
    let original = json!({"key": "value"});
    let val = ArcValue::new_json(original.clone());
    assert_eq!(val.category, ValueCategory::Json);

    let ser = val.serialize(None)?;
    let de = ArcValue::deserialize(&ser, None)?;
    let resolved: Arc<JsonValue> = de.as_json_ref()?;
    assert_eq!(*resolved, original);
    Ok(())
}

#[test]
fn test_struct() -> Result<()> {
    let original = TestStruct {
        a: 123,
        b: "test".to_string(),
    };
    let val = ArcValue::new_struct(original.clone());
    assert_eq!(val.category, ValueCategory::Struct);

    let ser = val.serialize(None)?;
    let de = ArcValue::deserialize(&ser, None)?;
    let resolved: Arc<TestStruct> = de.as_struct_ref()?;
    assert_eq!(*resolved, original);
    Ok(())
}

#[test]
fn test_nested() -> Result<()> {
    let mut map = HashMap::new();
    map.insert("num".to_string(), ArcValue::new_primitive(42i64));
    map.insert(
        "str".to_string(),
        ArcValue::new_primitive("nested".to_string()),
    );
    let list = vec![ArcValue::new_map(map)];
    let val = ArcValue::new_list(list);

    let ser = val.serialize(None)?;
    let de = ArcValue::deserialize(&ser, None)?;
    let resolved_list: Arc<Vec<ArcValue>> = de.as_list_ref()?;
    assert_eq!(resolved_list.len(), 1);
    let inner_map_val = resolved_list[0].clone();
    let resolved_map: Arc<HashMap<String, ArcValue>> = inner_map_val.as_map_ref()?;
    let num_val = resolved_map.get("num").unwrap().clone();
    assert_eq!(*num_val.as_type_ref::<i64>()?, 42);
    let str_val = resolved_map.get("str").unwrap().clone();
    assert_eq!(*str_val.as_type_ref::<String>()?, "nested");
    Ok(())
}

#[test]
fn test_to_json_primitive() -> Result<()> {
    let val = ArcValue::new_primitive("hello".to_string());
    let json_val = val.to_json()?;
    assert_eq!(json_val, json!("hello"));
    Ok(())
}

#[test]
fn test_to_json_list() -> Result<()> {
    let list = vec![ArcValue::new_primitive(1i64), ArcValue::new_primitive(2i64)];
    let val = ArcValue::new_list(list);
    let json_val = val.to_json()?;
    assert_eq!(json_val, json!([1, 2]));
    Ok(())
}

#[test]
fn test_new_json() -> Result<()> {
    let json_val = json!({
        "string": "hello",
        "number": 42,
        "boolean": true,
        "array": [1, 2, 3],
        "object": {"key": "value"}
    });

    let val = ArcValue::new_json(json_val.clone());
    assert_eq!(val.category, ValueCategory::Json);

    let back_to_json = val.to_json()?;
    assert_eq!(back_to_json, json_val);
    Ok(())
}

#[test]
fn test_null() -> Result<()> {
    let null_val = ArcValue::null();
    assert_eq!(null_val.category, ValueCategory::Null);
    assert!(null_val.is_null());

    let ser = null_val.serialize(None)?;
    let de = ArcValue::deserialize(&ser, None)?;
    assert_eq!(de.category, ValueCategory::Null);
    assert!(de.is_null());
    Ok(())
}

#[test]
fn test_as_typed_map_ref() -> Result<()> {
    // Create a HashMap<String, ArcValue> where each ArcValue contains a TestProfile
    let mut profiles = HashMap::new();
    profiles.insert(
        "user1".to_string(),
        ArcValue::new_struct(TestProfile {
            id: "u1".to_string(),
            name: "Alice".to_string(),
            email: "alice@example.com".to_string(),
        }),
    );
    profiles.insert(
        "user2".to_string(),
        ArcValue::new_struct(TestProfile {
            id: "u2".to_string(),
            name: "Bob".to_string(),
            email: "bob@example.com".to_string(),
        }),
    );

    // Wrap the HashMap in ArcValue using new_map
    let arc_value = ArcValue::new_map(profiles);
    assert_eq!(arc_value.category, ValueCategory::Map);

    // Serialize and deserialize
    let bytes = arc_value.serialize(None)?;
    let deserialized = ArcValue::deserialize(&bytes, None)?;
    assert_eq!(deserialized.category, ValueCategory::Map);

    // Get the map as ArcValue first
    let map_arc = deserialized.as_map_ref()?;
    assert_eq!(map_arc.len(), 2);

    // Verify we can access individual ArcValues and their categories
    let user1_arc = map_arc.get("user1").expect("user1 not found");
    assert_eq!(user1_arc.category, ValueCategory::Struct);

    let user2_arc = map_arc.get("user2").expect("user2 not found");
    assert_eq!(user2_arc.category, ValueCategory::Struct);

    // Demonstrate the concept: we can extract typed values from individual ArcValues
    // (This would work if struct deserialization was fully implemented)
    let user1_profile = user1_arc.as_struct_ref::<TestProfile>()?;
    assert_eq!(user1_profile.id, "u1");
    assert_eq!(user1_profile.name, "Alice");
    assert_eq!(user1_profile.email, "alice@example.com");

    let user2_profile = user2_arc.as_struct_ref::<TestProfile>()?;
    assert_eq!(user2_profile.id, "u2");
    assert_eq!(user2_profile.name, "Bob");
    assert_eq!(user2_profile.email, "bob@example.com");

    Ok(())
}

#[test]
fn test_deserialize_bounds_check_fix() {
    // Test that the bounds check fix prevents out-of-bounds access
    // This test would panic without the fix

    // Create malformed data that would cause out-of-bounds access
    let malformed_data = vec![1u8, 0u8, 2u8]; // category=1, encrypted=0, type_name_len=2
                                              // This has 3 bytes total, but claims type_name_len=2
                                              // Without the fix: bounds check would pass, but slice access bytes[3..5] would panic
                                              // With the fix: bounds check should catch this and return an error

    let result = ArcValue::deserialize(&malformed_data, None);
    assert!(result.is_err(), "Should fail with invalid type name length");

    // Verify the error message indicates the bounds issue
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("Invalid type name length"),
        "Error should mention invalid type name length, got: {error_msg}"
    );

    // Test with even more malformed data
    let more_malformed = vec![1u8, 0u8, 255u8]; // type_name_len=255, but only 3 bytes total
    let result2 = ArcValue::deserialize(&more_malformed, None);
    assert!(
        result2.is_err(),
        "Should fail with invalid type name length"
    );

    // Test edge case: exactly at the boundary (should work)
    let edge_case = vec![1u8, 0u8, 1u8, b'a']; // 4 bytes total, type_name_len=1
    let result3 = ArcValue::deserialize(&edge_case, None);
    // This will fail for other reasons (invalid type name, missing data), but not bounds check
    assert!(
        result3.is_err(),
        "Should fail for other reasons, not bounds check"
    );

    // Test with valid data (should work)
    let test_string = "hello".to_string();
    let arc_value = ArcValue::new_primitive(test_string.clone());
    let serialized = arc_value.serialize(None).unwrap();
    let result4 = ArcValue::deserialize(&serialized, None);
    assert!(
        result4.is_ok(),
        "Valid data should deserialize successfully"
    );
}
