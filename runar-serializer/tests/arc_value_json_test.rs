use runar_serializer::{ArcValue, Plain};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Plain)]
struct TestStruct {
    id: i32,
    name: String,
    active: bool,
    score: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Plain)]
struct NestedStruct {
    inner: TestStruct,
    metadata: String,
}

#[test]
fn test_primitive_types() {
    // Test integer
    let int_val = ArcValue::new_primitive(42i64);
    assert_eq!(int_val.to_json().unwrap(), json!(42));
    assert_eq!(int_val.as_type::<i64>().unwrap(), 42);

    // Test string
    let string_val = ArcValue::new_primitive("hello".to_string());
    assert_eq!(int_val.to_json().unwrap(), json!(42));
    assert_eq!(string_val.as_type::<String>().unwrap(), "hello");

    // Test float - use a non-approximate constant
    let float_val = ArcValue::new_primitive(std::f64::consts::PI);
    assert_eq!(float_val.to_json().unwrap(), json!(std::f64::consts::PI));
    assert_eq!(float_val.as_type::<f64>().unwrap(), std::f64::consts::PI);

    // Test boolean
    let bool_val = ArcValue::new_primitive(true);
    assert_eq!(bool_val.to_json().unwrap(), json!(true));
    assert!(bool_val.as_type::<bool>().unwrap());
}

#[test]
fn test_primitive_types_deserialization() {
    // Test integer
    let int_val = ArcValue::new_primitive(42i64);
    let serialized = int_val.serialize(None).unwrap();
    let int_val_deser = ArcValue::deserialize(&serialized, None).unwrap();
    assert_eq!(int_val_deser.to_json().unwrap(), json!(42));
    assert_eq!(int_val_deser.as_type::<i64>().unwrap(), 42);

    // Test string
    let string_val = ArcValue::new_primitive("hello".to_string());
    let serialized = string_val.serialize(None).unwrap();
    let string_val_deser = ArcValue::deserialize(&serialized, None).unwrap();
    assert_eq!(string_val_deser.to_json().unwrap(), json!("hello"));
    assert_eq!(string_val_deser.as_type::<String>().unwrap(), "hello");

    // Test float - use a non-approximate constant
    let float_val = ArcValue::new_primitive(std::f64::consts::PI);
    let serialized = float_val.serialize(None).unwrap();
    let float_val_deser = ArcValue::deserialize(&serialized, None).unwrap();
    assert_eq!(
        float_val_deser.to_json().unwrap(),
        json!(std::f64::consts::PI)
    );
    assert_eq!(
        float_val_deser.as_type::<f64>().unwrap(),
        std::f64::consts::PI
    );

    // Test boolean
    let bool_val = ArcValue::new_primitive(true);
    let serialized = bool_val.serialize(None).unwrap();
    let bool_val_deser = ArcValue::deserialize(&serialized, None).unwrap();
    assert_eq!(bool_val_deser.to_json().unwrap(), json!(true));
    assert!(bool_val_deser.as_type::<bool>().unwrap());
}

#[test]
fn test_list_types() {
    let list_data = vec![
        ArcValue::new_primitive("apple".to_string()),
        ArcValue::new_primitive("banana".to_string()),
        ArcValue::new_primitive(100i64),
        ArcValue::new_primitive(true),
    ];

    let arc_list = ArcValue::new_list(list_data.clone());
    let json_result = arc_list.to_json().unwrap();
    assert_eq!(json_result, json!(["apple", "banana", 100, true]));

    // Test deserialization
    let serialized = arc_list.serialize(None).unwrap();
    let deserialized = ArcValue::deserialize(&serialized, None).unwrap();
    let deserialized_list: Vec<ArcValue> = deserialized.as_type().unwrap();

    assert_eq!(deserialized_list.len(), 4);
    assert_eq!(deserialized_list[0].as_type::<String>().unwrap(), "apple");
    assert_eq!(deserialized_list[1].as_type::<String>().unwrap(), "banana");
    assert_eq!(deserialized_list[2].as_type::<i64>().unwrap(), 100);
    assert!(deserialized_list[3].as_type::<bool>().unwrap());

    // Test JSON conversion
    let json_result = deserialized.to_json().unwrap();
    assert_eq!(json_result, json!(["apple", "banana", 100, true]));
}

#[test]
fn test_map_types() {
    let mut map_data = HashMap::new();
    map_data.insert(
        "key1".to_string(),
        ArcValue::new_primitive("value1".to_string()),
    );
    map_data.insert("key2".to_string(), ArcValue::new_primitive(123i64));
    map_data.insert("key3".to_string(), ArcValue::new_primitive(true));

    let arc_map = ArcValue::new_map(map_data.clone());
    let json_result = arc_map.to_json().unwrap();
    assert_eq!(
        json_result,
        json!({
            "key1": "value1",
            "key2": 123,
            "key3": true
        })
    );

    // Test deserialization
    let serialized = arc_map.serialize(None).unwrap();
    let deserialized = ArcValue::deserialize(&serialized, None).unwrap();
    let deserialized_map: HashMap<String, ArcValue> = deserialized.as_type().unwrap();

    assert_eq!(deserialized_map.len(), 3);
    assert_eq!(
        deserialized_map["key1"].as_type::<String>().unwrap(),
        "value1"
    );
    assert_eq!(deserialized_map["key2"].as_type::<i64>().unwrap(), 123);
    assert!(deserialized_map["key3"].as_type::<bool>().unwrap());

    // Test JSON conversion
    let json_result = deserialized.to_json().unwrap();
    assert_eq!(
        json_result,
        json!({
            "key1": "value1",
            "key2": 123,
            "key3": true
        })
    );
}

#[test]
fn test_struct_types() {
    let test_struct = TestStruct {
        id: 1,
        name: "test".to_string(),
        active: true,
        score: 95.5,
    };

    let arc_struct = ArcValue::new_struct(test_struct.clone());
    let json_result = arc_struct.to_json().unwrap();
    assert_eq!(
        json_result,
        json!({
            "id": 1,
            "name": "test",
            "active": true,
            "score": 95.5
        })
    );

    // Test deserialization
    let serialized = arc_struct.serialize(None).unwrap();
    let deserialized = ArcValue::deserialize(&serialized, None).unwrap();
    let deserialized_struct: TestStruct = deserialized.as_type().unwrap();

    assert_eq!(deserialized_struct.id, 1);
    assert_eq!(deserialized_struct.name, "test");
    assert!(deserialized_struct.active);
    assert_eq!(deserialized_struct.score, 95.5);

    // Test JSON conversion
    let json_result = deserialized.to_json().unwrap();
    assert_eq!(
        json_result,
        json!({
            "id": 1,
            "name": "test",
            "active": true,
            "score": 95.5
        })
    );
}

#[test]
fn test_nested_struct_types() {
    let inner_struct = TestStruct {
        id: 1,
        name: "inner".to_string(),
        active: true,
        score: 85.0,
    };

    let nested_struct = NestedStruct {
        inner: inner_struct,
        metadata: "nested_test".to_string(),
    };

    let arc_nested_struct = ArcValue::new_struct(nested_struct.clone());
    let json_result = arc_nested_struct.to_json().unwrap();
    assert_eq!(
        json_result,
        json!({
            "inner": {
                "id": 1,
                "name": "inner",
                "active": true,
                "score": 85.0
            },
            "metadata": "nested_test"
        })
    );

    // Test deserialization
    let serialized = arc_nested_struct.serialize(None).unwrap();
    let deserialized = ArcValue::deserialize(&serialized, None).unwrap();
    let deserialized_nested: NestedStruct = deserialized.as_type().unwrap();

    assert_eq!(deserialized_nested.inner.id, 1);
    assert_eq!(deserialized_nested.inner.name, "inner");
    assert!(deserialized_nested.inner.active);
    assert_eq!(deserialized_nested.inner.score, 85.0);
    assert_eq!(deserialized_nested.metadata, "nested_test");

    // Test JSON conversion
    let json_result = deserialized.to_json().unwrap();
    assert_eq!(
        json_result,
        json!({
            "inner": {
                "id": 1,
                "name": "inner",
                "active": true,
                "score": 85.0
            },
            "metadata": "nested_test"
        })
    );
}

#[test]
fn test_struct_reference_types() {
    let test_struct = TestStruct {
        id: 1,
        name: "test".to_string(),
        active: true,
        score: 95.5,
    };

    let arc_struct = ArcValue::new_struct(test_struct.clone());
    let struct_ref = arc_struct.as_struct_ref::<TestStruct>().unwrap();

    assert_eq!(struct_ref.id, 1);
    assert_eq!(struct_ref.name, "test");
    assert!(struct_ref.active);
    assert_eq!(struct_ref.score, 95.5);

    // Test JSON conversion
    let json_result = arc_struct.to_json().unwrap();
    assert_eq!(
        json_result,
        json!({
            "id": 1,
            "name": "test",
            "active": true,
            "score": 95.5
        })
    );
}

#[test]
fn test_json_value_types() {
    let json_data = json!({
        "id": 1,
        "name": "test",
        "active": true,
        "score": 95.5
    });

    let arc_json = ArcValue::new_json(json_data.clone());
    let json_result = arc_json.to_json().unwrap();
    assert_eq!(json_result, json_data);

    // Test deserialization
    let serialized = arc_json.serialize(None).unwrap();
    let deserialized = ArcValue::deserialize(&serialized, None).unwrap();
    let deserialized_json: serde_json::Value = deserialized.as_type().unwrap();

    assert_eq!(deserialized_json, json_data);

    // Test JSON conversion
    let json_result = deserialized.to_json().unwrap();
    assert_eq!(json_result, json_data);
}

#[test]
fn test_bytes_types() {
    let bytes_data = b"hello world".to_vec();
    let arc_bytes = ArcValue::new_bytes(bytes_data.clone());

    // Test deserialization
    let serialized = arc_bytes.serialize(None).unwrap();
    let deserialized = ArcValue::deserialize(&serialized, None).unwrap();
    let deserialized_bytes: Vec<u8> = deserialized.as_type().unwrap();

    assert_eq!(deserialized_bytes, bytes_data);
}
