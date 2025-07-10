use runar_serializer::{ArcValue, ValueCategory};
use std::collections::HashMap;
use std::sync::Arc;

// Non-JSON tests for ArcValue functionality
#[test]
fn test_null_value() {
    let null_value = ArcValue::null();
    assert_eq!(null_value.category, ValueCategory::Null);
    assert!(null_value.is_null());
}

#[test]
fn test_primitive_creation() {
    let string_value = ArcValue::new_primitive("Hello, world!".to_string());
    assert_eq!(string_value.category, ValueCategory::Primitive);

    let int_value = ArcValue::new_primitive(42i32);
    assert_eq!(int_value.category, ValueCategory::Primitive);

    let bool_value = ArcValue::new_primitive(true);
    assert_eq!(bool_value.category, ValueCategory::Primitive);
}

#[test]
fn test_list_creation() {
    let list_value = ArcValue::new_list(vec![1, 2, 3, 4, 5]);
    assert_eq!(list_value.category, ValueCategory::List);
}

#[test]
fn test_map_creation() {
    let mut map = HashMap::new();
    map.insert("key1".to_string(), "value1".to_string());
    map.insert("key2".to_string(), "value2".to_string());

    let map_value = ArcValue::new_map(map);
    assert_eq!(map_value.category, ValueCategory::Map);
}

#[test]
fn test_struct_creation() {
    #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct TestStruct {
        field1: String,
        field2: i32,
    }

    let test_struct = TestStruct {
        field1: "Hello".to_string(),
        field2: 42,
    };

    let struct_value = ArcValue::from_struct(test_struct);
    assert_eq!(struct_value.category, ValueCategory::Struct);
}

#[test]
fn test_bytes_creation() {
    let bytes_value = ArcValue::new_bytes(vec![1, 2, 3, 4, 5]);
    assert_eq!(bytes_value.category, ValueCategory::Bytes);
}

#[test]
fn test_json_creation() {
    let json_value = ArcValue::new_json(serde_json::json!({"key": "value"}));
    assert_eq!(json_value.category, ValueCategory::Json);
}

#[test]
fn test_primitive_access() {
    let mut value = ArcValue::new_primitive("Hello, world!".to_string());

    // Test as_type
    let string_value: String = value.as_type().unwrap();
    assert_eq!(string_value, "Hello, world!");

    // Test as_type_ref
    let string_ref = value.as_type_ref::<String>().unwrap();
    assert_eq!(&*string_ref, "Hello, world!");
}

#[test]
fn test_list_access() {
    let list = vec![1, 2, 3, 4, 5];
    let mut value = ArcValue::new_list(list);

    // Test as_list_ref
    let list_ref = value.as_list_ref::<i32>().unwrap();
    assert_eq!(*list_ref, vec![1, 2, 3, 4, 5]);
}

#[test]
fn test_map_access() {
    let mut map = HashMap::new();
    map.insert("key1".to_string(), "value1".to_string());
    map.insert("key2".to_string(), "value2".to_string());

    let mut value = ArcValue::new_map(map);

    // Test as_map_ref
    let map_ref = value.as_map_ref::<String, String>().unwrap();
    assert_eq!(map_ref.len(), 2);
    assert_eq!(map_ref.get("key1"), Some(&"value1".to_string()));
    assert_eq!(map_ref.get("key2"), Some(&"value2".to_string()));
}

#[test]
fn test_struct_access() {
    #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct TestStruct {
        field1: String,
        field2: i32,
    }

    let test_struct = TestStruct {
        field1: "Hello".to_string(),
        field2: 42,
    };

    let mut value = ArcValue::from_struct(test_struct.clone());

    // Test as_struct_ref
    let struct_ref = value.as_struct_ref::<TestStruct>().unwrap();
    assert_eq!(*struct_ref, test_struct);
}

#[test]
fn test_type_mismatch_errors() {
    let mut value = ArcValue::new_primitive("Hello, world!".to_string());

    // Try to get it as a number - this should fail
    let result: Result<i32, _> = value.as_type();
    assert!(result.is_err());

    // Try to get it as a list - this should fail
    let result: Result<Arc<Vec<String>>, _> = value.as_list_ref();
    assert!(result.is_err());

    // Try to get it as a map - this should fail
    let result: Result<Arc<HashMap<String, String>>, _> = value.as_map_ref();
    assert!(result.is_err());
}

#[test]
fn test_cloning() {
    let original_value = ArcValue::new_primitive("Hello, world!".to_string());
    let cloned_value = original_value.clone();

    // Verify they have the same content
    let mut original = original_value;
    let mut cloned = cloned_value;

    let original_string: String = original.as_type().unwrap();
    let cloned_string: String = cloned.as_type().unwrap();
    assert_eq!(original_string, cloned_string);
}

#[test]
fn test_equality() {
    let value1 = ArcValue::new_primitive("Hello".to_string());
    let value2 = ArcValue::new_primitive("Hello".to_string());
    let value3 = ArcValue::new_primitive("World".to_string());

    assert_eq!(value1, value2);
    assert_ne!(value1, value3);

    let null1 = ArcValue::null();
    let null2 = ArcValue::null();
    assert_eq!(null1, null2);
}

#[test]
fn test_category_mismatch() {
    let primitive_value = ArcValue::new_primitive("Hello".to_string());
    let list_value = ArcValue::new_list(vec![1, 2, 3]);
    let map_value = ArcValue::new_map(HashMap::<String, String>::new());

    assert_eq!(primitive_value.category, ValueCategory::Primitive);
    assert_eq!(list_value.category, ValueCategory::List);
    assert_eq!(map_value.category, ValueCategory::Map);
}
