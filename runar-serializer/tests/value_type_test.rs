use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use runar_common::logging::{Component, Logger};
use runar_serializer::{ArcValue, SerializerRegistry, ValueCategory};
use serde::{Deserialize, Serialize};
use serde_json::{self, json};

// Create a test registry for use in tests
fn create_test_registry() -> SerializerRegistry {
    let mut registry = SerializerRegistry::with_defaults(Arc::new(Logger::new_root(
        Component::Custom("Test"),
        "test-node",
    )));

    // Register the test struct for serialization
    registry.register::<TestStruct>().unwrap();

    // Make sure all registrations are done before any serialization
    println!("Test registry initialized with TestStruct");

    registry
}

#[derive(Clone, PartialEq, Serialize, Deserialize, prost::Message)]
#[prost(message)]
struct TestStruct {
    #[prost(string, tag = "1")]
    field1: String,
    #[prost(int32, tag = "2")]
    field2: i32,
}

#[test]
fn test_primitives_arc_preservation() -> Result<()> {
    // Create a value with a string
    let string_value = "Hello, world!".to_string();
    let mut value = ArcValue::new_primitive(string_value);

    // Get reference to the string
    let ref1 = value.as_type_ref::<String>()?;
    let ref2 = value.as_type_ref::<String>()?;

    // Verify identity (same Arc pointer)
    assert!(Arc::ptr_eq(&ref1, &ref2));

    // Verify content
    assert_eq!(&*ref1, "Hello, world!");
    assert_eq!(&*ref2, "Hello, world!");

    Ok(())
}

#[test]
fn test_list_arc_preservation() -> Result<()> {
    // Create a value with a list
    let list = vec![1, 2, 3, 4, 5];
    let mut value = ArcValue::new_list(list);

    // Get references
    let ref1 = value.as_list_ref::<i32>()?;
    let ref2 = value.as_list_ref::<i32>()?;

    // Verify identity
    assert!(Arc::ptr_eq(&ref1, &ref2));

    // Verify content
    assert_eq!(*ref1, vec![1, 2, 3, 4, 5]);
    assert_eq!(*ref2, vec![1, 2, 3, 4, 5]);

    Ok(())
}

#[test]
fn test_map_arc_preservation() -> Result<()> {
    // Create a map
    let mut map = HashMap::new();
    map.insert("key1".to_string(), "value1".to_string());
    map.insert("key2".to_string(), "value2".to_string());

    let mut value = ArcValue::new_map(map);

    // Get references
    let ref1 = value.as_map_ref::<String, String>()?;
    let ref2 = value.as_map_ref::<String, String>()?;

    // Verify identity
    assert!(Arc::ptr_eq(&ref1, &ref2));

    // Verify content
    assert_eq!(ref1.len(), 2);
    assert_eq!(ref1.get("key1"), Some(&"value1".to_string()));
    assert_eq!(ref1.get("key2"), Some(&"value2".to_string()));

    assert_eq!(ref2.len(), 2);
    assert_eq!(ref2.get("key1"), Some(&"value1".to_string()));
    assert_eq!(ref2.get("key2"), Some(&"value2".to_string()));

    // Let's check serialization
    let registry = create_test_registry();
    let bytes = registry.serialize_value(&value)?;
    let mut value_from_bytes = registry.deserialize_value(bytes)?;
    let ref3 = value_from_bytes.as_map_ref::<String, String>()?;
    assert_eq!(ref3.len(), 2);
    assert_eq!(ref3.get("key1"), Some(&"value1".to_string()));
    assert_eq!(ref3.get("key2"), Some(&"value2".to_string()));

    Ok(())
}

#[test]
fn test_struct_arc_preservation() -> Result<()> {
    // Create a struct
    let test_struct = TestStruct {
        field1: "Hello".to_string(),
        field2: 42,
    };

    let mut value = ArcValue::from_struct(test_struct.clone());

    // Get references
    let ref1 = value.as_struct_ref::<TestStruct>()?;
    let ref2 = value.as_struct_ref::<TestStruct>()?;

    // Verify identity
    assert!(Arc::ptr_eq(&ref1, &ref2));

    // Verify content
    assert_eq!(*ref1, test_struct);
    assert_eq!(*ref2, test_struct);

    assert_eq!(ref1.field1, "Hello");
    assert_eq!(ref1.field2, 42);

    // No need to test serialization here - we'll do that in a separate test
    Ok(())
}

#[test]
fn test_struct_serialization() -> Result<()> {
    // Create test struct
    let test_struct = TestStruct {
        field1: "Hello".to_string(),
        field2: 42,
    };

    // Create a registry
    let registry = create_test_registry();

    // First, directly create an ArcValue from the struct
    let value = ArcValue::from_struct(test_struct.clone());

    // Manually serialize it
    let serialized_bytes = registry.serialize_value(&value)?;

    // Now we should be able to deserialize it back
    let mut deserialized_value = registry.deserialize_value(serialized_bytes)?;

    // Extract to validate - if this fails, our test failure is in the right place
    let deserialized_struct = deserialized_value.as_struct_ref::<TestStruct>()?;

    // Verify the deserialized content
    assert_eq!(deserialized_struct.field1, "Hello");
    assert_eq!(deserialized_struct.field2, 42);

    //again
    let deserialized_struct = deserialized_value.as_struct_ref::<TestStruct>()?;
    assert_eq!(deserialized_struct.field1, "Hello");
    assert_eq!(deserialized_struct.field2, 42);

    Ok(())
}

#[test]
fn test_nested() -> Result<()> {
    // Create a map
    let mut map = HashMap::new();
    map.insert(
        "key1".to_string(),
        ArcValue::new_primitive("value1".to_string()),
    );
    map.insert(
        "key2".to_string(),
        ArcValue::new_primitive("value2".to_string()),
    );

    let mut value = ArcValue::new_map(map);

    // Get references
    let ref1 = value.as_map_ref::<String, ArcValue>()?;
    let ref2 = value.as_map_ref::<String, ArcValue>()?;

    // Verify identity
    assert!(Arc::ptr_eq(&ref1, &ref2));

    // Verify content
    assert_eq!(ref1.len(), 2);
    let mut key1_value = ref1.get("key1").unwrap().to_owned();
    let mut key2_value = ref1.get("key2").unwrap().to_owned();
    assert_eq!(key1_value.as_type::<String>()?, "value1");
    assert_eq!(key2_value.as_type::<String>()?, "value2");

    assert_eq!(ref2.len(), 2);
    let mut key1_value = ref2.get("key1").unwrap().to_owned();
    let mut key2_value = ref2.get("key2").unwrap().to_owned();
    assert_eq!(key1_value.as_type::<String>()?, "value1");
    assert_eq!(key2_value.as_type::<String>()?, "value2");

    Ok(())
}

#[test]
fn test_json_serialization_support() -> Result<()> {
    // 1. Test direct serialization of a struct with `serde::Serialize`
    let test_struct = TestStruct {
        field1: "hello".to_string(),
        field2: 123,
    };
    let mut avt_struct = ArcValue::from_struct(test_struct.clone());
    let json_from_struct = avt_struct.to_json_value()?;
    assert_eq!(
        json_from_struct,
        json!({ "field1": "hello", "field2": 123 })
    );

    let json_from_struct = avt_struct.as_type::<serde_json::Value>()?;
    assert_eq!(
        json_from_struct,
        json!({ "field1": "hello", "field2": 123 })
    );

    // 2. Test direct serialization of a primitive
    let mut avt_primitive = ArcValue::new_primitive("hello".to_string());
    let json_from_primitive = avt_primitive.to_json_value()?;
    assert_eq!(json_from_primitive, json!("hello"));

    // 3. Test direct serialization of a list
    let mut avt_list = ArcValue::new_list(vec![1, 2, 3]);
    let json_from_list = avt_list.to_json_value()?;
    assert_eq!(json_from_list, json!([1, 2, 3]));

    // 4. Test direct serialization of a map
    let mut map = HashMap::new();
    map.insert("key1".to_string(), "value1".to_string());
    map.insert("key2".to_string(), "value2".to_string());
    let mut avt_map = ArcValue::new_map(map);
    let json_from_map = avt_map.to_json_value()?;
    assert_eq!(json_from_map, json!({ "key1": "value1", "key2": "value2" }));

    // 5. Test from_json_value for a struct
    let json_struct = json!({ "field1": "hello", "field2": 123 });
    let mut avt_from_json = ArcValue::from_json(json_struct)?;
    let struct_from_json = avt_from_json.as_struct_ref::<TestStruct>()?;
    assert_eq!(struct_from_json.field1, "hello");
    assert_eq!(struct_from_json.field2, 123);

    // 6. Test from_json_value for a primitive
    let json_primitive = json!("hello");
    let mut avt_from_json = ArcValue::from_json(json_primitive)?;
    let primitive_from_json: String = avt_from_json.as_type()?;
    assert_eq!(primitive_from_json, "hello");

    // 7. Test from_json_value for a list
    let json_list = json!([1, 2, 3]);
    let mut avt_from_json = ArcValue::from_json(json_list)?;
    let list_from_json = avt_from_json.as_list_ref::<i64>()?;
    assert_eq!(*list_from_json, vec![1, 2, 3]);

    // 8. Test from_json_value for a map
    let json_map = json!({ "key1": "value1", "key2": "value2" });
    let mut avt_from_json = ArcValue::from_json(json_map)?;
    let map_from_json = avt_from_json.as_map_ref::<String, String>()?;
    assert_eq!(map_from_json.get("key1"), Some(&"value1".to_string()));
    assert_eq!(map_from_json.get("key2"), Some(&"value2".to_string()));

    Ok(())
}

#[test]
fn test_map_of_struts_serialization() -> Result<()> {
    // Create a map of structs
    let mut map = HashMap::new();
    map.insert(
        "struct1".to_string(),
        TestStruct {
            field1: "hello1".to_string(),
            field2: 123,
        },
    );
    map.insert(
        "struct2".to_string(),
        TestStruct {
            field1: "hello2".to_string(),
            field2: 456,
        },
    );

    let mut value = ArcValue::new_map(map);

    // Create a registry
    let registry = create_test_registry();

    // Serialize
    let serialized_bytes = registry.serialize_value(&value)?;

    // Deserialize
    let mut deserialized_value = registry.deserialize_value(serialized_bytes)?;

    // Extract and validate
    let deserialized_map = deserialized_value.as_map_ref::<String, TestStruct>()?;

    assert_eq!(deserialized_map.len(), 2);
    assert_eq!(deserialized_map.get("struct1").unwrap().field1, "hello1");
    assert_eq!(deserialized_map.get("struct1").unwrap().field2, 123);
    assert_eq!(deserialized_map.get("struct2").unwrap().field1, "hello2");
    assert_eq!(deserialized_map.get("struct2").unwrap().field2, 456);

    Ok(())
}

#[test]
fn test_type_mismatch_errors() -> Result<()> {
    // Create a value with a string
    let mut value = ArcValue::new_primitive("Hello, world!".to_string());

    // Try to get it as a number - this should fail
    let result: Result<i32> = value.as_type();
    assert!(result.is_err());

    // Try to get it as a list - this should fail
    let result: Result<Vec<String>> = value.as_list_ref();
    assert!(result.is_err());

    // Try to get it as a map - this should fail
    let result: Result<HashMap<String, String>> = value.as_map_ref();
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_null_value() -> Result<()> {
    let null_value = ArcValue::null();
    assert_eq!(null_value.category, ValueCategory::Null);
    Ok(())
}

#[test]
fn test_primitive_cloning() -> Result<()> {
    // Create a value with a string
    let mut original_value = ArcValue::new_primitive("Hello, world!".to_string());
    let mut cloned_value = original_value.clone();

    // Verify they have the same content
    let original_string: String = original_value.as_type()?;
    let cloned_string: String = cloned_value.as_type()?;
    assert_eq!(original_string, cloned_string);

    // Verify they are different Arc instances (cloned, not shared)
    let original_ref = original_value.as_type_ref::<String>()?;
    let cloned_ref = cloned_value.as_type_ref::<String>()?;
    assert!(!Arc::ptr_eq(&original_ref, &cloned_ref));

    Ok(())
}

#[test]
fn test_registry_with_defaults() -> Result<()> {
    let registry = SerializerRegistry::with_defaults(Arc::new(Logger::new_root(
        Component::Custom("Test"),
        "test-node",
    )));

    // Test that we can serialize and deserialize a simple string
    let value = ArcValue::new_primitive("Hello, world!".to_string());
    let bytes = registry.serialize_value(&value)?;
    let mut deserialized_value = registry.deserialize_value(bytes)?;
    let deserialized_string: String = deserialized_value.as_type()?;
    assert_eq!(deserialized_string, "Hello, world!");

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MyStruct {
    id: i64,
    name: String,
    active: bool,
}

#[test]
fn test_from_json_null() {
    let json_value = json!(null);
    let result = ArcValue::from_json(json_value);
    assert!(result.is_ok());
    let arc_value = result.unwrap();
    assert_eq!(arc_value.category, ValueCategory::Null);
}

#[test]
fn test_from_json_bool() {
    let json_value = json!(true);
    let result = ArcValue::from_json(json_value);
    assert!(result.is_ok());
    let mut arc_value = result.unwrap();
    let bool_value: bool = arc_value.as_type().unwrap();
    assert_eq!(bool_value, true);
}

#[test]
fn test_from_json_number_int() {
    let json_value = json!(42);
    let result = ArcValue::from_json(json_value);
    assert!(result.is_ok());
    let mut arc_value = result.unwrap();
    let int_value: i64 = arc_value.as_type().unwrap();
    assert_eq!(int_value, 42);
}

#[test]
fn test_from_json_number_float() {
    let json_value = json!(3.14);
    let result = ArcValue::from_json(json_value);
    assert!(result.is_ok());
    let mut arc_value = result.unwrap();
    let float_value: f64 = arc_value.as_type().unwrap();
    assert_eq!(float_value, 3.14);
}

#[test]
fn test_from_json_string() {
    let json_value = json!("hello");
    let result = ArcValue::from_json(json_value);
    assert!(result.is_ok());
    let mut arc_value = result.unwrap();
    let string_value: String = arc_value.as_type().unwrap();
    assert_eq!(string_value, "hello");
}

#[test]
fn test_from_json_array() {
    let json_value = json!([1, 2, 3]);
    let result = ArcValue::from_json(json_value);
    assert!(result.is_ok());
    let mut arc_value = result.unwrap();
    let list_value = arc_value.as_list_ref::<i64>().unwrap();
    assert_eq!(*list_value, vec![1, 2, 3]);
}

#[test]
fn test_from_json_object_to_map_moved() {
    let json_value = json!({
        "key1": "value1",
        "key2": "value2"
    });
    let result = ArcValue::from_json(json_value);
    assert!(result.is_ok());
    let mut arc_value = result.unwrap();
    let map_value = arc_value.as_map_ref::<String, String>().unwrap();
    assert_eq!(map_value.get("key1"), Some(&"value1".to_string()));
    assert_eq!(map_value.get("key2"), Some(&"value2".to_string()));
}

#[test]
fn test_from_json_object_to_struct_moved() {
    let json_value = json!({
        "id": 123,
        "name": "test",
        "active": true
    });
    let result = ArcValue::from_json(json_value);
    assert!(result.is_ok());
    let mut arc_value = result.unwrap();
    let struct_value = arc_value.as_struct_ref::<MyStruct>().unwrap();
    assert_eq!(struct_value.id, 123);
    assert_eq!(struct_value.name, "test");
    assert_eq!(struct_value.active, true);
}

#[test]
fn test_from_json_object_to_struct_list_moved() {
    let json_value = json!([
        {"id": 1, "name": "item1", "active": true},
        {"id": 2, "name": "item2", "active": false}
    ]);
    let result = ArcValue::from_json(json_value);
    assert!(result.is_ok());
    let mut arc_value = result.unwrap();
    let list_value = arc_value.as_list_ref::<MyStruct>().unwrap();
    assert_eq!(list_value.len(), 2);
    assert_eq!(list_value[0].id, 1);
    assert_eq!(list_value[0].name, "item1");
    assert_eq!(list_value[0].active, true);
    assert_eq!(list_value[1].id, 2);
    assert_eq!(list_value[1].name, "item2");
    assert_eq!(list_value[1].active, false);
}
