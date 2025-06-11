use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use runar_common::logging::{Component, Logger};
use runar_common::types::{ArcValue, SerializerRegistry, ValueCategory};
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

    // // Make sure TestStru
    // Explicitly register HashMap<String, String> for map tests
    registry.register_map::<String, String>().unwrap();

    registry.register_map::<String, TestStruct>().unwrap();

    // Make sure all registrations are done before any serialization
    println!("Test registry initialized with TestStruct and map types");

    registry
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct TestStruct {
    field1: String,
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

    // Let's check serialization
    let mut registry = create_test_registry();
    let _ = registry.register::<HashMap<String, ArcValue>>();

    // let bytes = registry.serialize_value(&value)?;
    // let mut value_from_bytes = registry.deserialize_value(bytes)?;
    // let ref3 = value_from_bytes.as_map_ref::<String, ArcValue>()?;

    // assert_eq!(ref3.len(), 2);
    // let mut key1_value = ref3.get("key1").unwrap().to_owned();
    // let mut key2_value = ref3.get("key2").unwrap().to_owned();
    // assert_eq!(key1_value.as_type::<String>()?, "value1");
    // assert_eq!(key2_value.as_type::<String>()?, "value2");

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

    // 2. Test a primitive type
    let mut avt_primitive = ArcValue::new_primitive(42i64);
    let json_from_primitive = avt_primitive.to_json_value()?;
    assert_eq!(json_from_primitive, json!(42));

    // 3. Test Bytes serialization (base64)
    let bytes_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let mut avt_bytes = ArcValue::new_bytes(bytes_data.clone());
    let json_from_bytes = avt_bytes.to_json_value()?;
    assert_eq!(json_from_bytes, json!(STANDARD.encode(&bytes_data)));

    // 4. Test a list of serializable types
    let list_of_avt = vec![
        ArcValue::new_primitive(100i64),
        ArcValue::from_struct(test_struct.clone()),
        ArcValue::new_primitive(true),
    ];
    let mut avt_list = ArcValue::new_list(list_of_avt);
    let json_from_list = avt_list.to_json_value()?;
    assert_eq!(
        json_from_list,
        json!([100, { "field1": "hello", "field2": 123 }, true])
    );

    // 5. Test a map of serializable types
    let mut map_of_avt = HashMap::new();
    map_of_avt.insert("num".to_string(), ArcValue::new_primitive(99i64));
    map_of_avt.insert("struct".to_string(), ArcValue::from_struct(test_struct));
    let mut avt_map = ArcValue::new_map(map_of_avt);
    let json_from_map = avt_map.to_json_value()?;
    assert_eq!(
        json_from_map,
        json!({
            "num": 99,
            "struct": { "field1": "hello", "field2": 123 }
        })
    );

    Ok(())
}

#[test]
fn test_map_of_struts_serialization() -> Result<()> {
    // Create a map
    let mut map = HashMap::new();

    let test_struct1 = TestStruct {
        field1: "Hello".to_string(),
        field2: 42,
    };
    map.insert("key1".to_string(), test_struct1.clone());

    let test_struct2 = TestStruct {
        field1: "World".to_string(),
        field2: 100,
    };
    map.insert("key2".to_string(), test_struct2.clone());

    println!("Created test map with structs");

    let mut value = ArcValue::new_map(map.clone());
    println!("Created ArcValue, category: {:?}", value.category);

    // Get references
    let ref1 = value.as_map_ref::<String, TestStruct>()?;
    println!("Successfully got ref1");

    let ref2 = value.as_map_ref::<String, TestStruct>()?;
    println!("Successfully got ref2");

    // Verify identity
    assert!(Arc::ptr_eq(&ref1, &ref2));
    println!("Identity verified");

    // Verify content
    assert_eq!(ref1.len(), 2);
    assert_eq!(ref1.get("key1"), Some(&test_struct1));
    assert_eq!(ref1.get("key2"), Some(&test_struct2));
    println!("Content verified for ref1");

    assert_eq!(ref2.len(), 2);
    assert_eq!(ref2.get("key1"), Some(&test_struct1));
    assert_eq!(ref2.get("key2"), Some(&test_struct2));
    println!("Content verified for ref2");

    // Let's check serialization
    let registry = create_test_registry();
    println!("Created registry");

    // Print registered deserializers
    println!("REGISTERED DESERIALIZERS:");
    registry.debug_print_deserializers();

    let bytes = registry.serialize_value(&value)?;
    println!("Serialized value, {} bytes", bytes.len());

    let mut value_from_bytes = registry.deserialize_value(bytes)?;
    println!(
        "Deserialized value, category: {:?}",
        value_from_bytes.category
    );

    let ref3 = value_from_bytes.as_map_ref::<String, TestStruct>()?;
    println!("Successfully got ref3");

    assert_eq!(ref3.len(), 2);
    assert_eq!(ref3.get("key1"), Some(&test_struct1));
    assert_eq!(ref3.get("key2"), Some(&test_struct2));
    println!("Content verified for ref3");

    Ok(())
}

#[test]
fn test_type_mismatch_errors() -> Result<()> {
    // Create a value with a string
    let mut value = ArcValue::new_primitive("Hello, world!".to_string());

    // Try to get it as an integer - should fail
    let result = value.as_type_ref::<i32>();
    assert!(result.is_err());

    // Try to get it as a list - should fail
    let result = value.as_list_ref::<String>();
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_null_value() -> Result<()> {
    let value = ArcValue::null();
    assert!(value.is_null());

    Ok(())
}

#[test]
fn test_primitive_cloning() -> Result<()> {
    // Test that as_type (not as_type_ref) does clone the value
    let string_value = "Hello, world!".to_string();
    let mut value = ArcValue::new_primitive(string_value);

    // Get a cloned value
    let cloned_value: String = value.as_type()?;

    // Verify it's a clone, not the original
    let ref_value = value.as_type_ref::<String>()?;
    assert_eq!(cloned_value, *ref_value);

    // Modifying the clone should not affect the original
    let mut cloned_value = cloned_value;
    cloned_value.push_str(" Modified");

    // Original should remain unchanged
    let ref_value = value.as_type_ref::<String>()?;
    assert_eq!(&*ref_value, "Hello, world!");
    assert_eq!(cloned_value, "Hello, world! Modified");

    let registry = create_test_registry();
    //serialize and deserialize
    let serialized_bytes = registry.serialize_value(&value)?;
    let mut value_from_bytes = registry.deserialize_value(serialized_bytes)?;
    let ref_value = value_from_bytes.as_type_ref::<String>()?;
    assert_eq!(&*ref_value, "Hello, world!");
    Ok(())
}

#[test]
fn test_registry_with_defaults() -> Result<()> {
    // Create a registry with defaults
    let registry = SerializerRegistry::with_defaults(Arc::new(Logger::new_root(
        Component::Custom("Test"),
        "test-node",
    )));

    // Test serialization and deserialization of a primitive
    let value = ArcValue::new_primitive(42i32);
    let bytes = registry.serialize_value(&value)?;
    let mut value_from_bytes = registry.deserialize_value(bytes)?;
    let num: i32 = value_from_bytes.as_type()?;
    assert_eq!(num, 42);

    Ok(())
}

// ---------------- Tests moved from src/types/arc_value_test.rs ----------------

#[derive(Clone, Serialize, Deserialize, Debug)]
struct MyStruct {
    id: i64,
    name: String,
    active: bool,
}

#[test]
fn test_from_json_null() {
    let json_null = json!(null);
    let arc_value = ArcValue::from_json(json_null);
    assert!(arc_value.is_null());
}

#[test]
fn test_from_json_bool() {
    let json_bool = json!(true);
    let mut arc_value = ArcValue::from_json(json_bool);
    assert_eq!(arc_value.as_type::<bool>().unwrap(), true);
}

#[test]
fn test_from_json_number_int() {
    let json_int = json!(123);
    let mut arc_value = ArcValue::from_json(json_int);
    assert_eq!(arc_value.as_type::<i64>().unwrap(), 123);
}

#[test]
fn test_from_json_number_float() {
    let json_float = json!(123.45);
    let mut arc_value = ArcValue::from_json(json_float);
    assert_eq!(arc_value.as_type::<f64>().unwrap(), 123.45);
}

#[test]
fn test_from_json_string() {
    let json_string = json!("hello");
    let mut arc_value = ArcValue::from_json(json_string);
    assert_eq!(arc_value.as_type::<String>().unwrap(), "hello".to_string());
}

#[test]
fn test_from_json_array() {
    let json_array = json!([1, "test", true]);
    let mut arc_value = ArcValue::from_json(json_array);
    assert_eq!(arc_value.category, ValueCategory::List);
    let list = arc_value.as_type::<Vec<ArcValue>>().unwrap();
    assert_eq!(list.len(), 3);

    let mut val0 = list[0].clone();
    assert_eq!(val0.as_type::<i64>().unwrap(), 1);

    let mut val1 = list[1].clone();
    assert_eq!(val1.as_type::<String>().unwrap(), "test".to_string());

    let mut val2 = list[2].clone();
    assert_eq!(val2.as_type::<bool>().unwrap(), true);
}

#[test]
fn test_from_json_object_to_map_moved() {
    let json_object = json!({ "key1": "value1", "key2": 123 });
    let mut arc_value = ArcValue::from_json(json_object);
    // Initially, JSON objects are represented lazily with category Json
    assert_eq!(arc_value.category, ValueCategory::Json);
    // Accessing as a HashMap triggers lazy conversion and updates the category to Map
    let map = arc_value.as_type::<HashMap<String, ArcValue>>().unwrap();
    assert_eq!(arc_value.category, ValueCategory::Map);
    assert_eq!(map.len(), 2);

    let mut val1 = map.get("key1").unwrap().clone();
    assert_eq!(val1.as_type::<String>().unwrap(), "value1".to_string());

    let mut val2 = map.get("key2").unwrap().clone();
    assert_eq!(val2.as_type::<i64>().unwrap(), 123);

    let payload = json!({ "message": "hello from gateway test" });
    let mut arc_value = ArcValue::from_json(payload);
    // Initially, JSON objects are represented lazily with category Json
    assert_eq!(arc_value.category, ValueCategory::Json);
    // Accessing as a HashMap triggers lazy conversion and updates the category to Map
    let map = arc_value.as_type::<HashMap<String, ArcValue>>().unwrap();
    assert_eq!(arc_value.category, ValueCategory::Map);
    assert_eq!(map.len(), 1);
    let mut message = map.get("message").unwrap().clone();
    assert_eq!(
        message.as_type::<String>().unwrap(),
        "hello from gateway test".to_string()
    );
}

#[test]
fn test_from_json_object_to_struct_moved() {
    let json_object = json!({ "id": 1, "name": "Test Struct", "active": true });
    let mut arc_value = ArcValue::from_json(json_object);
    assert_eq!(arc_value.category, ValueCategory::Json);
    let obj: MyStruct = arc_value.as_type::<MyStruct>().unwrap();
    assert_eq!(obj.id, 1);
    assert_eq!(obj.name, "Test Struct");
    assert_eq!(obj.active, true);
}

#[test]
fn test_from_json_object_to_struct_list_moved() {
    let json_object = json!([ { "id": 1, "name": "Test Struct", "active": true } ]);
    let mut arc_value = ArcValue::from_json(json_object);
    assert_eq!(arc_value.category, ValueCategory::List);
    let list: Vec<MyStruct> = arc_value.as_type::<Vec<MyStruct>>().unwrap();
    assert_eq!(list.len(), 1);
    let obj = list[0].clone();
    assert_eq!(obj.id, 1);
    assert_eq!(obj.name, "Test Struct");
    assert_eq!(obj.active, true);
}
