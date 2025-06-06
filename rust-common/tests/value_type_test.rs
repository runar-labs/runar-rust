use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use bincode;
use runar_common::logging::{Component, Logger};
use runar_common::types::{ArcValueType, SerializerRegistry};
use serde::{Deserialize, Serialize};

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
    let mut value = ArcValueType::new_primitive(string_value);

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
    let mut value = ArcValueType::new_list(list);

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

    let mut value = ArcValueType::new_map(map);

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

    let mut value = ArcValueType::from_struct(test_struct.clone());

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

    // First, directly create an ArcValueType from the struct
    let value = ArcValueType::from_struct(test_struct.clone());

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
        ArcValueType::new_primitive("value1".to_string()),
    );
    map.insert(
        "key2".to_string(),
        ArcValueType::new_primitive("value2".to_string()),
    );

    let mut value = ArcValueType::new_map(map);

    // Get references
    let ref1 = value.as_map_ref::<String, ArcValueType>()?;
    let ref2 = value.as_map_ref::<String, ArcValueType>()?;

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
    let _ = registry.register::<HashMap<String, ArcValueType>>();

    // let bytes = registry.serialize_value(&value)?;
    // let mut value_from_bytes = registry.deserialize_value(bytes)?;
    // let ref3 = value_from_bytes.as_map_ref::<String, ArcValueType>()?;

    // assert_eq!(ref3.len(), 2);
    // let mut key1_value = ref3.get("key1").unwrap().to_owned();
    // let mut key2_value = ref3.get("key2").unwrap().to_owned();
    // assert_eq!(key1_value.as_type::<String>()?, "value1");
    // assert_eq!(key2_value.as_type::<String>()?, "value2");

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

    let mut value = ArcValueType::new_map(map.clone());
    println!("Created ArcValueType, category: {:?}", value.category);

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
    let mut value = ArcValueType::new_primitive("Hello, world!".to_string());

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
    let value = ArcValueType::null();
    assert!(value.is_null());

    Ok(())
}

#[test]
fn test_primitive_cloning() -> Result<()> {
    // Test that as_type (not as_type_ref) does clone the value
    let string_value = "Hello, world!".to_string();
    let mut value = ArcValueType::new_primitive(string_value);

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
    let value = ArcValueType::new_primitive(42i32);
    let bytes = registry.serialize_value(&value)?;
    let mut value_from_bytes = registry.deserialize_value(bytes)?;
    let num: i32 = value_from_bytes.as_type()?;
    assert_eq!(num, 42);

    Ok(())
}
