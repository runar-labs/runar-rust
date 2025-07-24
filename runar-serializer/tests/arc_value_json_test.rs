use runar_serializer::{ArcValue, Plain};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Plain)]
struct TestStruct {
    id: i32,
    name: String,
    active: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Plain)]
struct NestedStruct {
    inner: TestStruct,
    count: i64,
}

#[test]
fn test_basic_primitives_to_json() {
    // Test all basic primitive types
    let string_val = ArcValue::new_primitive("hello world".to_string());
    let int_val = ArcValue::new_primitive(42i64);
    let float_val = ArcValue::new_primitive(3.14f64);
    let bool_val = ArcValue::new_primitive(true);
    let null_val = ArcValue::null();

    assert_eq!(string_val.to_json().unwrap(), json!("hello world"));
    assert_eq!(int_val.to_json().unwrap(), json!(42));
    assert_eq!(float_val.to_json().unwrap(), json!(3.14));
    assert_eq!(bool_val.to_json().unwrap(), json!(true));
    assert_eq!(null_val.to_json().unwrap(), json!(null));

    assert_eq!(string_val.as_type::<String>().unwrap(), "hello world");
    assert_eq!(int_val.as_type::<i64>().unwrap(), 42);
    assert_eq!(float_val.as_type::<f64>().unwrap(), 3.14);
    assert_eq!(bool_val.as_type::<bool>().unwrap(), true);
    
    let string_val_ser = string_val.serialize(None).expect("Failed to serialize string value");
    let int_val_ser = int_val.serialize(None).expect("Failed to serialize int value");
    let float_val_ser = float_val.serialize(None).expect("Failed to serialize float value");
    let bool_val_ser = bool_val.serialize(None).expect("Failed to serialize bool value");
    let null_val_ser = null_val.serialize(None).expect("Failed to serialize null value");

    let string_val_deser = ArcValue::deserialize(&string_val_ser, None).expect("Failed to deserialize string value");
    let int_val_deser = ArcValue::deserialize(&int_val_ser, None).expect("Failed to deserialize int value");
    let float_val_deser = ArcValue::deserialize(&float_val_ser, None).expect("Failed to deserialize float value");
    let bool_val_deser = ArcValue::deserialize(&bool_val_ser, None).expect("Failed to deserialize bool value");
    let null_val_deser = ArcValue::deserialize(&null_val_ser, None).expect("Failed to deserialize null value");

    assert_eq!(string_val_deser.to_json().unwrap(), json!("hello world"));
    assert_eq!(int_val_deser.to_json().unwrap(), json!(42));
    assert_eq!(float_val_deser.to_json().unwrap(), json!(3.14));
    assert_eq!(bool_val_deser.to_json().unwrap(), json!(true));
    assert_eq!(null_val_deser.to_json().unwrap(), json!(null));

    assert_eq!(string_val_deser.as_type::<String>().unwrap(), "hello world");
    assert_eq!(int_val_deser.as_type::<i64>().unwrap(), 42);
    assert_eq!(float_val_deser.as_type::<f64>().unwrap(), 3.14);
    assert_eq!(bool_val_deser.as_type::<bool>().unwrap(), true);
}

#[test]
fn test_lists_to_json() {
    // Test list of primitives
    let list_json = json!(["apple", "banana", 123, true]);
    let arc_value = ArcValue::from_json(list_json);

    let result = arc_value.to_json().unwrap();
    assert_eq!(result, json!(["apple", "banana", 123, true]));

    // lets get the values as primitives
    let arc_list = arc_value.as_type::<Vec<ArcValue>>().unwrap();
    assert_eq!(arc_list.len(), 4);
    assert_eq!(arc_list[0].as_type::<String>().unwrap(), "apple");
    assert_eq!(arc_list[1].as_type::<String>().unwrap(), "banana");
    assert_eq!(arc_list[2].as_type::<i64>().unwrap(), 123);
    assert_eq!(arc_list[3].as_type::<bool>().unwrap(), true);

    //lets test serialization and deserialization
    let list_json_ser = arc_value.serialize(None).expect("Failed to serialize list value");
    let list_json_deser = ArcValue::deserialize(&list_json_ser, None).expect("Failed to deserialize list value");
    assert_eq!(list_json_deser.to_json().unwrap(), json!(["apple", "banana", 123, true]));

    let arc_list = list_json_deser.as_type::<Vec<ArcValue>>().unwrap();
    assert_eq!(arc_list.len(), 4);
    assert_eq!(arc_list[0].as_type::<String>().unwrap(), "apple");
    assert_eq!(arc_list[1].as_type::<String>().unwrap(), "banana");
    assert_eq!(arc_list[2].as_type::<i64>().unwrap(), 123);
    assert_eq!(arc_list[3].as_type::<bool>().unwrap(), true);

     
    //lets start with a list as primitives
    let list_primitives = ArcValue::new_list(  vec![
        ArcValue::new_primitive("apple".to_string()),
        ArcValue::new_primitive("banana".to_string()),
        ArcValue::new_primitive(123i64),
        ArcValue::new_primitive(true),
    ]);

    //convert to json
    let list_json_primitives = list_primitives.to_json().unwrap();
    assert_eq!(list_json_primitives, json!(["apple", "banana", 123, true]));

}

#[test]
fn test_maps_to_json() {
    // Test map of primitives
    let map_json = json!({
        "key1": "value1",
        "key2": 123,
        "key3": true
    });
    let arc_value = ArcValue::from_json(map_json);

    let result = arc_value.to_json().unwrap();
    assert_eq!(result, json!({
        "key1": "value1",
        "key2": 123,
        "key3": true
    }));

    // lets get the values as primitives
    let arc_map = arc_value.as_type::<std::collections::HashMap<String, ArcValue>>().unwrap();
    assert_eq!(arc_map.len(), 3);
    assert_eq!(arc_map["key1"].as_type::<String>().unwrap(), "value1");
    assert_eq!(arc_map["key2"].as_type::<i64>().unwrap(), 123);
    assert_eq!(arc_map["key3"].as_type::<bool>().unwrap(), true);

    //lets test serialization and deserialization
    let map_json_ser = arc_value.serialize(None).expect("Failed to serialize map value");
    let map_json_deser = ArcValue::deserialize(&map_json_ser, None).expect("Failed to deserialize map value");
    assert_eq!(map_json_deser.to_json().unwrap(), json!({
        "key1": "value1",
        "key2": 123,
        "key3": true
    }));

    let arc_map = map_json_deser.as_type::<std::collections::HashMap<String, ArcValue>>().unwrap();
    assert_eq!(arc_map.len(), 3);
    assert_eq!(arc_map["key1"].as_type::<String>().unwrap(), "value1");
    assert_eq!(arc_map["key2"].as_type::<i64>().unwrap(), 123);
    assert_eq!(arc_map["key3"].as_type::<bool>().unwrap(), true);

     
    //lets start with a map as primitives
    let mut map_primitives = std::collections::HashMap::new();
    map_primitives.insert("key1".to_string(), ArcValue::new_primitive("value1".to_string()));
    map_primitives.insert("key2".to_string(), ArcValue::new_primitive(123i64));
    map_primitives.insert("key3".to_string(), ArcValue::new_primitive(true));
    let map_arc_value = ArcValue::new_map(map_primitives);

    //convert to json
    let map_json_primitives = map_arc_value.to_json().unwrap();
    assert_eq!(map_json_primitives, json!({
        "key1": "value1",
        "key2": 123,
        "key3": true
    }));
}

#[test]
fn test_nested_structures_to_json() {
    // Test nested structures
    let nested_json = json!({
        "list": [1, 2, 3],
        "map": {"a": "b", "c": "d"},
        "primitive": "test"
    });
    let arc_value = ArcValue::from_json(nested_json);

    let result = arc_value.to_json().unwrap();
    assert_eq!(result, json!({
        "list": [1, 2, 3],
        "map": {"a": "b", "c": "d"},
        "primitive": "test"
    }));

    // lets get the values as nested structures
    let arc_map = arc_value.as_type::<std::collections::HashMap<String, ArcValue>>().unwrap();
    assert_eq!(arc_map.len(), 3);
    
    // Test the list inside the map
    let nested_list = arc_map["list"].as_type::<Vec<ArcValue>>().unwrap();
    assert_eq!(nested_list.len(), 3);
    assert_eq!(nested_list[0].as_type::<i64>().unwrap(), 1);
    assert_eq!(nested_list[1].as_type::<i64>().unwrap(), 2);
    assert_eq!(nested_list[2].as_type::<i64>().unwrap(), 3);
    
    // Test the map inside the map
    let nested_map = arc_map["map"].as_type::<std::collections::HashMap<String, ArcValue>>().unwrap();
    assert_eq!(nested_map.len(), 2);
    assert_eq!(nested_map["a"].as_type::<String>().unwrap(), "b");
    assert_eq!(nested_map["c"].as_type::<String>().unwrap(), "d");
    
    // Test the primitive
    assert_eq!(arc_map["primitive"].as_type::<String>().unwrap(), "test");

    //lets test serialization and deserialization
    let nested_json_ser = arc_value.serialize(None).expect("Failed to serialize nested value");
    let nested_json_deser = ArcValue::deserialize(&nested_json_ser, None).expect("Failed to deserialize nested value");
    assert_eq!(nested_json_deser.to_json().unwrap(), json!({
        "list": [1, 2, 3],
        "map": {"a": "b", "c": "d"},
        "primitive": "test"
    }));

    let arc_map = nested_json_deser.as_type::<std::collections::HashMap<String, ArcValue>>().unwrap();
    assert_eq!(arc_map.len(), 3);
    
    // Test the list inside the map after deserialization
    let nested_list = arc_map["list"].as_type::<Vec<ArcValue>>().unwrap();
    assert_eq!(nested_list.len(), 3);
    assert_eq!(nested_list[0].as_type::<i64>().unwrap(), 1);
    assert_eq!(nested_list[1].as_type::<i64>().unwrap(), 2);
    assert_eq!(nested_list[2].as_type::<i64>().unwrap(), 3);
    
    // Test the map inside the map after deserialization
    let nested_map = arc_map["map"].as_type::<std::collections::HashMap<String, ArcValue>>().unwrap();
    assert_eq!(nested_map.len(), 2);
    assert_eq!(nested_map["a"].as_type::<String>().unwrap(), "b");
    assert_eq!(nested_map["c"].as_type::<String>().unwrap(), "d");
    
    // Test the primitive after deserialization
    assert_eq!(arc_map["primitive"].as_type::<String>().unwrap(), "test");

     
    //lets start with nested structures as primitives
    let nested_list = ArcValue::new_list(vec![
        ArcValue::new_primitive(1i64),
        ArcValue::new_primitive(2i64),
        ArcValue::new_primitive(3i64),
    ]);
    
    let mut nested_map = std::collections::HashMap::new();
    nested_map.insert("a".to_string(), ArcValue::new_primitive("b".to_string()));
    nested_map.insert("c".to_string(), ArcValue::new_primitive("d".to_string()));
    let nested_map_arc = ArcValue::new_map(nested_map);
    
    let mut outer_map = std::collections::HashMap::new();
    outer_map.insert("list".to_string(), nested_list);
    outer_map.insert("map".to_string(), nested_map_arc);
    outer_map.insert("primitive".to_string(), ArcValue::new_primitive("test".to_string()));
    let nested_arc_value = ArcValue::new_map(outer_map);

    //convert to json
    let nested_json_primitives = nested_arc_value.to_json().unwrap();
    assert_eq!(nested_json_primitives, json!({
        "list": [1, 2, 3],
        "map": {"a": "b", "c": "d"},
        "primitive": "test"
    }));
}

#[test]
fn test_custom_structs_to_json() {
    let test_struct = TestStruct {
        id: 1,
        name: "Test Struct".to_string(),
        active: true,
    };
    let arc_value = ArcValue::new_struct(test_struct);

    let result = arc_value.to_json().unwrap();
    assert_eq!(result, json!({
        "id": 1,
        "name": "Test Struct",
        "active": true
    }));

    // lets get the values as struct
    let arc_struct = arc_value.as_type::<TestStruct>().unwrap();
    assert_eq!(arc_struct.id, 1);
    assert_eq!(arc_struct.name, "Test Struct");
    assert_eq!(arc_struct.active, true);

    //lets test serialization and deserialization
    let struct_bytes = arc_value.serialize(None).expect("Failed to serialize struct value");
    let struct_deser = ArcValue::deserialize(&struct_bytes, None).expect("Failed to deserialize struct value");
    assert_eq!(struct_deser.to_json().unwrap(), json!({
        "id": 1,
        "name": "Test Struct",
        "active": true
    }));

    let arc_struct = struct_deser.as_type::<TestStruct>().unwrap();
    assert_eq!(arc_struct.id, 1);
    assert_eq!(arc_struct.name, "Test Struct");
    assert_eq!(arc_struct.active, true);
 
    // Test nested struct
    let nested_struct = NestedStruct {
        inner: TestStruct {
            id: 100,
            name: "Nested Inner".to_string(),
            active: true,
        },
        count: 999,
    };
    let nested_arc_value = ArcValue::new_struct(nested_struct);

    let nested_result = nested_arc_value.to_json().unwrap();
    assert_eq!(nested_result, json!({
        "inner": {
            "id": 100,
            "name": "Nested Inner",
            "active": true
        },
        "count": 999
    }));

    let arc_nested_struct = nested_arc_value.as_type::<NestedStruct>().unwrap();
    assert_eq!(arc_nested_struct.inner.id, 100);
    assert_eq!(arc_nested_struct.inner.name, "Nested Inner");
    assert_eq!(arc_nested_struct.inner.active, true);
    assert_eq!(arc_nested_struct.count, 999);

    // Test serialization and deserialization round-trip for nested struct
    let serialized = nested_arc_value.serialize(None).unwrap();
    let deserialized = ArcValue::deserialize(&serialized, None).unwrap();
    
    // Verify the deserialized nested struct maintains all data
    let deserialized_nested = deserialized.as_type::<NestedStruct>().unwrap();
    assert_eq!(deserialized_nested.inner.id, 100);
    assert_eq!(deserialized_nested.inner.name, "Nested Inner");
    assert_eq!(deserialized_nested.inner.active, true);
    assert_eq!(deserialized_nested.count, 999);
    
    // Verify JSON conversion still works after serialization/deserialization
    let deserialized_json = deserialized.to_json().unwrap();
    assert_eq!(deserialized_json, json!({
        "inner": {
            "id": 100,
            "name": "Nested Inner",
            "active": true
        },
        "count": 999
    }));
    
    // Test that the nested struct can be extracted as a reference
    let deserialized_nested_ref = deserialized.as_type_ref::<NestedStruct>().unwrap();
    assert_eq!(deserialized_nested_ref.inner.id, 100);
    assert_eq!(deserialized_nested_ref.inner.name, "Nested Inner");
    assert_eq!(deserialized_nested_ref.inner.active, true);
    assert_eq!(deserialized_nested_ref.count, 999);
}
