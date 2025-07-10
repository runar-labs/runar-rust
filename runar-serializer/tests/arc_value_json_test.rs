use runar_serializer::ArcValue;
use serde_json::json;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Person {
    name: String,
    age: u32,
}

#[test]
fn test_from_json_null() {
    let json_value = json!(null);
    let arc_value = ArcValue::from_json(json_value);
    assert_eq!(arc_value.category(), runar_serializer::ValueCategory::Null);
}

#[test]
fn test_from_json_string() {
    let json_value = json!("hello world");
    let mut arc_value = ArcValue::from_json(json_value);
    assert_eq!(arc_value.as_string().unwrap(), "hello world");
}

#[test]
fn test_from_json_number_int() {
    let json_value = json!(42);
    let mut arc_value = ArcValue::from_json(json_value);
    assert_eq!(arc_value.as_int().unwrap(), 42);
}

#[test]
fn test_from_json_number_float() {
    let json_value = json!(3.14);
    let mut arc_value = ArcValue::from_json(json_value);
    assert_eq!(arc_value.as_float().unwrap(), 3.14);
}

#[test]
fn test_from_json_bool() {
    let json_value = json!(true);
    let mut arc_value = ArcValue::from_json(json_value);
    let bool_value = arc_value.as_bool().unwrap();
    assert!(bool_value);
}

#[test]
fn test_from_json_array() {
    let json_value = json!([1, 2, 3]);
    let mut arc_value = ArcValue::from_json(json_value);
    let list = arc_value.as_list().unwrap();
    assert_eq!(list.len(), 3);
    let mut v0 = list[0].clone();
    let mut v1 = list[1].clone();
    let mut v2 = list[2].clone();
    assert_eq!(v0.as_int().unwrap(), 1);
    assert_eq!(v1.as_int().unwrap(), 2);
    assert_eq!(v2.as_int().unwrap(), 3);
}

#[test]
fn test_from_json_object_to_map() {
    let json_value = json!({"key1": "value1", "key2": "value2"});
    let mut arc_value = ArcValue::from_json(json_value);
    let mut map = arc_value.as_map().unwrap();
    assert_eq!(map.len(), 2);
    let mut v1 = map.get_mut("key1").unwrap().clone();
    let mut v2 = map.get_mut("key2").unwrap().clone();
    assert_eq!(v1.as_string().unwrap(), "value1");
    assert_eq!(v2.as_string().unwrap(), "value2");
}

#[test]
fn test_from_json_object_to_struct() {
    let json_value = json!({"name": "John", "age": 30});
    let mut arc_value = ArcValue::from_json(json_value);
    let mut map = arc_value.as_map().unwrap();
    assert_eq!(map.len(), 2);
    let mut name_val = map.get_mut("name").unwrap().clone();
    let mut age_val = map.get_mut("age").unwrap().clone();
    assert_eq!(name_val.as_string().unwrap(), "John");
    assert_eq!(age_val.as_int().unwrap(), 30);
}

#[test]
fn test_from_json_array_complex() {
    let json_value = json!([{"name": "Alice"}, {"name": "Bob"}]);
    let mut arc_value = ArcValue::from_json(json_value);
    let list = arc_value.as_list().unwrap();
    assert_eq!(list.len(), 2);

    let mut alice_map_val = list[0].clone();
    let alice_map = alice_map_val.as_map().unwrap();
    let mut name_val = alice_map.get("name").unwrap().clone();
    assert_eq!(name_val.as_string().unwrap(), "Alice");

    let mut bob_map_val = list[1].clone();
    let bob_map = bob_map_val.as_map().unwrap();
    let mut bob_name = bob_map.get("name").unwrap().clone();
    assert_eq!(bob_name.as_string().unwrap(), "Bob");
}

#[test]
fn test_from_json_object_to_struct_list() {
    let json_value = json!({
        "users": [
            {"name": "Alice", "age": 25},
            {"name": "Bob", "age": 30}
        ]
    });
    let mut arc_value = ArcValue::from_json(json_value);
    let mut map = arc_value.as_map().unwrap();
    let mut users_val = map.get_mut("users").unwrap().clone();
    let users = users_val.as_list().unwrap();

    assert_eq!(users.len(), 2);
    let mut user0 = users[0].clone();
    let user0_map = user0.as_map().unwrap();
    let mut u0_name = user0_map.get("name").unwrap().clone();
    let mut u0_age = user0_map.get("age").unwrap().clone();
    assert_eq!(u0_name.as_string().unwrap(), "Alice");
    assert_eq!(u0_age.as_int().unwrap(), 25);

    let mut user1 = users[1].clone();
    let user1_map = user1.as_map().unwrap();
    let mut u1_name = user1_map.get("name").unwrap().clone();
    let mut u1_age = user1_map.get("age").unwrap().clone();
    assert_eq!(u1_name.as_string().unwrap(), "Bob");
    assert_eq!(u1_age.as_int().unwrap(), 30);
}

#[test]
fn test_json_roundtrip() {
    // Test that we can convert from JSON to ArcValue and back
    let original_json = json!({
        "string": "hello",
        "number": 42,
        "boolean": true,
        "array": [1, 2, 3],
        "object": {"nested": "value"}
    });

    let mut arc_value = ArcValue::from_json(original_json.clone());
    let roundtrip_json = arc_value.to_json_value().unwrap();

    assert_eq!(original_json, roundtrip_json);
}

#[test]
fn test_json_lazy_conversion() {
    // Test that JSON objects are converted lazily
    let json_value = json!({"name": "Alice", "age": 25});
    let mut arc_value = ArcValue::from_json(json_value);

    // Initially should be Json category
    assert_eq!(arc_value.category(), runar_serializer::ValueCategory::Json);

    // After accessing as map, should become Map category
    let mut map = arc_value.as_map().unwrap();
    assert_eq!(arc_value.category(), runar_serializer::ValueCategory::Map);
    let mut name_val = map.get_mut("name").unwrap().clone();
    let mut age_val = map.get_mut("age").unwrap().clone();
    assert_eq!(name_val.as_string().unwrap(), "Alice");
    assert_eq!(age_val.as_int().unwrap(), 25);
}

#[test]
fn test_json_array_lazy_conversion() {
    // Test that JSON arrays are converted lazily
    let json_value = json!([1, 2, 3]);
    let mut arc_value = ArcValue::from_json(json_value);

    // Initially should be Json category
    assert_eq!(arc_value.category(), runar_serializer::ValueCategory::Json);

    // After accessing as list, should become List category
    let list = arc_value.as_list().unwrap();
    assert_eq!(arc_value.category(), runar_serializer::ValueCategory::List);
    assert_eq!(list.len(), 3);
    let mut v0 = list[0].clone();
    let mut v1 = list[1].clone();
    let mut v2 = list[2].clone();
    assert_eq!(v0.as_int().unwrap(), 1);
    assert_eq!(v1.as_int().unwrap(), 2);
    assert_eq!(v2.as_int().unwrap(), 3);
}

#[test]
fn test_json_primitive_lazy_conversion() {
    // Test that JSON primitives are converted lazily
    let json_value = json!("hello world");
    let mut arc_value = ArcValue::from_json(json_value);

    // Initially should be Json category
    assert_eq!(arc_value.category(), runar_serializer::ValueCategory::Json);

    // After accessing as string, should become Primitive category
    let string_value = arc_value.as_string().unwrap();
    assert_eq!(
        arc_value.category(),
        runar_serializer::ValueCategory::Primitive
    );
    assert_eq!(string_value, "hello world");
}

#[test]
fn test_json_to_custom_struct_lazy() {
    // Prepare JSON representing our custom struct
    let json_value = json!({"name": "Charlie", "age": 28});

    // Create ArcValue lazily (category = Json)
    let mut arc_value = ArcValue::from_json(json_value);
    assert_eq!(arc_value.category(), runar_serializer::ValueCategory::Json);

    // Convert lazily to Person struct
    let person: Person = arc_value.as_type().unwrap();
    assert_eq!(person.name, "Charlie");
    assert_eq!(person.age, 28);

    // Category should now be Struct and repeated access should use cached value
    assert_eq!(
        arc_value.category(),
        runar_serializer::ValueCategory::Struct
    );
    let person_ref = arc_value.as_type_ref::<Person>().unwrap();
    assert_eq!(person_ref.name, "Charlie");
    assert_eq!(person_ref.age, 28);
}
