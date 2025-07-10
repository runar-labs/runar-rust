use runar_serializer::{ArcValue, ValueCategory};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;

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
    assert!(arc_value.as_type::<bool>().unwrap());
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
    assert!(val2.as_type::<bool>().unwrap());
}

#[test]
fn test_from_json_object_to_map() {
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

#[derive(Clone, Serialize, Deserialize, Debug)]
struct MyStruct {
    id: i64,
    name: String,
    active: bool,
}

#[test]
fn test_from_json_object_to_struct() {
    let json_object = json!({ "id": 1, "name": "Test Struct", "active": true });
    let mut arc_value = ArcValue::from_json(json_object);
    assert_eq!(arc_value.category, ValueCategory::Json);
    let obj: MyStruct = arc_value.as_type::<MyStruct>().unwrap();
    assert_eq!(obj.id, 1);
    assert_eq!(obj.name, "Test Struct");
    assert!(obj.active);
}

#[test]
fn test_from_json_object_to_struct_list() {
    let json_object = json!([ { "id": 1, "name": "Test Struct", "active": true } ]);
    let mut arc_value = ArcValue::from_json(json_object);
    assert_eq!(arc_value.category, ValueCategory::List);
    let list: Vec<MyStruct> = arc_value.as_type::<Vec<MyStruct>>().unwrap();
    assert_eq!(list.len(), 1);
    let obj = list[0].clone();
    assert_eq!(obj.id, 1);
    assert_eq!(obj.name, "Test Struct");
    assert!(obj.active);
}
