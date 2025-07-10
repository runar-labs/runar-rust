use runar_common::logging::{Component, Logger};
use runar_serializer::{ArcValue, SerializerRegistry};
use std::collections::HashMap;
use std::sync::Arc;

// Custom struct that follows the same rules as built-in types
#[derive(Clone, PartialEq, prost::Message, serde::Serialize, serde::Deserialize)]
pub struct MyCustomType {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(int32, tag = "2")]
    pub value: i32,
    #[prost(bool, tag = "3")]
    pub active: bool,
}

// Custom map type for String -> MyCustomType (equivalent to StringToIntMap pattern)
#[derive(Clone, PartialEq, prost::Message, serde::Serialize, serde::Deserialize)]
pub struct StringToMyCustomTypeMap {
    #[prost(map = "string, message", tag = "1")]
    pub entries: HashMap<String, MyCustomType>,
}

impl StringToMyCustomTypeMap {
    pub fn from_hashmap(map: HashMap<String, MyCustomType>) -> Self {
        Self { entries: map }
    }

    pub fn into_hashmap(self) -> HashMap<String, MyCustomType> {
        self.entries
    }
}

// Custom vector type for Vec<HashMap<String, MyCustomType>>
#[derive(Clone, PartialEq, prost::Message, serde::Serialize, serde::Deserialize)]
pub struct VecHashMapStringMyCustomType {
    #[prost(message, repeated, tag = "1")]
    pub entries: Vec<StringToMyCustomTypeMap>,
}

impl VecHashMapStringMyCustomType {
    pub fn from_vec_hashmap(vec: Vec<HashMap<String, MyCustomType>>) -> Self {
        let entries = vec
            .into_iter()
            .map(|map| StringToMyCustomTypeMap::from_hashmap(map))
            .collect();
        Self { entries }
    }

    pub fn into_vec_hashmap(self) -> Vec<HashMap<String, MyCustomType>> {
        self.entries
            .into_iter()
            .map(|map_type| map_type.into_hashmap())
            .collect()
    }
}

#[test]
fn test_direct_hashmap_serialization() {
    // Create a logger
    let logger = Arc::new(Logger::new_root(Component::System, "direct-hashmap-test"));
    // Create a serializer registry
    let registry = SerializerRegistry::new(logger);
    // Create test data: HashMap<String, String> directly
    let mut map1 = HashMap::new();
    map1.insert("key1".to_string(), "value1".to_string());
    map1.insert("key2".to_string(), "value2".to_string());
    // Wrap directly in ArcValue - no conversion needed
    let arc_value = ArcValue::from_struct(map1.clone());
    // Serialize and deserialize using expect for concise error handling
    let bytes = registry
        .serialize_value(&arc_value)
        .expect("Serialization failed");
    let mut deserialized_arc = registry
        .deserialize_value(std::sync::Arc::from(bytes))
        .expect("Deserialization failed");
    // Extract back to HashMap<String, String> directly
    let extracted: HashMap<String, String> = deserialized_arc
        .as_type()
        .expect("Failed to convert ArcValue to HashMap<String, String>");
    assert_eq!(extracted, map1);
}

#[test]
fn test_direct_vec_hashmap_serialization() {
    // Create a logger
    let logger = Arc::new(Logger::new_root(
        Component::System,
        "direct-vec-hashmap-test",
    ));
    // Create a serializer registry
    let registry = SerializerRegistry::new(logger);
    // Create test data: Vec<HashMap<String, String>> directly
    let mut map1 = HashMap::new();
    map1.insert("key1".to_string(), "value1".to_string());
    map1.insert("key2".to_string(), "value2".to_string());
    let mut map2 = HashMap::new();
    map2.insert("key3".to_string(), "value3".to_string());
    let test_data: Vec<HashMap<String, String>> = vec![map1, map2];
    // Wrap directly in ArcValue - no conversion needed
    let arc_value = ArcValue::from_struct(test_data.clone());
    // Serialize and deserialize using expect for concise error handling
    let bytes = registry
        .serialize_value(&arc_value)
        .expect("Serialization failed");
    let mut deserialized_arc = registry
        .deserialize_value(std::sync::Arc::from(bytes))
        .expect("Deserialization failed");
    // Extract back to Vec<HashMap<String, String>> directly
    let extracted: Vec<HashMap<String, String>> = deserialized_arc
        .as_type()
        .expect("Failed to convert ArcValue to Vec<HashMap<String, String>>");
    assert_eq!(extracted, test_data);
}

#[test]
fn test_direct_hashmap_float_serialization() {
    // Create a logger
    let logger = Arc::new(Logger::new_root(
        Component::System,
        "direct-hashmap-float-test",
    ));
    // Create a serializer registry
    let registry = SerializerRegistry::new(logger);
    // Create test data: HashMap<String, f64> directly
    let mut map1 = HashMap::new();
    map1.insert("a".to_string(), 1000.0);
    map1.insert("b".to_string(), 500.0);
    // Wrap directly in ArcValue - no conversion needed
    let arc_value = ArcValue::from_struct(map1.clone());
    // Serialize and deserialize using expect for concise error handling
    let bytes = registry
        .serialize_value(&arc_value)
        .expect("Serialization failed");
    let mut deserialized_arc = registry
        .deserialize_value(std::sync::Arc::from(bytes))
        .expect("Deserialization failed");
    // Extract back to HashMap<String, f64> directly
    let extracted: HashMap<String, f64> = deserialized_arc
        .as_type()
        .expect("Failed to convert ArcValue to HashMap<String, f64>");
    assert_eq!(extracted, map1);
}

#[test]
fn test_custom_type_hashmap_serialization() {
    // Create a logger
    let logger = Arc::new(Logger::new_root(
        Component::System,
        "custom-type-hashmap-test",
    ));
    // Create a serializer registry
    let mut registry = SerializerRegistry::new(logger);

    // Register the custom types (this would be done automatically by macros)
    registry
        .register::<MyCustomType>()
        .expect("Failed to register MyCustomType");
    registry
        .register::<StringToMyCustomTypeMap>()
        .expect("Failed to register StringToMyCustomTypeMap");

    // Register custom converter for HashMap<String, MyCustomType>
    let type_name = std::any::type_name::<HashMap<String, MyCustomType>>();

    // Serializer: HashMap<String, MyCustomType> -> StringToMyCustomTypeMap -> bytes
    let serializer = Box::new(|value: &dyn std::any::Any| -> anyhow::Result<Vec<u8>> {
        if let Some(hashmap) = value.downcast_ref::<HashMap<String, MyCustomType>>() {
            let map_type = StringToMyCustomTypeMap::from_hashmap(hashmap.clone());
            let mut buf = Vec::new();
            prost::Message::encode(&map_type, &mut buf)?;
            Ok(buf)
        } else {
            Err(anyhow::anyhow!(
                "Type mismatch during HashMap<String, MyCustomType> serialization"
            ))
        }
    });

    // Deserializer: bytes -> StringToMyCustomTypeMap -> HashMap<String, MyCustomType>
    let deserializer = runar_serializer::DeserializerFnWrapper::new(
        |bytes: &[u8]| -> anyhow::Result<Box<dyn std::any::Any + Send + Sync>> {
            let map_type: StringToMyCustomTypeMap = prost::Message::decode(bytes)?;
            let hashmap = map_type.into_hashmap();
            Ok(Box::new(hashmap))
        },
    );

    registry
        .register_custom_serializer(type_name, serializer)
        .expect("Failed to register custom serializer");
    registry
        .register_custom_deserializer(type_name, deserializer)
        .expect("Failed to register custom deserializer");

    // Create test data: HashMap<String, MyCustomType> directly
    let mut map1 = HashMap::new();
    map1.insert(
        "user1".to_string(),
        MyCustomType {
            name: "Alice".to_string(),
            value: 42,
            active: true,
        },
    );
    map1.insert(
        "user2".to_string(),
        MyCustomType {
            name: "Bob".to_string(),
            value: 100,
            active: false,
        },
    );

    // Wrap directly in ArcValue - no conversion needed
    let arc_value = ArcValue::from_struct(map1.clone());

    // Serialize and deserialize using expect for concise error handling
    let bytes = registry
        .serialize_value(&arc_value)
        .expect("Serialization failed");
    let mut deserialized_arc = registry
        .deserialize_value(std::sync::Arc::from(bytes))
        .expect("Deserialization failed");

    // Extract back to HashMap<String, MyCustomType> directly
    let extracted: HashMap<String, MyCustomType> = deserialized_arc
        .as_type()
        .expect("Failed to convert ArcValue to HashMap<String, MyCustomType>");
    assert_eq!(extracted, map1);

    // Verify the custom type data is preserved correctly
    let alice = extracted.get("user1").expect("user1 should exist");
    assert_eq!(alice.name, "Alice");
    assert_eq!(alice.value, 42);
    assert_eq!(alice.active, true);

    let bob = extracted.get("user2").expect("user2 should exist");
    assert_eq!(bob.name, "Bob");
    assert_eq!(bob.value, 100);
    assert_eq!(bob.active, false);
}

#[test]
fn test_custom_type_vec_hashmap_serialization() {
    // Create a logger
    let logger = Arc::new(Logger::new_root(
        Component::System,
        "custom-type-vec-hashmap-test",
    ));
    // Create a serializer registry
    let mut registry = SerializerRegistry::new(logger);

    // Register the custom types (this would be done automatically by macros)
    registry
        .register::<MyCustomType>()
        .expect("Failed to register MyCustomType");
    registry
        .register::<StringToMyCustomTypeMap>()
        .expect("Failed to register StringToMyCustomTypeMap");
    registry
        .register::<VecHashMapStringMyCustomType>()
        .expect("Failed to register VecHashMapStringMyCustomType");

    // Register custom converter for Vec<HashMap<String, MyCustomType>>
    let type_name = std::any::type_name::<Vec<HashMap<String, MyCustomType>>>();

    // Serializer: Vec<HashMap<String, MyCustomType>> -> VecHashMapStringMyCustomType -> bytes
    let serializer = Box::new(|value: &dyn std::any::Any| -> anyhow::Result<Vec<u8>> {
        if let Some(vec_hashmap) = value.downcast_ref::<Vec<HashMap<String, MyCustomType>>>() {
            let vec_type = VecHashMapStringMyCustomType::from_vec_hashmap(vec_hashmap.clone());
            let mut buf = Vec::new();
            prost::Message::encode(&vec_type, &mut buf)?;
            Ok(buf)
        } else {
            Err(anyhow::anyhow!(
                "Type mismatch during Vec<HashMap<String, MyCustomType>> serialization"
            ))
        }
    });

    // Deserializer: bytes -> VecHashMapStringMyCustomType -> Vec<HashMap<String, MyCustomType>>
    let deserializer = runar_serializer::DeserializerFnWrapper::new(
        |bytes: &[u8]| -> anyhow::Result<Box<dyn std::any::Any + Send + Sync>> {
            let vec_type: VecHashMapStringMyCustomType = prost::Message::decode(bytes)?;
            let vec_hashmap = vec_type.into_vec_hashmap();
            Ok(Box::new(vec_hashmap))
        },
    );

    registry
        .register_custom_serializer(type_name, serializer)
        .expect("Failed to register custom serializer");
    registry
        .register_custom_deserializer(type_name, deserializer)
        .expect("Failed to register custom deserializer");

    // Create test data: Vec<HashMap<String, MyCustomType>> directly
    let mut map1 = HashMap::new();
    map1.insert(
        "user1".to_string(),
        MyCustomType {
            name: "Alice".to_string(),
            value: 42,
            active: true,
        },
    );

    let mut map2 = HashMap::new();
    map2.insert(
        "user2".to_string(),
        MyCustomType {
            name: "Bob".to_string(),
            value: 100,
            active: false,
        },
    );

    let test_data: Vec<HashMap<String, MyCustomType>> = vec![map1, map2];

    // Wrap directly in ArcValue - no conversion needed
    let arc_value = ArcValue::from_struct(test_data.clone());

    // Serialize and deserialize using expect for concise error handling
    let bytes = registry
        .serialize_value(&arc_value)
        .expect("Serialization failed");
    let mut deserialized_arc = registry
        .deserialize_value(std::sync::Arc::from(bytes))
        .expect("Deserialization failed");

    // Extract back to Vec<HashMap<String, MyCustomType>> directly
    let extracted: Vec<HashMap<String, MyCustomType>> = deserialized_arc
        .as_type()
        .expect("Failed to convert ArcValue to Vec<HashMap<String, MyCustomType>>");
    assert_eq!(extracted, test_data);

    // Verify the data is preserved correctly
    assert_eq!(extracted.len(), 2);

    let first_map = &extracted[0];
    let alice = first_map
        .get("user1")
        .expect("user1 should exist in first map");
    assert_eq!(alice.name, "Alice");
    assert_eq!(alice.value, 42);
    assert_eq!(alice.active, true);

    let second_map = &extracted[1];
    let bob = second_map
        .get("user2")
        .expect("user2 should exist in second map");
    assert_eq!(bob.name, "Bob");
    assert_eq!(bob.value, 100);
    assert_eq!(bob.active, false);
}
