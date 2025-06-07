use anyhow::Result;
use runar_common::{
    types::{ArcValueType, SerializerRegistry},
    Component, Logger,
};
use runar_node::network::transport::{NetworkMessage, NetworkMessagePayloadItem, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct TestStruct {
    id: String,
    value: i32,
    metadata: HashMap<String, String>,
}

#[test]
fn test_message_payload_item_serialization() -> Result<()> {
    // Create a simple payload item with ArcValueType
    let value = ArcValueType::new_primitive("test-value".to_string());

    // Create a SerializerRegistry for serialization
    let logger = Logger::new_root(Component::Network, "binary_serialization_test");

    // Create a SerializerRegistry for serialization
    let registry = SerializerRegistry::with_defaults(Arc::new(logger.clone()));

    // Serialize the ArcValueType
    let value_bytes = registry.serialize_value(&value)?;

    let payload_item = NetworkMessagePayloadItem::new(
        "test/path".to_string(),
        value_bytes.to_vec(),
        "correlation-123".to_string(),
    );

    // Serialize the payload item
    let serialized = bincode::serialize(&payload_item)?;
    println!("Serialized payload item to {} bytes", serialized.len());

    // Deserialize the payload item
    let deserialized: NetworkMessagePayloadItem = bincode::deserialize(&serialized)?;

    // Verify the data matches
    assert_eq!(deserialized.path, "test/path");
    assert_eq!(deserialized.correlation_id, "correlation-123");

    // Deserialize the value bytes back to ArcValueType
    let mut deserialized_value =
        registry.deserialize_value(Arc::from(deserialized.value_bytes.clone()))?;
    let string_value: String = deserialized_value.as_type()?;
    assert_eq!(string_value, "test-value");

    println!("Test passed: Payload item serialization/deserialization works with ArcValueType");
    Ok(())
}

#[test]
fn test_network_message_serialization() -> Result<()> {
    // Create source and destination IDs
    let source_id = PeerId::new("source-node".to_string());
    let dest_id = PeerId::new("dest-node".to_string());

    // Create a payload with ArcValueType
    let value = ArcValueType::new_primitive(42.0);

    // Create a SerializerRegistry for serialization
    let logger = Logger::new_root(Component::Network, "binary_serialization_test");

    // Create a SerializerRegistry for serialization
    let registry = SerializerRegistry::with_defaults(Arc::new(logger.clone()));

    // Serialize the ArcValueType
    let value_bytes = registry.serialize_value(&value)?;

    let payload_item = NetworkMessagePayloadItem::new(
        "test/path".to_string(),
        value_bytes.to_vec(),
        "correlation-456".to_string(),
    );

    // Create a network message
    let message = NetworkMessage {
        source: source_id.clone(),
        destination: dest_id.clone(),
        message_type: "TestMessage".to_string(),
        payloads: vec![payload_item],
    };

    // Serialize the message
    let serialized = bincode::serialize(&message)?;
    println!("Serialized network message to {} bytes", serialized.len());

    // Deserialize the message
    let deserialized: NetworkMessage = bincode::deserialize(&serialized)?;

    // Verify the data matches
    assert_eq!(deserialized.source.public_key, source_id.public_key);
    assert_eq!(deserialized.destination.public_key, dest_id.public_key);
    assert_eq!(deserialized.message_type, "TestMessage");
    assert_eq!(deserialized.payloads.len(), 1);
    assert_eq!(deserialized.payloads[0].path, "test/path");
    assert_eq!(deserialized.payloads[0].correlation_id, "correlation-456");

    // Deserialize the value bytes back to ArcValueType
    let bytes: Arc<[u8]> = Arc::from(deserialized.payloads[0].value_bytes.clone());
    let mut deserialized_value = registry.deserialize_value(bytes)?;
    let number_value: f64 = deserialized_value.as_type()?;
    assert_eq!(number_value, 42.0);

    println!("Test passed: Network message serialization/deserialization works with ArcValueType");
    Ok(())
}

// Now try with the struct-based approach
#[test]
fn test_struct_serialization_in_network_message() -> Result<()> {
    // Create test data
    let mut metadata = HashMap::new();
    metadata.insert("type".to_string(), "test".to_string());
    metadata.insert("version".to_string(), "1.0".to_string());

    let original = TestStruct {
        id: "test-struct-123".to_string(),
        value: 42,
        metadata: metadata.clone(),
    };

    // Create source and destination IDs
    let source_id = PeerId::new("source-node".to_string());
    let dest_id = PeerId::new("dest-node".to_string());

    // Create a payload with the struct using ArcValueType
    let arc_value = ArcValueType::from_struct(original.clone());

    // Create a SerializerRegistry for serialization
    let logger = Logger::new_root(Component::Network, "binary_serialization_test");

    // Create a SerializerRegistry for serialization
    let mut registry = SerializerRegistry::with_defaults(Arc::new(logger.clone()));
    registry.register::<TestStruct>()?;

    // Serialize the ArcValueType
    let value_bytes = registry.serialize_value(&arc_value)?;

    let payload_item = NetworkMessagePayloadItem::new(
        "test/path".to_string(),
        value_bytes.to_vec(),
        "test-correlation-123".to_string(),
    );

    // Deserialize the value bytes back to ArcValueType
    let mut deserialized_value =
        registry.deserialize_value(Arc::from(payload_item.value_bytes.clone()))?;

    // Extract the struct from ArcValueType
    let extracted1: TestStruct = deserialized_value
        .as_struct_ref::<TestStruct>()?
        .as_ref()
        .clone();

    assert_eq!(extracted1, original, "struct extraction failed");

    // Create a network message
    let message = NetworkMessage {
        source: source_id,
        destination: dest_id,
        message_type: "TestMessage".to_string(),
        payloads: vec![payload_item],
    };

    // Serialize the entire message using bincode
    let serialized_message = bincode::serialize(&message)?;
    println!(
        "Serialized struct-based network message to {} bytes",
        serialized_message.len()
    );

    // Deserialize the message
    let deserialized_message: NetworkMessage = bincode::deserialize(&serialized_message)?;

    // Deserialize the value bytes back to ArcValueType
    let mut deserialized_value = registry.deserialize_value(Arc::from(
        deserialized_message.payloads[0].value_bytes.clone(),
    ))?;

    // Extract the struct from ArcValueType
    let extracted_struct: TestStruct = deserialized_value
        .as_struct_ref::<TestStruct>()?
        .as_ref()
        .clone();

    // Verify the data
    assert_eq!(
        extracted_struct, original,
        "Extracted struct doesn't match original"
    );
    assert_eq!(deserialized_message.message_type, "TestMessage");
    assert_eq!(deserialized_message.payloads[0].path, "test/path");
    assert_eq!(
        deserialized_message.payloads[0].correlation_id,
        "test-correlation-123"
    );

    println!(
        "Test passed: Direct bincode serialization and deserialization works with both methods"
    );
    Ok(())
}

#[test]
fn test_multiple_struct_types_in_message() -> Result<()> {
    // Create test data with two different struct types
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct UserData {
        username: String,
        email: String,
        age: u32,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct ProductData {
        name: String,
        price: f64,
        stock: u32,
    }

    let user = UserData {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        age: 30,
    };

    let product = ProductData {
        name: "Test Product".to_string(),
        price: 99.99,
        stock: 10,
    };

    // Create source and destination IDs
    let source_id = PeerId::new("source-node".to_string());
    let dest_id = PeerId::new("dest-node".to_string());

    // Create payloads with different struct types using ArcValueType
    // Create a SerializerRegistry for serialization
    let logger = Logger::new_root(Component::Network, "binary_serialization_test");

    // Create a SerializerRegistry for serialization
    let mut registry = SerializerRegistry::with_defaults(Arc::new(logger.clone()));
    registry.register::<UserData>()?;
    registry.register::<ProductData>()?;

    // Create ArcValueType for user data
    let user_arc_value = ArcValueType::from_struct(user.clone());
    let user_value_bytes = registry.serialize_value(&user_arc_value)?;
    let user_payload = NetworkMessagePayloadItem::new(
        "users/data".to_string(),
        user_value_bytes.to_vec(),
        "user-123".to_string(),
    );

    // Create ArcValueType for product data
    let product_arc_value = ArcValueType::from_struct(product.clone());
    let product_value_bytes = registry.serialize_value(&product_arc_value)?;
    let product_payload = NetworkMessagePayloadItem::new(
        "products/data".to_string(),
        product_value_bytes.to_vec(),
        "product-456".to_string(),
    );

    // Create a network message with multiple payloads
    let message = NetworkMessage {
        source: source_id,
        destination: dest_id,
        message_type: "MultiStructMessage".to_string(),
        payloads: vec![user_payload, product_payload],
    };

    // Serialize the entire message
    let serialized_message = bincode::serialize(&message)?;
    println!(
        "Serialized multi-struct message to {} bytes",
        serialized_message.len()
    );

    // Deserialize the message
    let deserialized_message: NetworkMessage = bincode::deserialize(&serialized_message)?;

    // Deserialize the value bytes back to ArcValueType
    let mut deserialized_user_value = registry.deserialize_value(Arc::from(
        deserialized_message.payloads[0].value_bytes.clone(),
    ))?;
    let mut deserialized_product_value = registry.deserialize_value(Arc::from(
        deserialized_message.payloads[1].value_bytes.clone(),
    ))?;

    // Extract the structs from ArcValueType
    let extracted_user: UserData = deserialized_user_value
        .as_struct_ref::<UserData>()?
        .as_ref()
        .clone();
    let extracted_product: ProductData = deserialized_product_value
        .as_struct_ref::<ProductData>()?
        .as_ref()
        .clone();

    // Verify the data
    assert_eq!(
        extracted_user, user,
        "Extracted user doesn't match original"
    );
    assert_eq!(
        extracted_product, product,
        "Extracted product doesn't match original"
    );
    assert_eq!(deserialized_message.payloads[0].path, "users/data");
    assert_eq!(deserialized_message.payloads[1].path, "products/data");

    println!("Multi-struct test passed: All data correctly serialized and deserialized using ArcValueType");
    Ok(())
}

#[test]
fn test_various_types_in_network_messages() -> Result<()> {
    // Create source and destination IDs
    let source_id = PeerId::new("source-node".to_string());
    let dest_id = PeerId::new("dest-node".to_string());

    // Create a struct
    let mut metadata = HashMap::new();
    metadata.insert("type".to_string(), "test".to_string());

    let test_struct = TestStruct {
        id: "struct-test".to_string(),
        value: 42,
        metadata: metadata.clone(),
    };

    // Create a map
    let mut test_map = HashMap::new();
    test_map.insert("key1".to_string(), "value1".to_string());
    test_map.insert("key2".to_string(), "value2".to_string());

    // Create an array
    let test_array = vec![1, 2, 3, 4, 5];

    // Create a logger
    let logger = Logger::new_root(Component::Network, "binary_serialization_test");

    // Create a SerializerRegistry for serialization
    let mut registry = SerializerRegistry::with_defaults(Arc::new(logger.clone()));
    registry.register::<TestStruct>()?;

    // Create payload items for each type using ArcValueType
    // Struct payload
    let struct_arc_value = ArcValueType::from_struct(test_struct.clone());
    let struct_value_bytes = registry.serialize_value(&struct_arc_value)?;
    let struct_payload = NetworkMessagePayloadItem::new(
        "test/struct".to_string(),
        struct_value_bytes.to_vec(),
        "correlation-struct".to_string(),
    );

    // Map payload
    let map_arc_value = ArcValueType::from_map(test_map.clone());
    let map_value_bytes = registry.serialize_value(&map_arc_value)?;
    let map_payload = NetworkMessagePayloadItem::new(
        "test/map".to_string(),
        map_value_bytes.to_vec(),
        "correlation-map".to_string(),
    );

    // Array payload
    let array_arc_value = ArcValueType::from_list(test_array.clone());
    let array_value_bytes = registry.serialize_value(&array_arc_value)?;
    let array_payload = NetworkMessagePayloadItem::new(
        "test/array".to_string(),
        array_value_bytes.to_vec(),
        "correlation-array".to_string(),
    );

    // Create a network message with all payloads
    let message = NetworkMessage {
        source: source_id,
        destination: dest_id,
        message_type: "TestAllTypes".to_string(),
        payloads: vec![struct_payload, map_payload, array_payload],
    };

    // Serialize the message
    let serialized = bincode::serialize(&message)?;
    println!(
        "Serialized network message with all types to {} bytes",
        serialized.len()
    );

    // Deserialize the message
    let deserialized: NetworkMessage = bincode::deserialize(&serialized)?;

    // Deserialize the value bytes back to ArcValueType for each payload
    let mut deserialized_struct_value =
        registry.deserialize_value(Arc::from(deserialized.payloads[0].value_bytes.clone()))?;
    let mut deserialized_map_value =
        registry.deserialize_value(Arc::from(deserialized.payloads[1].value_bytes.clone()))?;
    let mut deserialized_array_value =
        registry.deserialize_value(Arc::from(deserialized.payloads[2].value_bytes.clone()))?;

    // Verify struct payload
    let extracted_struct: TestStruct = deserialized_struct_value
        .as_struct_ref::<TestStruct>()?
        .as_ref()
        .clone();
    assert_eq!(
        extracted_struct, test_struct,
        "Extracted struct doesn't match original"
    );
    println!("✓ Struct extraction works with ArcValueType");

    // Verify map payload
    let extracted_map: HashMap<String, String> =
        deserialized_map_value.as_map_ref()?.as_ref().clone();
    assert_eq!(
        extracted_map, test_map,
        "Extracted map doesn't match original"
    );
    println!("✓ Map extraction works with ArcValueType");

    // Verify array payload
    let extracted_array: Vec<i32> = deserialized_array_value.as_list_ref()?.as_ref().clone();
    assert_eq!(
        extracted_array, test_array,
        "Extracted array doesn't match original"
    );
    println!("✓ Array extraction works with ArcValueType");

    assert_eq!(extracted_struct, test_struct, "Struct extraction failed");
    assert_eq!(extracted_map, test_map, "Map extraction failed");
    assert_eq!(extracted_array, test_array, "Array extraction failed");

    println!("✓ ArcValueType extraction works for all types");
    println!("All tests passed for various data types in network messages using ArcValueType");

    Ok(())
}
