// runar_common/src/types/schemas.rs
//
// Schema definitions for the Runar system

use prost::Message;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents metadata for a service action
#[derive(Clone, PartialEq, Serialize, Deserialize, Message)]
pub struct ActionMetadata {
    /// The name of the action
    #[prost(string, tag = "1")]
    pub name: String,
    /// The description of the action
    #[prost(string, tag = "2")]
    pub description: String,
    /// The input schema for the action (if any)
    #[prost(message, optional, tag = "3")]
    pub input_schema: Option<FieldSchema>,
    /// The output schema for the action (if any)
    #[prost(message, optional, tag = "4")]
    pub output_schema: Option<FieldSchema>,
}

/// Represents metadata for a service event
#[derive(Clone, PartialEq, Serialize, Deserialize, Message)]
pub struct EventMetadata {
    /// The name of the event
    #[prost(string, tag = "1")]
    pub path: String,
    /// The description of the event
    #[prost(string, tag = "2")]
    pub description: String,
    /// The schema for the event data (if any)
    #[prost(message, optional, tag = "3")]
    pub data_schema: Option<FieldSchema>,
}

/// Represents metadata for a service.
/// This is a unified struct that replaces ServiceCapability.
#[derive(Clone, PartialEq, Serialize, Deserialize, Message)]
pub struct ServiceMetadata {
    /// The network ID this service belongs to
    #[prost(string, tag = "1")]
    pub network_id: String,
    /// The path of the service (e.g., "math-service")
    #[prost(string, tag = "2")]
    pub service_path: String,
    /// The name of the service
    #[prost(string, tag = "3")]
    pub name: String,
    /// The version of the service
    #[prost(string, tag = "4")]
    pub version: String,
    /// The description of the service
    #[prost(string, tag = "5")]
    pub description: String,
    /// The actions provided by this service
    #[prost(message, repeated, tag = "6")]
    pub actions: Vec<ActionMetadata>,
    /// The events emitted by this service
    #[prost(message, repeated, tag = "7")]
    pub events: Vec<EventMetadata>,
    /// The timestamp when the service was registered (in seconds since UNIX epoch)
    #[prost(uint64, tag = "8")]
    pub registration_time: u64,
    /// The timestamp when the service was last started (in seconds since UNIX epoch)
    /// This is None if the service has never been started
    #[prost(uint64, optional, tag = "9")]
    pub last_start_time: Option<u64>,
}

/// Represents a field in a schema
#[derive(Clone, PartialEq, Serialize, Deserialize, Message)]
pub struct FieldSchema {
    /// The name of the field
    #[prost(string, tag = "1")]
    pub name: String,
    /// The type of the field (as u8: 1=String, 2=Int32, 3=Int64, etc.)
    #[prost(uint32, tag = "2")]
    pub data_type: u32,
    /// The description of the field
    #[prost(string, optional, tag = "3")]
    pub description: Option<String>,
    /// Whether the field is nullable
    #[prost(bool, optional, tag = "4")]
    pub nullable: Option<bool>,
    /// The default value of the field (if any)
    #[prost(string, optional, tag = "5")]
    pub default_value: Option<String>,
    /// For Object type: Defines the schema for each property of the object
    #[prost(map = "string, message", tag = "6")]
    pub properties: HashMap<String, FieldSchema>,
    /// Required fields for object types
    #[prost(string, repeated, tag = "7")]
    pub required: Vec<String>,
    /// For Array type: Defines the schema for items in the array
    #[prost(message, optional, tag = "8")]
    pub items: Option<Box<FieldSchema>>,
    /// Regular expression pattern for string validation
    #[prost(string, optional, tag = "9")]
    pub pattern: Option<String>,
    /// String representations of allowed enumeration values
    #[prost(string, repeated, tag = "10")]
    pub enum_values: Vec<String>,
    // Numeric constraints
    #[prost(double, optional, tag = "11")]
    pub minimum: Option<f64>,
    #[prost(double, optional, tag = "12")]
    pub maximum: Option<f64>,
    #[prost(bool, optional, tag = "13")]
    pub exclusive_minimum: Option<bool>,
    #[prost(bool, optional, tag = "14")]
    pub exclusive_maximum: Option<bool>,
    // String length constraints
    #[prost(uint64, optional, tag = "15")]
    pub min_length: Option<u64>,
    #[prost(uint64, optional, tag = "16")]
    pub max_length: Option<u64>,
    // Array length constraints
    #[prost(uint64, optional, tag = "17")]
    pub min_items: Option<u64>,
    #[prost(uint64, optional, tag = "18")]
    pub max_items: Option<u64>,
    /// Example value as a string
    #[prost(string, optional, tag = "19")]
    pub example: Option<String>,
    /// For Reference type: the referenced type name
    #[prost(string, optional, tag = "20")]
    pub reference_type: Option<String>,
    /// For Union type: the union types as strings
    #[prost(string, repeated, tag = "21")]
    pub union_types: Vec<String>,
}

/// Represents the data type of a schema field (as u32 constants)
pub struct SchemaDataType;

impl SchemaDataType {
    pub const STRING: u32 = 1;
    pub const INT32: u32 = 2;
    pub const INT64: u32 = 3;
    pub const FLOAT: u32 = 4;
    pub const DOUBLE: u32 = 5;
    pub const BOOLEAN: u32 = 6;
    pub const TIMESTAMP: u32 = 7;
    pub const BINARY: u32 = 8;
    pub const OBJECT: u32 = 9;
    pub const ARRAY: u32 = 10;
    pub const REFERENCE: u32 = 11;
    pub const UNION: u32 = 12;
    pub const ANY: u32 = 13;
}

impl FieldSchema {
    // Helper constructors for common types
    pub fn new(name: &str, data_type: u32) -> Self {
        FieldSchema {
            name: name.to_string(),
            data_type,
            description: None,
            nullable: None,
            default_value: None,
            properties: HashMap::new(),
            required: Vec::new(),
            items: None,
            pattern: None,
            enum_values: Vec::new(),
            minimum: None,
            maximum: None,
            exclusive_minimum: None,
            exclusive_maximum: None,
            min_length: None,
            max_length: None,
            min_items: None,
            max_items: None,
            example: None,
            reference_type: None,
            union_types: Vec::new(),
        }
    }

    pub fn string(name: &str) -> Self {
        FieldSchema::new(name, SchemaDataType::STRING)
    }

    pub fn integer(name: &str) -> Self {
        FieldSchema::new(name, SchemaDataType::INT32)
    }

    pub fn long(name: &str) -> Self {
        FieldSchema::new(name, SchemaDataType::INT64)
    }

    pub fn float(name: &str) -> Self {
        FieldSchema::new(name, SchemaDataType::FLOAT)
    }

    pub fn double(name: &str) -> Self {
        FieldSchema::new(name, SchemaDataType::DOUBLE)
    }

    pub fn boolean(name: &str) -> Self {
        FieldSchema::new(name, SchemaDataType::BOOLEAN)
    }

    pub fn timestamp(name: &str) -> Self {
        FieldSchema::new(name, SchemaDataType::TIMESTAMP)
    }

    pub fn object(
        name: &str,
        properties: HashMap<String, Box<FieldSchema>>,
        required: Option<Vec<String>>,
    ) -> Self {
        // Convert Box<FieldSchema> to FieldSchema for protobuf compatibility
        let properties_converted: HashMap<String, FieldSchema> =
            properties.into_iter().map(|(k, v)| (k, *v)).collect();

        FieldSchema {
            name: name.to_string(),
            data_type: SchemaDataType::OBJECT,
            properties: properties_converted,
            required: required.unwrap_or_default(),
            ..FieldSchema::new(name, SchemaDataType::OBJECT)
        }
    }

    pub fn array(name: &str, items: Box<FieldSchema>) -> Self {
        FieldSchema {
            name: name.to_string(),
            data_type: SchemaDataType::ARRAY,
            items: Some(items),
            ..FieldSchema::new(name, SchemaDataType::ARRAY)
        }
    }

    pub fn reference(name: &str, reference_type: &str) -> Self {
        FieldSchema {
            name: name.to_string(),
            data_type: SchemaDataType::REFERENCE,
            reference_type: Some(reference_type.to_string()),
            ..FieldSchema::new(name, SchemaDataType::REFERENCE)
        }
    }

    pub fn union(name: &str, union_types: Vec<String>) -> Self {
        FieldSchema {
            name: name.to_string(),
            data_type: SchemaDataType::UNION,
            union_types,
            ..FieldSchema::new(name, SchemaDataType::UNION)
        }
    }
}
