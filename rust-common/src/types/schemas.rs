// runar_common/src/types/schemas.rs
//
// Schema definitions for the Runar system

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents metadata for a service action
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionMetadata {
    /// The name of the action
    pub name: String,
    /// The description of the action
    pub description: String,
    /// The input schema for the action (if any)
    pub input_schema: Option<FieldSchema>,
    /// The output schema for the action (if any)
    pub output_schema: Option<FieldSchema>,
}

/// Represents metadata for a service event
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventMetadata {
    /// The name of the event
    pub path: String,
    /// The description of the event
    pub description: String,
    /// The schema for the event data (if any)
    pub data_schema: Option<FieldSchema>,
}

/// Represents metadata for a service.
/// This is a unified struct that replaces ServiceCapability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceMetadata {
    /// The network ID this service belongs to
    pub network_id: String,
    /// The path of the service (e.g., "math-service")
    pub service_path: String,
    /// The name of the service
    pub name: String,
    /// The version of the service
    pub version: String,
    /// The description of the service
    pub description: String,
    /// The actions provided by this service
    pub actions: Vec<ActionMetadata>,
    /// The events emitted by this service
    pub events: Vec<EventMetadata>,
    /// The timestamp when the service was registered (in seconds since UNIX epoch)
    pub registration_time: u64,
    /// The timestamp when the service was last started (in seconds since UNIX epoch)
    /// This is None if the service has never been started
    pub last_start_time: Option<u64>,
}

/// Represents a field in a schema
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldSchema {
    /// The name of the field
    pub name: String,
    /// The type of the field
    pub data_type: SchemaDataType,
    /// The description of the field
    pub description: Option<String>,
    /// Whether the field is nullable
    pub nullable: Option<bool>,
    /// The default value of the field (if any)
    pub default_value: Option<String>,
    /// For `SchemaDataType::Object`: Defines the schema for each property of the object
    pub properties: Option<HashMap<String, Box<FieldSchema>>>,
    /// Required fields for object types
    pub required: Option<Vec<String>>,
    /// For `SchemaDataType::Array`: Defines the schema for items in the array
    pub items: Option<Box<FieldSchema>>,
    /// Regular expression pattern for string validation
    pub pattern: Option<String>,
    /// String representations of allowed enumeration values
    pub enum_values: Option<Vec<String>>,
    // Numeric constraints
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
    pub exclusive_minimum: Option<bool>,
    pub exclusive_maximum: Option<bool>,
    // String length constraints
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    // Array length constraints
    pub min_items: Option<usize>,
    pub max_items: Option<usize>,
    /// Example value as a string
    pub example: Option<String>,
}

/// Represents the data type of a schema field
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SchemaDataType {
    /// A string value
    String,
    /// A 32-bit signed integer
    Int32,
    /// A 64-bit signed integer
    Int64,
    /// A 32-bit floating point number
    Float,
    /// A 64-bit floating point number
    Double,
    /// A boolean value
    Boolean,
    /// A timestamp (ISO 8601 string)
    Timestamp,
    /// A binary blob (base64 encoded string)
    Binary,
    /// A nested object with its own schema
    Object,
    /// An array of values of the same type
    Array,
    /// A reference to another type by name
    Reference(String),
    /// A union of multiple possible types
    Union(Vec<SchemaDataType>),
    /// Any valid JSON value
    Any,
}

impl FieldSchema {
    // Helper constructors for common types
    pub fn new(name: &str, data_type: SchemaDataType) -> Self {
        FieldSchema {
            name: name.to_string(),
            data_type,
            description: None,
            nullable: None,
            default_value: None,
            properties: None,
            required: None,
            items: None,
            pattern: None,
            enum_values: None,
            minimum: None,
            maximum: None,
            exclusive_minimum: None,
            exclusive_maximum: None,
            min_length: None,
            max_length: None,
            min_items: None,
            max_items: None,
            example: None,
        }
    }

    pub fn string(name: &str) -> Self {
        FieldSchema::new(name, SchemaDataType::String)
    }

    pub fn integer(name: &str) -> Self {
        FieldSchema::new(name, SchemaDataType::Int32)
    }

    pub fn long(name: &str) -> Self {
        FieldSchema::new(name, SchemaDataType::Int64)
    }

    pub fn float(name: &str) -> Self {
        FieldSchema::new(name, SchemaDataType::Float)
    }

    pub fn double(name: &str) -> Self {
        FieldSchema::new(name, SchemaDataType::Double)
    }

    pub fn boolean(name: &str) -> Self {
        FieldSchema::new(name, SchemaDataType::Boolean)
    }

    pub fn timestamp(name: &str) -> Self {
        FieldSchema::new(name, SchemaDataType::Timestamp)
    }

    pub fn object(
        name: &str,
        properties: HashMap<String, Box<FieldSchema>>,
        required: Option<Vec<String>>,
    ) -> Self {
        FieldSchema {
            name: name.to_string(),
            data_type: SchemaDataType::Object,
            properties: Some(properties),
            required,
            ..FieldSchema::new(name, SchemaDataType::Object)
        }
    }

    pub fn array(name: &str, items: Box<FieldSchema>) -> Self {
        FieldSchema {
            name: name.to_string(),
            data_type: SchemaDataType::Array,
            items: Some(items),
            ..FieldSchema::new(name, SchemaDataType::Array)
        }
    }
}
