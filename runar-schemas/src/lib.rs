//! Runar core schemas (ServiceMetadata, etc.) extracted into a dedicated
//! crate to avoid layering violations.  All message types derive
//! `Serializable`, which auto-implements `CustomFromBytes` / `AsArcValue`.

use prost::Message;
use runar_serializer_macros::Serializable;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, PartialEq, Serialize, Deserialize, Message, Serializable)]
pub struct ActionMetadata {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub description: String,
    #[prost(message, optional, tag = "3")]
    pub input_schema: Option<FieldSchema>,
    #[prost(message, optional, tag = "4")]
    pub output_schema: Option<FieldSchema>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Message, Serializable)]
pub struct EventMetadata {
    #[prost(string, tag = "1")]
    pub path: String,
    #[prost(string, tag = "2")]
    pub description: String,
    #[prost(message, optional, tag = "3")]
    pub data_schema: Option<FieldSchema>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Message, Serializable)]
pub struct ServiceMetadata {
    #[prost(string, tag = "1")]
    pub network_id: String,
    #[prost(string, tag = "2")]
    pub service_path: String,
    #[prost(string, tag = "3")]
    pub name: String,
    #[prost(string, tag = "4")]
    pub version: String,
    #[prost(string, tag = "5")]
    pub description: String,
    #[prost(message, repeated, tag = "6")]
    pub actions: Vec<ActionMetadata>,
    #[prost(message, repeated, tag = "7")]
    pub events: Vec<EventMetadata>,
    #[prost(uint64, tag = "8")]
    pub registration_time: u64,
    #[prost(uint64, optional, tag = "9")]
    pub last_start_time: Option<u64>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Message, Serializable)]
pub struct FieldSchema {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(uint32, tag = "2")]
    pub data_type: u32,
    #[prost(string, optional, tag = "3")]
    pub description: Option<String>,
    #[prost(bool, optional, tag = "4")]
    pub nullable: Option<bool>,
    #[prost(string, optional, tag = "5")]
    pub default_value: Option<String>,
    #[prost(map = "string, message", tag = "6")]
    pub properties: HashMap<String, FieldSchema>,
    #[prost(string, repeated, tag = "7")]
    pub required: Vec<String>,
    #[prost(message, optional, tag = "8")]
    pub items: Option<Box<FieldSchema>>,
    #[prost(string, optional, tag = "9")]
    pub pattern: Option<String>,
    #[prost(string, repeated, tag = "10")]
    pub enum_values: Vec<String>,
    #[prost(double, optional, tag = "11")]
    pub minimum: Option<f64>,
    #[prost(double, optional, tag = "12")]
    pub maximum: Option<f64>,
    #[prost(bool, optional, tag = "13")]
    pub exclusive_minimum: Option<bool>,
    #[prost(bool, optional, tag = "14")]
    pub exclusive_maximum: Option<bool>,
    #[prost(uint64, optional, tag = "15")]
    pub min_length: Option<u64>,
    #[prost(uint64, optional, tag = "16")]
    pub max_length: Option<u64>,
    #[prost(uint64, optional, tag = "17")]
    pub min_items: Option<u64>,
    #[prost(uint64, optional, tag = "18")]
    pub max_items: Option<u64>,
    #[prost(string, optional, tag = "19")]
    pub example: Option<String>,
    #[prost(string, optional, tag = "20")]
    pub reference_type: Option<String>,
    #[prost(string, repeated, tag = "21")]
    pub union_types: Vec<String>,
}

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
