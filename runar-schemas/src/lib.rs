//! Runar core schemas (ServiceMetadata, etc.) extracted into a dedicated
//! crate to avoid layering violations.  All message types derive
//! `Plain`, which provides basic serialization capabilities.

use runar_serializer_macros::Plain;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, Plain)]
pub struct ActionMetadata {
    pub name: String,
    pub description: String,
    pub input_schema: Option<FieldSchema>,
    pub output_schema: Option<FieldSchema>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, Plain)]
pub struct EventMetadata {
    pub path: String,
    pub description: String,
    pub data_schema: Option<FieldSchema>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, Plain)]
pub struct ServiceMetadata {
    pub network_id: String,
    pub service_path: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub actions: Vec<ActionMetadata>,
    pub events: Vec<EventMetadata>,
    pub registration_time: u64,
    pub last_start_time: Option<u64>,
}

/// Represents the data type of a schema field
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Plain)]
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

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, Plain)]
pub struct FieldSchema {
    pub name: String,
    pub data_type: SchemaDataType,
    pub description: Option<String>,
    pub nullable: Option<bool>,
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

    pub fn reference(name: &str, reference_type: &str) -> Self {
        FieldSchema {
            name: name.to_string(),
            data_type: SchemaDataType::Reference(reference_type.to_string()),
            ..FieldSchema::new(name, SchemaDataType::Reference(reference_type.to_string()))
        }
    }

    pub fn union(name: &str, union_types: Vec<SchemaDataType>) -> Self {
        FieldSchema {
            name: name.to_string(),
            data_type: SchemaDataType::Union(union_types),
            ..FieldSchema::new(name, SchemaDataType::Union(vec![]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use runar_serializer::{arc_value::AsArcValue, ArcValue};
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn test_service_metadata_serialization_roundtrip() -> Result<()> {
        // Create a comprehensive ServiceMetadata with all fields populated
        let service_metadata = ServiceMetadata {
            network_id: "test-network-123".to_string(),
            service_path: "math-service".to_string(),
            name: "Math Service".to_string(),
            version: "1.2.3".to_string(),
            description: "A comprehensive mathematical operations service".to_string(),
            actions: vec![
                ActionMetadata {
                    name: "add".to_string(),
                    description: "Adds two numbers".to_string(),
                    input_schema: Some(FieldSchema::object(
                        "AddInput",
                        HashMap::from([
                            ("a".to_string(), Box::new(FieldSchema::double("a"))),
                            ("b".to_string(), Box::new(FieldSchema::double("b"))),
                        ]),
                        Some(vec!["a".to_string(), "b".to_string()]),
                    )),
                    output_schema: Some(FieldSchema::double("result")),
                },
                ActionMetadata {
                    name: "multiply".to_string(),
                    description: "Multiplies two numbers".to_string(),
                    input_schema: Some(FieldSchema::object(
                        "MultiplyInput",
                        HashMap::from([
                            ("x".to_string(), Box::new(FieldSchema::integer("x"))),
                            ("y".to_string(), Box::new(FieldSchema::integer("y"))),
                        ]),
                        Some(vec!["x".to_string(), "y".to_string()]),
                    )),
                    output_schema: Some(FieldSchema::long("result")),
                },
                ActionMetadata {
                    name: "calculate".to_string(),
                    description: "Performs complex calculations".to_string(),
                    input_schema: Some(FieldSchema::object(
                        "CalculateInput",
                        HashMap::from([
                            (
                                "expression".to_string(),
                                Box::new(FieldSchema::string("expression")),
                            ),
                            (
                                "variables".to_string(),
                                Box::new(FieldSchema::array(
                                    "variables",
                                    Box::new(FieldSchema::object(
                                        "Variable",
                                        HashMap::from([
                                            (
                                                "name".to_string(),
                                                Box::new(FieldSchema::string("name")),
                                            ),
                                            (
                                                "value".to_string(),
                                                Box::new(FieldSchema::double("value")),
                                            ),
                                        ]),
                                        Some(vec!["name".to_string(), "value".to_string()]),
                                    )),
                                )),
                            ),
                        ]),
                        Some(vec!["expression".to_string()]),
                    )),
                    output_schema: Some(FieldSchema::double("result")),
                },
            ],
            events: vec![
                EventMetadata {
                    path: "calculation.completed".to_string(),
                    description: "Emitted when a calculation is completed".to_string(),
                    data_schema: Some(FieldSchema::object(
                        "CalculationCompleted",
                        HashMap::from([
                            (
                                "operation".to_string(),
                                Box::new(FieldSchema::string("operation")),
                            ),
                            (
                                "result".to_string(),
                                Box::new(FieldSchema::double("result")),
                            ),
                            (
                                "timestamp".to_string(),
                                Box::new(FieldSchema::timestamp("timestamp")),
                            ),
                            (
                                "user_id".to_string(),
                                Box::new(FieldSchema::string("user_id")),
                            ),
                        ]),
                        Some(vec![
                            "operation".to_string(),
                            "result".to_string(),
                            "timestamp".to_string(),
                        ]),
                    )),
                },
                EventMetadata {
                    path: "error.occurred".to_string(),
                    description: "Emitted when an error occurs".to_string(),
                    data_schema: Some(FieldSchema::object(
                        "ErrorOccurred",
                        HashMap::from([
                            (
                                "error_code".to_string(),
                                Box::new(FieldSchema::integer("error_code")),
                            ),
                            (
                                "error_message".to_string(),
                                Box::new(FieldSchema::string("error_message")),
                            ),
                            (
                                "stack_trace".to_string(),
                                Box::new(FieldSchema::string("stack_trace")),
                            ),
                        ]),
                        Some(vec!["error_code".to_string(), "error_message".to_string()]),
                    )),
                },
            ],
            registration_time: 1640995200, // 2022-01-01 00:00:00 UTC
            last_start_time: Some(1640995260), // 2022-01-01 00:01:00 UTC
        };

        // Wrap in ArcValue
        let arc_value = ArcValue::new_struct(service_metadata.clone());

        // Serialize
        let serialized = arc_value.serialize(None)?;

        // Deserialize
        let deserialized = ArcValue::deserialize(&serialized, None)?;

        // Extract the ServiceMetadata from the deserialized ArcValue
        let extracted_metadata: Arc<ServiceMetadata> = deserialized.as_struct_ref()?;

        // Verify that the output matches the input
        assert_eq!(*extracted_metadata, service_metadata);

        // Additional verification of specific fields
        assert_eq!(extracted_metadata.network_id, "test-network-123");
        assert_eq!(extracted_metadata.service_path, "math-service");
        assert_eq!(extracted_metadata.name, "Math Service");
        assert_eq!(extracted_metadata.version, "1.2.3");
        assert_eq!(
            extracted_metadata.description,
            "A comprehensive mathematical operations service"
        );
        assert_eq!(extracted_metadata.registration_time, 1640995200);
        assert_eq!(extracted_metadata.last_start_time, Some(1640995260));

        // Verify actions
        assert_eq!(extracted_metadata.actions.len(), 3);
        assert_eq!(extracted_metadata.actions[0].name, "add");
        assert_eq!(extracted_metadata.actions[1].name, "multiply");
        assert_eq!(extracted_metadata.actions[2].name, "calculate");

        // Verify events
        assert_eq!(extracted_metadata.events.len(), 2);
        assert_eq!(extracted_metadata.events[0].path, "calculation.completed");
        assert_eq!(extracted_metadata.events[1].path, "error.occurred");

        // Verify that input schemas are preserved
        assert!(extracted_metadata.actions[0].input_schema.is_some());
        assert!(extracted_metadata.actions[1].input_schema.is_some());
        assert!(extracted_metadata.actions[2].input_schema.is_some());

        // Verify that output schemas are preserved
        assert!(extracted_metadata.actions[0].output_schema.is_some());
        assert!(extracted_metadata.actions[1].output_schema.is_some());
        assert!(extracted_metadata.actions[2].output_schema.is_some());

        // Verify that event data schemas are preserved
        assert!(extracted_metadata.events[0].data_schema.is_some());
        assert!(extracted_metadata.events[1].data_schema.is_some());

        println!("✅ ServiceMetadata serialization roundtrip test passed!");
        println!("   - Network ID: {}", extracted_metadata.network_id);
        println!("   - Service Path: {}", extracted_metadata.service_path);
        println!("   - Actions: {}", extracted_metadata.actions.len());
        println!("   - Events: {}", extracted_metadata.events.len());

        Ok(())
    }

    #[test]
    fn test_field_schema_serialization() -> Result<()> {
        // Test various FieldSchema types
        let string_schema = FieldSchema::string("name");
        let integer_schema = FieldSchema::integer("age");
        let double_schema = FieldSchema::double("score");
        let boolean_schema = FieldSchema::boolean("active");
        let timestamp_schema = FieldSchema::timestamp("created_at");

        // Test object schema with properties
        let mut properties = HashMap::new();
        properties.insert("id".to_string(), Box::new(FieldSchema::integer("id")));
        properties.insert("name".to_string(), Box::new(FieldSchema::string("name")));
        let object_schema = FieldSchema::object(
            "User",
            properties,
            Some(vec!["id".to_string(), "name".to_string()]),
        );

        // Test array schema
        let array_schema = FieldSchema::array("tags", Box::new(FieldSchema::string("tag")));

        // Test reference schema
        let reference_schema = FieldSchema::reference("user", "User");

        // Test union schema
        let union_schema = FieldSchema::union(
            "value",
            vec![
                SchemaDataType::String,
                SchemaDataType::Int32,
                SchemaDataType::Double,
            ],
        );

        // Create a comprehensive schema with all types
        let schemas = vec![
            string_schema,
            integer_schema,
            double_schema,
            boolean_schema,
            timestamp_schema,
            object_schema,
            array_schema,
            reference_schema,
            union_schema,
        ];

        for schema in schemas {
            let arc_value = ArcValue::new_struct(schema.clone());
            let serialized = arc_value.serialize(None)?;
            let deserialized = ArcValue::deserialize(&serialized, None)?;
            let extracted: Arc<FieldSchema> = deserialized.as_struct_ref()?;

            assert_eq!(*extracted, schema);
        }

        println!("✅ FieldSchema serialization test passed!");
        Ok(())
    }

    #[test]
    fn test_service_metadata_json_to_arcvalue() -> Result<()> {
        // Define the complete ServiceMetadata in JSON format that matches the exact struct fields
        let json_service_metadata = serde_json::json!({
            "network_id": "json-test-network",
            "service_path": "user-service",
            "name": "User Management Service",
            "version": "2.1.0",
            "description": "Comprehensive user management with authentication and profiles",
            "actions": [
                {
                    "name": "create_user",
                    "description": "Creates a new user account",
                    "input_schema": {
                        "name": "CreateUserInput",
                        "data_type": "Object",
                        "description": null,
                        "nullable": null,
                        "default_value": null,
                        "properties": {
                            "username": {
                                "name": "username",
                                "data_type": "String",
                                "description": null,
                                "nullable": null,
                                "default_value": null,
                                "properties": null,
                                "required": null,
                                "items": null,
                                "pattern": null,
                                "enum_values": null,
                                "minimum": null,
                                "maximum": null,
                                "exclusive_minimum": null,
                                "exclusive_maximum": null,
                                "min_length": 3,
                                "max_length": 50,
                                "min_items": null,
                                "max_items": null,
                                "example": null
                            },
                            "email": {
                                "name": "email",
                                "data_type": "String",
                                "description": null,
                                "nullable": null,
                                "default_value": null,
                                "properties": null,
                                "required": null,
                                "items": null,
                                "pattern": "^[^@]+@[^@]+\\.[^@]+$",
                                "enum_values": null,
                                "minimum": null,
                                "maximum": null,
                                "exclusive_minimum": null,
                                "exclusive_maximum": null,
                                "min_length": null,
                                "max_length": null,
                                "min_items": null,
                                "max_items": null,
                                "example": null
                            }
                        },
                        "required": ["username", "email"],
                        "items": null,
                        "pattern": null,
                        "enum_values": null,
                        "minimum": null,
                        "maximum": null,
                        "exclusive_minimum": null,
                        "exclusive_maximum": null,
                        "min_length": null,
                        "max_length": null,
                        "min_items": null,
                        "max_items": null,
                        "example": null
                    },
                    "output_schema": {
                        "name": "User",
                        "data_type": "Object",
                        "description": null,
                        "nullable": null,
                        "default_value": null,
                        "properties": {
                            "id": {
                                "name": "id",
                                "data_type": "String",
                                "description": null,
                                "nullable": null,
                                "default_value": null,
                                "properties": null,
                                "required": null,
                                "items": null,
                                "pattern": null,
                                "enum_values": null,
                                "minimum": null,
                                "maximum": null,
                                "exclusive_minimum": null,
                                "exclusive_maximum": null,
                                "min_length": null,
                                "max_length": null,
                                "min_items": null,
                                "max_items": null,
                                "example": null
                            }
                        },
                        "required": null,
                        "items": null,
                        "pattern": null,
                        "enum_values": null,
                        "minimum": null,
                        "maximum": null,
                        "exclusive_minimum": null,
                        "exclusive_maximum": null,
                        "min_length": null,
                        "max_length": null,
                        "min_items": null,
                        "max_items": null,
                        "example": null
                    }
                }
            ],
            "events": [
                {
                    "path": "user.created",
                    "description": "Emitted when a new user is created",
                    "data_schema": {
                        "name": "UserCreatedEvent",
                        "data_type": "Object",
                        "description": null,
                        "nullable": null,
                        "default_value": null,
                        "properties": {
                            "user_id": {
                                "name": "user_id",
                                "data_type": "String",
                                "description": null,
                                "nullable": null,
                                "default_value": null,
                                "properties": null,
                                "required": null,
                                "items": null,
                                "pattern": null,
                                "enum_values": null,
                                "minimum": null,
                                "maximum": null,
                                "exclusive_minimum": null,
                                "exclusive_maximum": null,
                                "min_length": null,
                                "max_length": null,
                                "min_items": null,
                                "max_items": null,
                                "example": null
                            }
                        },
                        "required": null,
                        "items": null,
                        "pattern": null,
                        "enum_values": null,
                        "minimum": null,
                        "maximum": null,
                        "exclusive_minimum": null,
                        "exclusive_maximum": null,
                        "min_length": null,
                        "max_length": null,
                        "min_items": null,
                        "max_items": null,
                        "example": null
                    }
                }
            ],
            "registration_time": 1640995200,
            "last_start_time": 1640995260
        });

        // Convert JSON to ArcValue using from_json
        let mut arc_value = ArcValue::from_json(json_service_metadata.clone());
        assert_eq!(arc_value.category, runar_serializer::ValueCategory::Map);

        // Convert ArcValue back to JSON to verify the conversion
        let back_to_json = arc_value.to_json()?;
        assert_eq!(back_to_json, json_service_metadata);

        // Now deserialize the JSON directly to ServiceMetadata and wrap in ArcValue
        let service_metadata: ServiceMetadata =
            serde_json::from_value(json_service_metadata.clone())?;
        let typed_arc_value = ArcValue::new_struct(service_metadata.clone());

        // Extract the typed ServiceMetadata from ArcValue using as_type_ref
        let obj_instance: Arc<ServiceMetadata> = typed_arc_value.as_type_ref()?;

        // Verify that all fields match the input JSON
        assert_eq!(obj_instance.network_id, "json-test-network");
        assert_eq!(obj_instance.service_path, "user-service");
        assert_eq!(obj_instance.name, "User Management Service");
        assert_eq!(obj_instance.version, "2.1.0");
        assert_eq!(
            obj_instance.description,
            "Comprehensive user management with authentication and profiles"
        );
        assert_eq!(obj_instance.registration_time, 1640995200);
        assert_eq!(obj_instance.last_start_time, Some(1640995260));

        // Verify actions
        assert_eq!(obj_instance.actions.len(), 1);
        assert_eq!(obj_instance.actions[0].name, "create_user");
        assert_eq!(
            obj_instance.actions[0].description,
            "Creates a new user account"
        );
        assert!(obj_instance.actions[0].input_schema.is_some());
        assert!(obj_instance.actions[0].output_schema.is_some());

        // Verify events
        assert_eq!(obj_instance.events.len(), 1);
        assert_eq!(obj_instance.events[0].path, "user.created");
        assert_eq!(
            obj_instance.events[0].description,
            "Emitted when a new user is created"
        );
        assert!(obj_instance.events[0].data_schema.is_some());

        println!("   - Successfully converted JSON to typed ServiceMetadata");
        println!("   - All fields match the input JSON structure");

        // Now try to extract as ServiceMetadata (this would work if the JSON structure matches exactly)
        // Note: This is a demonstration of the concept - in practice, you'd need to ensure
        // the JSON structure exactly matches the ServiceMetadata struct

        println!("✅ JSON to ArcValue conversion test passed!");
        println!("   - JSON structure preserved in ArcValue");
        println!("   - Roundtrip JSON conversion successful");
        println!("   - ArcValue category: {:?}", arc_value.category);

        // Let's also test a simpler case with a basic FieldSchema from JSON
        let json_field_schema = serde_json::json!({
            "name": "test_field",
            "data_type": "String",
            "description": "A test field",
            "nullable": true,
            "min_length": 1,
            "max_length": 100
        });

        let mut field_arc_value = ArcValue::from_json(json_field_schema.clone());
        let field_back_to_json = field_arc_value.to_json()?;
        assert_eq!(field_back_to_json, json_field_schema);

        println!("   - FieldSchema JSON conversion also successful");

        // Test the AsArcValue trait usage - this is the proper way to convert JSON to typed struct
        let service_metadata_from_json: ServiceMetadata =
            serde_json::from_value(json_service_metadata)?;
        let arc_value_from_struct = service_metadata_from_json.clone().into_arc_value();

        // Now extract it back using AsArcValue trait
        let extracted_service_metadata = ServiceMetadata::from_arc_value(arc_value_from_struct)?;

        // Verify the roundtrip worked
        assert_eq!(extracted_service_metadata, service_metadata_from_json);

        println!("   - AsArcValue trait roundtrip successful");
        println!("   - JSON -> ServiceMetadata -> ArcValue -> ServiceMetadata works perfectly!");

        Ok(())
    }
}
