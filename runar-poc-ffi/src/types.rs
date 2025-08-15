use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Sample object that will be serialized/deserialized between Rust and Swift/Kotlin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleObject {
    pub id: u64,
    pub name: String,
    pub timestamp: u64,
    pub metadata: HashMap<String, String>,
    pub values: Vec<f64>,
}

impl SampleObject {
    /// Create a new SampleObject with current timestamp
    pub fn new(id: u64, name: String, metadata: HashMap<String, String>, values: Vec<f64>) -> Self {
        Self {
            id,
            name,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            metadata,
            values,
        }
    }

    /// Check if this object is an error test object
    pub fn is_error_test(&self) -> bool {
        self.name == "ERROR"
    }

    /// Modify the object for testing purposes
    pub fn modify_for_test(&mut self) {
        // Add a processing timestamp
        self.metadata.insert(
            "processed_at".to_string(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_string(),
        );

        // Modify some values
        if !self.values.is_empty() {
            for value in &mut self.values {
                *value *= 2.0;
            }
        }

        // Add a test flag
        self.metadata.insert("rust_processed".to_string(), "true".to_string());
    }
}

/// Error codes for FFI communication
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum ErrorCode {
    Success = 0,
    InvalidPointer = 1,
    SerializationError = 2,
    DeserializationError = 3,
    InvalidData = 4,
    CallbackError = 5,
    UnknownError = 99,
}

impl From<anyhow::Error> for ErrorCode {
    fn from(_: anyhow::Error) -> Self {
        ErrorCode::UnknownError
    }
}

impl From<serde_cbor::Error> for ErrorCode {
    fn from(_: serde_cbor::Error) -> Self {
        ErrorCode::SerializationError
    }
}
