use std::collections::HashMap;
use serde_cbor;

// Define a simplified version of SampleObject for the example
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SampleObject {
    id: u64,
    name: String,
    timestamp: u64,
    metadata: HashMap<String, String>,
    values: Vec<f64>,
}

impl SampleObject {
    fn new(id: u64, name: String, metadata: HashMap<String, String>, values: Vec<f64>) -> Self {
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

    fn is_error_test(&self) -> bool {
        self.name == "ERROR"
    }

    fn modify_for_test(&mut self) {
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

fn main() {
    // Initialize logging
    env_logger::init();

    // Create a sample object
    let mut metadata = HashMap::new();
    metadata.insert("test_key".to_string(), "test_value".to_string());
    metadata.insert("platform".to_string(), "rust_example".to_string());
    
    let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
    let sample_object = SampleObject::new(42, "rust_test".to_string(), metadata, values);

    println!("Original object: {:#?}", sample_object);

    // Serialize to CBOR
    let cbor_bytes = serde_cbor::to_vec(&sample_object).unwrap();
    println!("Serialized to CBOR: {} bytes", cbor_bytes.len());

    // Deserialize from CBOR to verify
    let deserialized: SampleObject = serde_cbor::from_slice(&cbor_bytes).unwrap();
    println!("Deserialized object: {:#?}", deserialized);

    // Test object modification
    let mut modified_object = sample_object.clone();
    modified_object.modify_for_test();
    println!("Modified object: {:#?}", modified_object);

    // Test error detection
    let error_test_object = SampleObject::new(999, "ERROR".to_string(), HashMap::new(), vec![1.0]);
    println!("Is error test object: {}", error_test_object.is_error_test());

    // Test normal object
    let normal_object = SampleObject::new(888, "NORMAL".to_string(), HashMap::new(), vec![1.0]);
    println!("Is error test object: {}", normal_object.is_error_test());

    println!("All tests completed successfully!");
}
