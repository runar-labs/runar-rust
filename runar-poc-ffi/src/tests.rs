#[cfg(test)]
mod tests {
    use crate::types::SampleObject;
    use crate::types::ErrorCode;
    use std::collections::HashMap;

    #[test]
    fn test_sample_object_creation() {
        let mut metadata = HashMap::new();
        metadata.insert("test_key".to_string(), "test_value".to_string());
        
        let values = vec![1.0, 2.0, 3.0];
        let obj = SampleObject::new(123, "test_object".to_string(), metadata.clone(), values.clone());
        
        assert_eq!(obj.id, 123);
        assert_eq!(obj.name, "test_object");
        assert_eq!(obj.metadata, metadata);
        assert_eq!(obj.values, values);
        assert!(obj.timestamp > 0);
    }

    #[test]
    fn test_error_test_detection() {
        let mut metadata = HashMap::new();
        let values = vec![1.0];
        
        let normal_obj = SampleObject::new(1, "normal".to_string(), metadata.clone(), values.clone());
        let error_obj = SampleObject::new(2, "ERROR".to_string(), metadata, values);
        
        assert!(!normal_obj.is_error_test());
        assert!(error_obj.is_error_test());
    }

    #[test]
    fn test_object_modification() {
        let mut metadata = HashMap::new();
        metadata.insert("original".to_string(), "value".to_string());
        
        let values = vec![1.0, 2.0];
        let mut obj = SampleObject::new(1, "test".to_string(), metadata, values);
        
        let original_values = obj.values.clone();
        obj.modify_for_test();
        
        // Check that values were doubled
        assert_eq!(obj.values.len(), original_values.len());
        for (i, &original) in original_values.iter().enumerate() {
            assert_eq!(obj.values[i], original * 2.0);
        }
        
        // Check that metadata was added
        assert!(obj.metadata.contains_key("processed_at"));
        assert!(obj.metadata.contains_key("rust_processed"));
        assert_eq!(obj.metadata["rust_processed"], "true");
    }

    #[test]
    fn test_cbor_serialization_deserialization() {
        let mut metadata = HashMap::new();
        metadata.insert("key1".to_string(), "value1".to_string());
        metadata.insert("key2".to_string(), "value2".to_string());
        
        let values = vec![1.5, 2.5, 3.5];
        let original_obj = SampleObject::new(42, "serialization_test".to_string(), metadata, values);
        
        // Serialize to CBOR
        let cbor_bytes = serde_cbor::to_vec(&original_obj).unwrap();
        assert!(!cbor_bytes.is_empty());
        
        // Deserialize from CBOR
        let deserialized_obj: SampleObject = serde_cbor::from_slice(&cbor_bytes).unwrap();
        
        // Verify all fields match
        assert_eq!(original_obj.id, deserialized_obj.id);
        assert_eq!(original_obj.name, deserialized_obj.name);
        assert_eq!(original_obj.timestamp, deserialized_obj.timestamp);
        assert_eq!(original_obj.metadata, deserialized_obj.metadata);
        assert_eq!(original_obj.values, deserialized_obj.values);
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(ErrorCode::Success as u32, 0);
        assert_eq!(ErrorCode::InvalidPointer as u32, 1);
        assert_eq!(ErrorCode::SerializationError as u32, 2);
        assert_eq!(ErrorCode::DeserializationError as u32, 3);
        assert_eq!(ErrorCode::InvalidData as u32, 4);
        assert_eq!(ErrorCode::CallbackError as u32, 5);
        assert_eq!(ErrorCode::UnknownError as u32, 99);
    }
}
