//! Serialization with selective field encryption for Runar, using macro-based approach without runtime registry
//!
//! This crate provides:
//! - Derive macros for selective field encryption
//! - Enhanced SerializerRegistry with encryption support
//! - Integration with runar-keys for envelope encryption
//! - Label-based key resolution system

pub mod arc_value;
pub mod encryption;
pub mod erased_arc;
pub mod primitive_types;
pub mod traits;
pub mod utils;

pub use encryption::*;
pub use traits::*;

// Re-export macros
pub use runar_serializer_macros::*;

// Re-export core types so callers can write `runar_serializer::ArcValue`.
pub use arc_value::{ArcValue, LazyDataWithOffset, ValueCategory};
pub use erased_arc::ErasedArc;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::SerializationContext;
    use std::sync::Arc;

    #[test]
    fn test_basic_serialization_context() {
        // Test that SerializationContext can be created
        let logger = Arc::new(runar_common::logging::Logger::new_root(
            runar_common::logging::Component::Keys,
            "test_node"
        ));
        let key_manager = runar_keys::mobile::MobileKeyManager::new(logger).unwrap();
        let context = SerializationContext::new(
            Arc::new(key_manager),
            Arc::new(crate::traits::ConfigurableLabelResolver::new(
                crate::traits::KeyMappingConfig {
                    label_mappings: std::collections::HashMap::new(),
                }
            )),
            "test_network".to_string(),
            "test_profile".to_string(),
        );
        
        assert_eq!(context.network_id, "test_network");
        assert_eq!(context.profile_id, "test_profile");
    }

    #[test]
    fn test_string_serialization() {
        let test_string = "Hello, World!".to_string();
        let bytes = test_string.to_binary(None).unwrap();
        let decoded: String = serde_cbor::from_slice(&bytes).unwrap();
        assert_eq!(test_string, decoded);
    }
}
