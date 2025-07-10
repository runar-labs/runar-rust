// runar_common/src/types/mod.rs
//
// Type definitions for runar common

// Type modules

// Trait for converting types to ArcValue
// ArcValue will be qualified from self::value_type directly in the trait

pub mod schemas;

pub use self::schemas::{
    ActionMetadata, EventMetadata, FieldSchema, SchemaDataType, ServiceMetadata,
};

// Export the implement_from_for_valuetype macro
#[macro_export]
macro_rules! implement_from_for_valuetype {
    ($t:ty, $variant:ident) => {
        impl From<$t> for runar_serializer::ArcValue {
            fn from(value: $t) -> Self {
                runar_serializer::ArcValue::new_primitive(value)
            }
        }
    };
}
