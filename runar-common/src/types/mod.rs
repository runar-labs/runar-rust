// runar_common/src/types/mod.rs
//
// Type definitions for runar common

// Type modules

// Trait for converting types to ArcValue
// ArcValue will be qualified from self::value_type directly in the trait

pub trait AsArcValue {
    fn into_arc_value_type(self) -> self::arc_value::ArcValue;
}

pub mod arc_value;
pub mod erased_arc;
pub mod schemas;
mod vmap;

// Export our types
pub use self::arc_value::{ArcValue, SerializerRegistry, ValueCategory};
pub use self::erased_arc::ErasedArc;
pub use self::schemas::{
    ActionMetadata, EventMetadata, FieldSchema, SchemaDataType, ServiceMetadata,
};
// AsArcValue is already public in this module, no need to re-export 'self::AsArcValue'
pub use vmap::VMap;
// Export the implement_from_for_valuetype macro
#[macro_export]
macro_rules! implement_from_for_valuetype {
    ($t:ty, $variant:ident) => {
        impl From<$t> for $crate::types::ArcValue {
            fn from(value: $t) -> Self {
                $crate::types::ArcValue::new_primitive(value)
            }
        }
    };
}
