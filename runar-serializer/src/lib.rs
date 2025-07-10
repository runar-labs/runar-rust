//! Enhanced serialization with selective field encryption for Runar
//!
//! This crate provides:
//! - Derive macros for selective field encryption
//! - Enhanced SerializerRegistry with encryption support
//! - Integration with runar-keys for envelope encryption
//! - Label-based key resolution system

pub trait AsArcValue {
    fn into_arc_value_type(self) -> self::arc_value::ArcValue;
}

pub mod arc_value;
pub mod encryption;
pub mod erased_arc;
pub mod map_types;
pub mod registry;
pub mod traits;
pub mod utils;
pub mod vec_types;

pub use encryption::*;
pub use registry::*;
pub use traits::*;

// Re-export macros
pub use runar_serializer_macros::*;

// Re-export core types so callers can write `runar_serializer::ArcValue`.
pub use arc_value::{ArcValue, DeserializerFnWrapper, LazyDataWithOffset, ValueCategory};
pub use erased_arc::ErasedArc;
