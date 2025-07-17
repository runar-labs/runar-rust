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
pub mod map_types;
pub mod primitive_types;
pub mod traits;
pub mod utils;
pub mod vec_types;

pub use encryption::*;
pub use traits::*;

// Re-export macros
pub use runar_serializer_macros::*;

// Re-export core types so callers can write `runar_serializer::ArcValue`.
pub use arc_value::{ArcValue, LazyDataWithOffset, ValueCategory};
pub use erased_arc::ErasedArc;
